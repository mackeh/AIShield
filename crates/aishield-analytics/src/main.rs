use axum::{
    extract::State,
    http::Request,
    http::{header, HeaderValue, Method},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use std::collections::{HashMap, VecDeque};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

mod auth;
mod db;
mod handlers;
mod models;

use handlers::{get_analytics_summary, get_top_rules, get_trends, health_check, ingest_scan};
use models::AppState;

#[derive(Debug)]
struct RateLimitState {
    max_requests: usize,
    window: Duration,
    buckets: Mutex<HashMap<String, VecDeque<Instant>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables from .env file
    dotenv::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            env::var("RUST_LOG").unwrap_or_else(|_| "info,aishield_analytics=debug".to_string()),
        )
        .init();

    info!("Starting AIShield Analytics API");

    // Database connection
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://aishield:aishield_dev_password@localhost:5432/aishield_analytics".to_string()
    });

    info!("Connecting to database...");
    let db_pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    // Test database connection
    sqlx::query("SELECT 1")
        .execute(&db_pool)
        .await
        .map_err(|e| {
            warn!("Database connection failed: {}", e);
            e
        })?;

    info!("Database connected successfully");

    // API key (in production, use proper secrets management)
    let api_key = env::var("AISHIELD_API_KEY").unwrap_or_else(|_| {
        warn!("AISHIELD_API_KEY not set, using default (insecure for production!)");
        "dev_key_12345".to_string()
    });

    // Hash the API key for comparison
    let api_key_hash = auth::hash_api_key(&api_key);

    let state = Arc::new(AppState {
        db_pool,
        api_key_hash,
    });

    let cors_layer = build_cors_layer()?;
    let rate_limit_requests = env::var("AISHIELD_RATE_LIMIT_REQUESTS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(120);
    let rate_limit_seconds = env::var("AISHIELD_RATE_LIMIT_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);
    let rate_limit_state = Arc::new(RateLimitState {
        max_requests: rate_limit_requests,
        window: Duration::from_secs(rate_limit_seconds),
        buckets: Mutex::new(HashMap::new()),
    });

    // Build router
    let app = Router::new()
        // Health check (no auth required)
        .route("/api/health", get(health_check))
        // Analytics endpoints (auth required)
        .route("/api/v1/scans/ingest", post(ingest_scan))
        .route("/api/v1/scans", get(handlers::list_scans))
        .route("/api/v1/analytics/summary", get(get_analytics_summary))
        .route("/api/v1/analytics/ai-metrics", get(handlers::ai_metrics))
        .route(
            "/api/v1/reports/compliance",
            get(handlers::generate_compliance_report),
        )
        .route("/api/v1/analytics/trends", get(get_trends))
        .route("/api/v1/analytics/top-rules", get(get_top_rules))
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            rate_limit_state,
            rate_limit_middleware,
        ))
        .layer(cors_layer);

    // Server address
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!("Analytics API listening on http://{}", addr);
    info!("Health check: http://{}/api/health", addr);
    info!(
        "Rate limiting enabled: {} requests / {} seconds",
        rate_limit_requests, rate_limit_seconds
    );

    // Start server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn build_cors_layer() -> anyhow::Result<CorsLayer> {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::HeaderName::from_static("x-api-key"),
        ]);

    if let Ok(raw_origins) = env::var("AISHIELD_ALLOWED_ORIGINS") {
        let origins = raw_origins
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();

        if origins.is_empty() {
            warn!("AISHIELD_ALLOWED_ORIGINS is set but empty; falling back to permissive CORS");
            return Ok(base.allow_origin(Any));
        }

        if origins.iter().any(|o| *o == "*") {
            warn!("AISHIELD_ALLOWED_ORIGINS contains '*'; using permissive CORS");
            return Ok(base.allow_origin(Any));
        }

        let parsed = origins
            .into_iter()
            .map(str::parse::<HeaderValue>)
            .collect::<Result<Vec<_>, _>>()?;

        info!("CORS restricted to configured origins");
        Ok(base.allow_origin(parsed))
    } else {
        warn!("AISHIELD_ALLOWED_ORIGINS not set; using permissive CORS for local/dev usage");
        Ok(base.allow_origin(Any))
    }
}

async fn rate_limit_middleware(
    State(state): State<Arc<RateLimitState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let key = request
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(auth::hash_api_key)
        .unwrap_or_else(|| "__anon__".to_string());

    let now = Instant::now();
    {
        let mut buckets = state.buckets.lock().expect("rate limit mutex poisoned");
        let bucket = buckets.entry(key).or_default();
        while let Some(front) = bucket.front() {
            if now.duration_since(*front) > state.window {
                bucket.pop_front();
            } else {
                break;
            }
        }

        if bucket.len() >= state.max_requests {
            return (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded",
            )
                .into_response();
        }

        bucket.push_back(now);
    }

    next.run(request).await
}

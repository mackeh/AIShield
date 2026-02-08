use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

mod auth;
mod db;
mod handlers;
mod models;

use handlers::{get_analytics_summary, get_top_rules, get_trends, health_check, ingest_scan};
use models::AppState;

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

    // Build router
    let app = Router::new()
        // Health check (no auth required)
        .route("/api/health", get(health_check))
        // Analytics endpoints (auth required)
        .route("/api/v1/scans/ingest", post(ingest_scan))
        .route("/api/v1/analytics/summary", get(get_analytics_summary))
        .route("/api/v1/analytics/trends", get(get_trends))
        .route("/api/v1/analytics/top-rules", get(get_top_rules))
        .with_state(state)
        .layer(CorsLayer::permissive()); // TODO: Restrict in production

    // Server address
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!("Analytics API listening on http://{}", addr);
    info!("Health check: http://{}/api/health", addr);

    // Start server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

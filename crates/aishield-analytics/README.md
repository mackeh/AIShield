# AIShield Analytics API

REST API server for ingesting AIShield scan results and serving analytics data.

## Features

- **Scan Ingestion**: Accept scan results from CLI/CI via REST API
- **Analytics Queries**: Aggregate data across org/team/repo dimensions
- **Time-Series Data**: Track vulnerability trends over time
- **API Key Authentication**: SHA-256 hashed API key validation
- **PostgreSQL + TimescaleDB**: Efficient time-series queries

## Quick Start

### 1. Set Up Database

```bash
# Start PostgreSQL with TimescaleDB
docker-compose -f docker-compose.analytics.yml up -d

# Apply migrations
bash migrations/test-migrations.sh
```

### 2. Configure Environment

Create `.env` file:

```bash
DATABASE_URL=postgres://aishield:aishield_dev_password@localhost:5432/aishield_analytics
AISHIELD_API_KEY=your_secure_api_key_here
PORT=8080
RUST_LOG=info,aishield_analytics=debug
```

### 3. Run Server

```bash
cargo run -p aishield-analytics
```

Server starts on `http://localhost:8080`

## API Endpoints

### Health Check

```bash
GET /api/health

# Response
{
  "ok": true,
  "service": "aishield-analytics",
  "version": "0.3.0"
}
```

### Ingest Scan Result

```bash
POST /api/v1/scans/ingest
Headers: x-api-key: YOUR_API_KEY
Content-Type: application/json

{
  "org_id": "github/acme-corp",
  "team_id": "backend",
  "repo_id": "github.com/acme/api-server",
  "repo_name": "api-server",
  "branch": "main",
  "commit_sha": "abc123",
  "target_path": "src/",
  "cli_version": "0.3.0",
  "scan_result": {
    "total_findings": 12,
    "critical": 2,
    "high": 7,
    "medium": 3,
    "low": 0,
    "info": 0,
    "ai_estimated_count": 5,
    "scan_duration_ms": 1234,
    "files_scanned": 156,
    "rules_loaded": 169,
    "findings": [
      {
        "rule_id": "AISHIELD-PY-CRYPTO-001",
        "rule_title": "Weak hash algorithm (MD5/SHA1)",
        "severity": "high",
        "file_path": "src/auth.py",
        "line_number": 42,
        "snippet": "hashlib.md5(password)",
        "ai_confidence": 0.87,
        "ai_tendency": "LLMs suggest MD5 from outdated tutorials",
        "fix_suggestion": "Use bcrypt or argon2",
        "cwe_id": "CWE-327",
        "owasp_category": "A02:2021"
      }
    ]
  }
}

# Response
{
  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
  "ingested_at": "2026-02-08T15:30:00Z",
  "findings_stored": 1
}
```

### Get Analytics Summary

```bash
GET /api/v1/analytics/summary?org_id=github/acme-corp&days=30&limit=10
Headers: x-api-key: YOUR_API_KEY

# Response
{
  "period": "30 days",
  "org_id": "github/acme-corp",
  "team_id": null,
  "summary": {
    "total_scans": 142,
    "total_findings": 1847,
    "critical": 23,
    "high": 456,
    "medium": 891,
    "low": 477,
    "info": 0,
    "ai_estimated": 734,
    "ai_ratio": 0.397
  },
  "trend": null,
  "time_series": [
    {
      "date": "2026-01-09",
      "scans": 5,
      "findings": 67,
      "ai_ratio": 0.41
    }
  ],
  "top_rules": [
    {
      "rule_id": "AISHIELD-PY-CRYPTO-001",
      "rule_title": "Weak hash algorithm",
      "severity": "high",
      "count": 89
    }
  ],
  "top_repos": [
    {
      "repo_id": "github.com/acme/api-server",
      "repo_name": "api-server",
      "findings": 456,
      "ai_ratio": 0.42
    }
  ]
}
```

### Get Time-Series Trends

```bash
GET /api/v1/analytics/trends?org_id=github/acme-corp&days=30
Headers: x-api-key: YOUR_API_KEY

# Response
[
  { "date": "2026-01-09", "scans": 5, "findings": 67, "ai_ratio": 0.41 },
  { "date": "2026-01-10", "scans": 4, "findings": 52, "ai_ratio": 0.38 }
]
```

### Get Top Rules

```bash
GET /api/v1/analytics/top-rules?org_id=github/acme-corp&days=30&limit=10
Headers: x-api-key: YOUR_API_KEY

# Response
[
  {
    "rule_id": "AISHIELD-PY-CRYPTO-001",
    "rule_title": "Weak hash algorithm",
    "severity": "high",
    "count": 89
  }
]
```

## Query Parameters

| Parameter | Type    | Default | Description               |
| --------- | ------- | ------- | ------------------------- |
| `org_id`  | string  | null    | Filter by organization    |
| `team_id` | string  | null    | Filter by team            |
| `repo_id` | string  | null    | Filter by repository      |
| `days`    | integer | 30      | Time period (last N days) |
| `limit`   | integer | 10      | Max results for top lists |

## Authentication

All endpoints except `/api/health` require API key authentication.

**Header**: `x-api-key: YOUR_API_KEY`

Set your API key via environment variable:

```bash
export AISHIELD_API_KEY=your_secret_key_here
```

Keys are hashed with SHA-256 for comparison.

## Development

### Build

```bash
cargo build -p aishield-analytics
```

### Test

```bash
cargo test -p aishield-analytics
```

### Run with Custom Config

```bash
DATABASE_URL=postgres://user:pass@host/db \
AISHIELD_API_KEY=test_key \
PORT=3000 \
cargo run -p aishield-analytics
```

## Deployment

### Option 1: Docker (TODO)

```bash
docker build -t aishield-analytics .
docker run -p 8080:8080 \
  -e DATABASE_URL=postgres://... \
  -e AISHIELD_API_KEY=... \
  aishield-analytics
```

### Option 2: Railway/Render

1. Connect GitHub repo
2. Set environment variables:
   - `DATABASE_URL` (from managed Postgres)
   - `AISHIELD_API_KEY`
3. Deploy main branch

## Architecture

```
┌─────────────┐        ┌──────────────────┐        ┌──────────────────┐
│             │        │                  │        │                  │
│  CLI/CI     ├───────►│  Analytics API   ├───────►│  PostgreSQL +    │
│  aishield   │  POST  │  (Axum + sqlx)   │        │  TimescaleDB     │
│    scan     │        │                  │        │                  │
│             │        │  - Auth (SHA256) │        │  - Hypertables   │
└─────────────┘        │  - Validation    │        │  - Materialized  │
                       │  - Ingestion     │        │    Views         │
┌─────────────┐        │                  │        │                  │
│             │        │                  │        │                  │
│  Dashboard  │◄───────┤  GET /analytics  │◄───────┤                  │
│  (Next.js)  │        │                  │        │                  │
│             │        │                  │        │                  │
└─────────────┘        └──────────────────┘        └──────────────────┘
```

## Performance

- Sub-10ms for single scan ingestion
- <100ms for 30-day aggregations (with TimescaleDB)
- Materialized views for instant dashboard queries

## Security

- ✅ API key authentication (SHA-256 hashing)
- ✅ SQL injection protection (sqlx parameterized queries)
- ⚠️ CORS permissive (restrict in production)
- ⚠️ HTTPS recommended for production
- ⚠️ Rate limiting TODO

## Troubleshooting

**Database connection failed:**

```bash
# Check DATABASE_URL
echo $DATABASE_URL

# Test connection
psql $DATABASE_URL -c "SELECT 1;"
```

**Authentication errors:**

```bash
# Verify API key hash
# In production, use proper secrets management
```

**Port already in use:**

```bash
PORT=3000 cargo run -p aishield-analytics
```

# Quick Start: Database Setup

This guide helps you set up the AIShield analytics database locally.

## Prerequisites

- Docker and Docker Compose
- PostgreSQL client (`psql`) — optional for manual verification

## Option 1: Docker Compose (Recommended)

### 1. Start Database

```bash
# From repository root
docker compose -f docker-compose.analytics.yml up -d

# Wait for database to be healthy (~10 seconds)
docker compose -f docker-compose.analytics.yml ps
```

This starts:

- PostgreSQL 16 with TimescaleDB extension (port 5432)
- pgAdmin web UI (port 5050) — optional database management tool

### 2. Run Migrations

```bash
# Test and apply all migrations
bash migrations/test-migrations.sh
```

Expected output:

```
✓ Connected to database: aishield_analytics
✓ TimescaleDB 2.x is installed
✓ Migration 001 applied
✓ Migration 002 applied
✓ Migration 003 applied
✓ Table 'scans' exists
✓ 'scans' is a TimescaleDB hypertable
✓ Materialized view 'top_rules_daily' exists
...
✅ ALL TESTS PASSED
```

### 3. Seed Test Data (Optional)

```bash
docker exec -i aishield-analytics-db psql -U aishield -d aishield_analytics < migrations/seed-test-data.sql
```

This creates 100 realistic scans across 3 orgs for dashboard testing.

### 4. Verify

Access **pgAdmin** at `http://localhost:5050`:

- Email: `admin@aishield.local`
- Password: `admin`

Add server connection:

- Host: `analytics-db`
- Port: `5432`
- Database: `aishield_analytics`
- Username: `aishield`
- Password: `aishield_dev_password`

Run sample query:

```sql
SELECT
  org_id,
  COUNT(*) as scans,
  SUM(total_findings) as findings,
  AVG(ai_ratio)::numeric(4,2) as ai_ratio
FROM scans
WHERE timestamp > NOW() - INTERVAL '7 days'
GROUP BY org_id;
```

---

## Option 2: Manual Setup (Managed Database)

### 1. Create Database

On Supabase/Neon/Railway:

1. Create new PostgreSQL 14+ database
2. Enable TimescaleDB extension via dashboard or SQL:
   ```sql
   CREATE EXTENSION timescaledb;
   ```

### 2. Set Environment Variables

```bash
export DB_HOST=your-db-host.supabase.co
export DB_PORT=5432
export DB_USER=postgres
export DB_NAME=postgres
export PGPASSWORD=your-password
```

### 3. Apply Migrations

```bash
psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f migrations/001_create_scans_table.sql
psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f migrations/002_create_findings_table.sql
psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f migrations/003_create_analytics_views.sql
```

---

## Next Steps

✅ **Database is ready!**

Continue with local stack verification:

1. Start full stack and smoke test: `./scripts/start-analytics-stack.sh`
2. Validate dashboard API mode using `WEEK5_TESTING.md`
3. Stop services cleanly: `./scripts/stop-analytics-stack.sh`

---

## Troubleshooting

**Docker container won't start:**

```bash
# Check logs
docker compose -f docker-compose.analytics.yml logs analytics-db

# Rebuild
docker compose -f docker-compose.analytics.yml down -v
docker compose -f docker-compose.analytics.yml up -d
```

**TimescaleDB extension not found:**

- Use TimescaleDB Docker image (already in docker-compose.analytics.yml)
- For managed databases, enable via dashboard

**Migrations fail with "relation already exists":**

- This is OK if re-running migrations
- To reset: `docker compose -f docker-compose.analytics.yml down -v` (⚠️ deletes all data)

**Can't connect to database:**

```bash
# Check container is running
docker ps | grep aishield

# Test connection
docker exec -it aishield-analytics-db psql -U aishield -d aishield_analytics -c "SELECT 1;"
```

# AIShield Database Migrations

This directory contains SQL migrations for the AIShield analytics database (PostgreSQL + TimescaleDB).

## Prerequisites

- PostgreSQL 14+
- TimescaleDB extension 2.10+

## Migration Order

Migrations must be applied in numeric order:

1. `001_create_scans_table.sql` — Core scans hypertable
2. `002_create_findings_table.sql` — Findings detail table
3. `003_create_analytics_views.sql` — Materialized views for dashboards

## Quick Start

### Option 1: Docker Compose (Recommended for Local Development)

```bash
# Start PostgreSQL + TimescaleDB
docker-compose up -d

# Apply migrations
psql -h localhost -p 5432 -U aishield -d aishield_analytics -f migrations/001_create_scans_table.sql
psql -h localhost -p 5432 -U aishield -d aishield_analytics -f migrations/002_create_findings_table.sql
psql -h localhost -p 5432 -U aishield -d aishield_analytics -f migrations/003_create_analytics_views.sql
```

### Option 2: Managed Database (Supabase, Neon, Railway)

1. Create a new PostgreSQL database
2. Enable TimescaleDB extension in your database dashboard
3. Connect via `psql` or SQL editor
4. Run migrations in order

### Option 3: Using sqlx-cli (Future)

```bash
# Install sqlx
cargo install sqlx-cli

# Run migrations
sqlx migrate run
```

## Verification

After applying migrations:

```sql
-- Check hypertable
SELECT * FROM timescaledb_information.hypertables WHERE hypertable_name = 'scans';

-- Check compression policy
SELECT * FROM timescaledb_information.jobs WHERE proc_name = 'policy_compression';

-- Check materialized views
SELECT schemaname, matviewname FROM pg_matviews;

-- Test insert
INSERT INTO scans (org_id, repo_id, repo_name, target_path, total_findings, critical_count)
VALUES ('github/test-org', 'github.com/test/repo', 'test-repo', '.', 5, 1);

SELECT * FROM scans ORDER BY timestamp DESC LIMIT 1;
```

## Refreshing Analytics Views

Materialized views are refreshed using:

```sql
-- Refresh all views
SELECT refresh_analytics_views();

-- Or refresh individually
REFRESH MATERIALIZED VIEW CONCURRENTLY top_rules_daily;
```

**Recommendation**: Set up a cron job or pg_cron task to refresh views every hour.

## Schema Overview

```
scans (hypertable)
  ├─ Partitioned by timestamp (7-day chunks)
  ├─ Compressed after 30 days
  └─ Retained for 2 years

findings (detail table)
  ├─ Foreign key to scans.scan_id
  └─ Tracks individual vulnerabilities

Materialized Views:
  ├─ top_rules_daily — Top security rules by org/team
  ├─ repo_health_daily — Repository health metrics
  ├─ team_leaderboard_weekly — Team performance scores
  └─ vulnerability_trend_hourly — Recent trend data
```

## Rollback

To rollback migrations:

```bash
# Drop in reverse order
psql -c "DROP MATERIALIZED VIEW IF EXISTS vulnerability_trend_hourly CASCADE;"
psql -c "DROP MATERIALIZED VIEW IF EXISTS team_leaderboard_weekly CASCADE;"
psql -c "DROP MATERIALIZED VIEW IF EXISTS repo_health_daily CASCADE;"
psql -c "DROP MATERIALIZED VIEW IF EXISTS top_rules_daily CASCADE;"
psql -c "DROP TABLE IF EXISTS findings CASCADE;"
psql -c "DROP TABLE IF EXISTS scans CASCADE;"
```

## Performance Tuning

### Recommended PostgreSQL Settings

```ini
# postgresql.conf
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 16MB
maintenance_work_mem = 128MB

# TimescaleDB
timescaledb.max_background_workers = 8
```

### Index Maintenance

```sql
-- Rebuild indexes monthly
REINDEX TABLE scans;
REINDEX TABLE findings;

-- Vacuum analyze
VACUUM ANALYZE scans;
VACUUM ANALYZE findings;
```

## Troubleshooting

**Error: `extension "timescaledb" is not available`**

- Install TimescaleDB: `CREATE EXTENSION timescaledb;`
- Or use Docker image: `timescale/timescaledb:latest-pg14`

**Error: `permission denied to create extension`**

- Requires superuser privileges
- For managed databases, enable via dashboard

**Slow queries on materialized views**

- Ensure unique indexes are created for `CONCURRENTLY` refresh
- Check refresh schedule isn't too frequent

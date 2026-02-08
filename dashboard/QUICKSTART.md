# Quick Start Guide - Dashboard Testing

## Option 1: File Mode Testing (No Database Required) ✅ EASIEST

This is the simplest way to see the dashboard working:

```bash
# From AIShield root directory
cd dashboard
node server.js
```

Then open: **http://localhost:3000**

The dashboard will run in FILE MODE, showing data from `.aishield-history.log` files.

---

## Option 2: API Mode Testing (Full Enterprise Features)

To test advanced features (filters, heatmap, team comparison), start the API/database stack first:

```bash
./scripts/start-analytics-stack.sh
```

Then start the dashboard in a second terminal:

### Start Dashboard

```bash
cd dashboard
node server.js
# Leave running - Dashboard on http://localhost:3000
```

### Terminal 3: Generate Test Data

```bash
# Generate sample scans with org/team data
./scripts/e2e-test.sh
```

### Browser: Configure Dashboard

1. Open http://localhost:3000
2. Click settings button (⚙️)
3. Enter:
   - **API URL**: `http://localhost:8080`
   - **API Key**: `test_key_e2e_12345`
4. Click "Test Connection" (should show ✅)
5. Click "Save Settings"
6. Refresh page

**Expected**:

- Mode badge shows "🌐 API Mode"
- Filter dropdowns appear
- Heatmap and team comparison charts visible

---

## Troubleshooting

### "Connection Refused" Error

**Cause**: Service not running  
**Fix**: Make sure you ran `node server.js` or `cargo run` in a terminal

### "PostgreSQL Connection Error"

**Cause**: Database not running or wrong credentials  
**Fix**:

```bash
# Check if PostgreSQL is running
pg_isready -h localhost -p 5432

# Start PostgreSQL (varies by system)
sudo systemctl start postgresql
# or
docker start postgres-container
```

### "No scans found"

**Cause**: No data in database  
**Fix**: Run `./scripts/e2e-test.sh` to generate sample data

### Filters/Heatmap Not Showing

**Cause**: Dashboard in file mode  
**Fix**: Configure API settings as described in Option 2

---

## Quick Test Commands

```bash
# Check if dashboard is running
curl http://localhost:3000

# Check if API is running
curl http://localhost:8080/api/health

# Check database connection
psql "postgres://aishield:aishield_dev_password@localhost:5432/aishield_analytics" -c "SELECT COUNT(*) FROM scans;"
```

---

## What You Should See

### File Mode (Option 1)

- Dashboard loads with basic analytics
- No filter dropdowns
- Mode badge shows "📁 File Mode"
- Data from local history files

### API Mode (Option 2)

- Dashboard loads with full features
- Filter dropdowns (Org/Team/Repo)
- Mode badge shows "🌐 API Mode"
- Organization Heatmap section
- Team Comparison charts
- Data from PostgreSQL via API

---

## Stop Services

```bash
# Dashboard
pkill -f "node server.js"

# API + database stack
./scripts/stop-analytics-stack.sh
```

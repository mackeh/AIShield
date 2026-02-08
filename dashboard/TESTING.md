# Dashboard API Integration Testing Guide

## Prerequisites

1. **Analytics API Running**:

```bash
cd crates/aishield-analytics
DATABASE_URL="postgres://aishield:aishield_dev_password@localhost:5432/aishield_analytics" \
AISHIELD_API_KEY="dev_key_12345" \
cargo run
```

2. **Dashboard Server Running**:

```bash
cd dashboard
node server.js
# Opens on http://localhost:3000
```

## Testing Scenarios

### Scenario 1: API Mode (Enterprise)

1. Open dashboard: `http://localhost:3000`
2. Click settings button (⚙️)
3. Enter configuration:
   - **API URL**: `http://localhost:8080`
   - **API Key**: `dev_key_12345`
4. Click "Test Connection" → Should show ✅
5. Click "Save Settings"
6. Refresh dashboard → Should load from API
7. Check browser console → Should see: `Loading data from Analytics API...`
8. Verify history file shows: `API Mode (all orgs)` or `API Mode (your-org)`

**Expected Behavior**:

- Dashboard loads data from `/api/v1/analytics/summary`
- Filters can be applied via settings (org_id, team_id)
- Falls back to file mode if API unavailable

### Scenario 2: File Mode (Community - No API)

1. Open dashboard: `http://localhost:3000`
2. **Don't configure API settings** (leave empty)
3. Dashboard loads normally
4. Check browser console → Should see: `Loading data from file-based endpoint...`
5. Verify history file shows local file path

**Expected Behavior**:

- Dashboard uses existing `/api/analytics` endpoint
- Data loaded from `.aishield-history.log`
- No API calls made

### Scenario 3: Graceful Degradation (API Down)

1. Configure API settings (Scenario 1)
2. **Stop the analytics API server**
3. Refresh dashboard
4. Check browser console → Should see:
   ```
   Loading data from Analytics API...
   API fetch failed, falling back to file-based mode: <error>
   Loading data from file-based endpoint...
   ```
5. Dashboard still works using file mode

**Expected Behavior**:

- Try API first
- Catch errors gracefully
- Fall back to file mode automatically
- User sees data (from file) with warning in console

## Manual API Testing

### Test API Endpoint Directly

```bash
# Test health
curl http://localhost:8080/api/health

# Test summary (requires auth)
curl -H "x-api-key: dev_key_12345" \
  "http://localhost:8080/api/v1/analytics/summary?days=30&limit=10"

# Test scans list
curl -H "x-api-key: dev_key_12345" \
  "http://localhost:8080/api/v1/scans?limit=10"
```

## Browser DevTools Inspection

### Network Tab Checks

**API Mode**:

- Request to: `http://localhost:8080/api/v1/analytics/summary?days=30&limit=10`
- Request headers include: `x-api-key: dev_key_12345`
- Response: JSON with `summary`, `time_series`, `top_rules`, `top_repos`

**File Mode**:

- Request to: `http://localhost:3000/api/analytics?days=30&limit=10`
- No API key header
- Response: JSON with existing structure

### Console Checks

Look for these log messages:

- ✅ `Loading data from Analytics API...` (API mode)
- ✅ `Loading data from file-based endpoint...` (file mode)
- ⚠️ `API fetch failed, falling back to file-based mode: <error>` (degradation)

### localStorage Inspection

```javascript
// In browser console
localStorage.getItem("AISHIELD_API_URL"); // Should show configured URL
localStorage.getItem("AISHIELD_API_KEY"); // Should show configured key
```

## Common Issues

### Issue: "API fetch failed: Connection refused"

**Cause**: Analytics API server not running  
**Fix**: Start analytics API (see Prerequisites)

### Issue: "API Error (401): Missing x-api-key header"

**Cause**: API key not configured or incorrect  
**Fix**: Check settings panel, verify API key matches server

### Issue: Dashboard shows no data

**Cause**: Both API and file mode failing  
**Fix**: Check dashboard server logs, verify `.aishield-history.log` exists

### Issue: Settings don't persist

**Cause**: localStorage blocked or private browsing mode  
**Fix**: Use normal browser mode, check browser settings

## Verification Checklist

- [ ] Settings panel opens and saves configuration
- [ ] Test connection button works (shows ✅ or ❌)
- [ ] API mode loads data successfully
- [ ] File mode loads data successfully
- [ ] Graceful degradation works (API down → file mode)
- [ ] Console logs show correct mode
- [ ] localStorage persists settings across page reloads
- [ ] Dashboard visualizations render correctly in both modes

## Next Steps

After successful testing:

1. Add org/team/repo filters to settings panel
2. Implement filter UI in dashboard header
3. Add mode indicator badge (API vs File)
4. Create org-wide heatmap visualization
5. Add team comparison charts

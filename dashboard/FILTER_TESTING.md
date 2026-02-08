# Dashboard Filter Testing Guide

## Overview

The dashboard now supports enterprise filtering by organization, team, and repository when API mode is enabled.

## Prerequisites

1. **Analytics API with data**:

```bash
cd crates/aishield-analytics
DATABASE_URL="..." AISHIELD_API_KEY="dev_key_12345" cargo run
```

2. **Sample scans with different orgs**:

```bash
# Push scans from different orgs
aishield scan . --analytics-push --org-id "acme-corp" --team-id "security"
aishield scan . --analytics-push --org-id "widgets-inc" --team-id "devops"
```

## Testing Filters

### Test 1: Filters Only Show in API Mode

1. Open dashboard without API configured
2. **Expected**: No filter dropdowns visible
3. Configure API settings (⚙️)
4. Save and refresh
5. **Expected**: Filter dropdowns appear in header

### Test 2: Filter Options Load Automatically

1. Open dashboard in API mode
2. Check console logs
3. **Expected**: "Loaded filters: X orgs, Y teams, Z repos"
4. Click org dropdown
5. **Expected**: List of organizations from your scans

### Test 3: Organization Filter

1. Select an organization from dropdown
2. **Expected**:
   - Dashboard data reloads
   - Console: "Loading data from Analytics API..."
   - History label shows: "API Mode (org:acme-corp)"
   - Dashboard shows only data for that org

### Test 4: Team Filter

1. Select org, then select team
2. **Expected**:
   - Data filtered by both org AND team
   - History label: "API Mode (org:acme-corp, team:security)"
   - Dashboard shows narrower dataset

### Test 5: Repository Filter

1. Select org, team, then repo
2. **Expected**:
   - Data filtered by all three
   - History label: "API Mode (org:acme-corp, team:security, repo:my-app)"
   - Dashboard shows repo-specific data

### Test 6: Filter Reset

1. Select org "acme-corp"
2. Select team "security"
3. Change org to "widgets-inc"
4. **Expected**:
   - Team filter automatically resets to "All Teams"
   - Data reloads for new org only

### Test 7: Clear All Filters

1. Apply multiple filters
2. Set org dropdown back to "All Organizations"
3. **Expected**:
   - All filters clear
   - Dashboard shows all data
   - History label: "API Mode (all orgs)"

## Browser DevTools Checks

### Network Tab

**With Filters Applied**:

```
Request URL: http://localhost:8080/api/v1/analytics/summary?days=30&limit=10&org_id=acme-corp&team_id=security
```

**Filter Change**:

- Each filter change triggers new API request
- Request includes updated query parameters

### Console Logs

Look for:

```
Loading data from Analytics API...
Loaded filters: 3 orgs, 5 teams, 12 repos
```

### Filter Values Inspection

```javascript
// In console
document.getElementById("org-filter").value; // Current org selection
document.getElementById("team-filter").value; // Current team
document.getElementById("repo-filter").value; // Current repo
```

## Common Issues

### Issue: Filters don't show

**Cause**: API mode not enabled  
**Fix**: Configure API settings in ⚙️ panel

### Issue: Dropdowns empty

**Cause**: No scan data or API connection failed  
**Fix**: Verify scans exist in database, check API connectivity

### Issue: Filter doesn't change data

**Cause**: API not returning filtered data  
**Fix**: Check backend `/api/v1/analytics/summary` handles filter params

### Issue: Filters show wrong values

**Cause**: Cache or stale data  
**Fix**: Hard refresh (Ctrl+Shift+R), check API response

## Filter Behavior Matrix

| Action           | org | team | repo | Result                      |
| ---------------- | --- | ---- | ---- | --------------------------- |
| Select org only  | ✓   | -    | -    | All teams/repos in that org |
| Select team only | -   | ✓    | -    | Invalid (team needs org)    |
| Change org       | ✓   | ✗    | ✗    | Team and repo reset         |
| Change team      | ✓   | ✓    | -    | Repo stays if valid         |
| Clear org        | -   | ✗    | ✗    | All filters reset           |

## Expected Filter Counts

After pushing sample scans:

- **Organizations**: 2-3 (acme-corp, widgets-inc, etc.)
- **Teams**: 3-5 (security, devops, engineering, etc.)
- **Repositories**: 5-15 (depends on scans)

## Verification Checklist

- [ ] Filters visible only in API mode
- [ ] Filter options load from scan data
- [ ] Org filter changes data correctly
- [ ] Team filter works with org
- [ ] Repo filter works with org+team
- [ ] Changing parent filter resets children
- [ ] History label shows active filters
- [ ] All filters clear when org set to "All"
- [ ] Console logs show filter activity
- [ ] Network requests include filter params

## Next: Advanced Visualizations

With filters working, you can now:

1. Create org-wide heatmaps
2. Add team comparison charts
3. Show repo-specific trend analysis
4. Generate filtered compliance reports

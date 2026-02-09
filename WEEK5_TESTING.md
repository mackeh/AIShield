# Week 5: Testing Guide 🧪

Since the dashboard interacts with a real API and Database, here is how to verify the new features.

## Quick Smoke Test (Recommended)

Fastest setup path:

```bash
./scripts/start-analytics-stack.sh
```

This starts Docker services, boots the analytics API, and runs the smoke checks.

The same smoke flow is now enforced in CI via:
`.github/workflows/analytics-smoke.yml`

To stop everything:

```bash
./scripts/stop-analytics-stack.sh
```

Run the automated endpoint smoke test first:

```bash
./scripts/smoke-analytics-api.sh
```

Optional args:

```bash
./scripts/smoke-analytics-api.sh http://localhost:8080 test_key_e2e_12345 test_org_1
```

Environment-variable equivalents are also supported:
`AISHIELD_ANALYTICS_URL`, `AISHIELD_API_KEY`, `AISHIELD_ORG_ID`, `AISHIELD_DAYS`.

The smoke test now ingests a deterministic metadata fixture before querying reports, and verifies that the generated CSV includes a row where:
- `Top CWE = CWE-79`
- `Top OWASP = A03:2021 - Injection`

## 1. AI Tool Metrics 🤖

**Objective**: Verify that AI-generated findings are correctly identified, aggregated, and displayed.

### Step 1: Backend Verification via CLI

Run the following command to check the raw JSON response from the API:

```bash
# Get your API key from .env or use the improved one
API_KEY="test_key_e2e_12345"
curl -s -H "x-api-key: $API_KEY" "http://localhost:8080/api/v1/analytics/ai-metrics?org_id=test_org_1" | jq
```

**Expected Output**:

- `summary`: Counts of AI findings.
- `by_tool`: List including "GitHub Copilot", "ChatGPT", etc.
- `by_pattern`: Top patterns.
- `confidence_distribution`: High/Medium/Low counts.

### Step 2: Dashboard Visualization

1. Open the dashboard in your browser (http://localhost:3000).
2. Ensure you are in **API Mode** (Globe icon 🌐).
3. If not, click Settings ⚙️ and enter:
   - URL: `http://localhost:8080`
   - Key: `test_key_e2e_12345` (or your key)
4. Verify the **"AI Detection Metrics"** panel appears below the filters.
5. Check that the "Tool Breakdown", "Top 10 Patterns", and "Confidence" charts are populated.

---

## 2. Compliance Reports 📋

**Objective**: Verify that the CSV report can be generated and downloaded.

### Step 1: Generate Report via Dashboard

1. Click the **Export Report 📋** button in the dashboard header.
2. In the modal:
   - **Format**: Keep "CSV".
   - **Template**: Select "General Audit" (or others).
   - **Date Range**: Leave empty for last 30 days.
3. Click **Download Report**.
4. A file named `compliance-report-test_org_1-TIMESTAMP.csv` should download.

### Step 2: Verify CSV Content

Open the downloaded CSV and check specifically for:
- `Top CWE`
- `Top OWASP`
- `Compliance Score` (last column, e.g. `85.5%`)

### Step 3: Backend Verification via CLI

```bash
API_KEY="test_key_e2e_12345"
curl -v -H "x-api-key: $API_KEY" \
  "http://localhost:8080/api/v1/reports/compliance?org_id=test_org_1&format=csv" \
  > report.csv
```

Check that the file is not empty:

```bash
cat report.csv
```

### Step 4: Compliance Gaps Endpoint Verification

```bash
API_KEY="test_key_e2e_12345"
curl -s -H "x-api-key: $API_KEY" \
  "http://localhost:8080/api/v1/analytics/compliance-gaps?org_id=test_org_1&days=30&limit=5" | jq
```

Expected shape:
- `summary.coverage_pct` is present
- `top_cwe` includes `key`, `count`, and severity mix fields
- `top_owasp` includes `key`, `count`, and severity mix fields

## 3. Staged Hardening Checks 🔒

**Objective**: Verify strict CORS allowlist and rate-limit enforcement before staging deploy.

Run smoke in hardening mode:

```bash
AISHIELD_ALLOWED_ORIGINS=http://localhost:3000 \
AISHIELD_RATE_LIMIT_REQUESTS=12 \
AISHIELD_RATE_LIMIT_SECONDS=60 \
AISHIELD_SMOKE_ASSERT_CORS=1 \
AISHIELD_SMOKE_ALLOWED_ORIGIN=http://localhost:3000 \
AISHIELD_SMOKE_DISALLOWED_ORIGIN=https://not-allowed.example \
AISHIELD_SMOKE_ASSERT_RATE_LIMIT=1 \
AISHIELD_SMOKE_RATE_LIMIT_MAX=12 \
./scripts/start-analytics-stack.sh
```

Expected additional smoke results:
- `pass: cors -> strict allowlist behavior verified`
- `pass: rate-limit -> middleware limit enforced`

---

## Troubleshooting

- **Panel not showing?**
  - Ensure `fetchAIMetrics` succeeded in the network tab.
  - Check browser console for "[AI Metrics] Error".
- **Empty data?**
  - Your database might rely on old data. Run the E2E test script to generate fresh data with AI metadata:
  ```bash
  ./scripts/e2e-test.sh
  ```

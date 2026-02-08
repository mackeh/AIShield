# AIShield CLI

Command-line interface for the AIShield security scanner.

## Installation

```bash
cargo install --path crates/aishield-cli
```

## Commands

### `scan` - Scan code for security vulnerabilities

```bash
aishield scan <target> [OPTIONS]
```

**Options**:

- `--analytics-push` - Push scan results to analytics API
- `--format <json|table>` - Output format
- `--rules-dir <path>` - Custom rules directory
- `--dedup <none|file|all>` - Deduplication mode
- `--no-history` - Don't save to history file
- And more (see `aishield scan --help`)

**Examples**:

```bash
# Basic scan
aishield scan ./src

# Scan with analytics push
aishield scan ./src --analytics-push

# CI/CD scan with environment variables
AISHIELD_ANALYTICS_URL=https://analytics.company.com \
AISHIELD_API_KEY=prod_key \
AISHIELD_ORG_ID=github/acme \
aishield scan ./src --analytics-push --format json
```

### `config` - Manage configuration

```bash
aishield config <set|get|show>
```

**Subcommands**:

**`set`** - Set a configuration value

```bash
aishield config set analytics.url http://localhost:8080
aishield config set analytics.api_key your_api_key
aishield config set analytics.org_id github/your-org
aishield config set analytics.team_id your-team
```

**`get`** - Get a configuration value

```bash
aishield config get analytics.url
```

**`show`** - Show all configuration

```bash
aishield config show
```

**Configuration file**: `~/.config/aishield/config.toml`

**Example config**:

```toml
[analytics]
enabled = false
url = "http://localhost:8080"
api_key = "your_api_key_here"
org_id = "github/acme-corp"
team_id = "backend"
```

### `analytics` - Analytics operations

```bash
aishield analytics migrate-history [OPTIONS]
```

Migrate historical scan data from local `.aishield-history.log` to the analytics API.

**Options**:

- `--dry-run` - Preview migration without pushing data
- `--history-file <path>` - Custom history file path (default: `.aishield-history.log`)

**Examples**:

```bash
# Preview migration
aishield analytics migrate-history --dry-run

# Migrate history to analytics
aishield analytics migrate-history

# Migrate from custom history file
aishield analytics migrate-history --history-file /path/to/history.log
```

### Other Commands

- `fix` - Apply automated fixes
- `bench` - Run benchmarks
- `init` - Initialize AIShield in a project
- `create-rule` - Create a new rule scaffold
- `stats` - View scan statistics
- `hook` - Git hook integration
- `tui` - Interactive TUI mode

## Environment Variables

The following environment variables override config file settings:

- `AISHIELD_ANALYTICS_URL` - Analytics API endpoint
- `AISHIELD_API_KEY` - API authentication key
- `AISHIELD_ORG_ID` - Organization identifier
- `AISHIELD_TEAM_ID` - Team identifier
- `AISHIELD_ANALYTICS_ENABLED` - Enable/disable analytics

**Perfect for CI/CD**: Set environment variables in your CI pipeline to avoid storing credentials in config files.

## Analytics Integration

The CLI can push scan results to a centralized analytics API for tracking, visualization, and compliance reporting.

### Setup

1. **Configure analytics**:

```bash
aishield config set analytics.url https://analytics.company.com
aishield config set analytics.api_key your_api_key
aishield config set analytics.org_id github/your-org
```

2. **Run a scan with analytics push**:

```bash
aishield scan ./src --analytics-push
```

3. **Migrate historical scans**:

```bash
aishield analytics migrate-history
```

### CI/CD Integration

**GitHub Actions**:

```yaml
- name: Security Scan
  run: aishield scan . --analytics-push --format json
  env:
    AISHIELD_ANALYTICS_URL: ${{ secrets.ANALYTICS_URL }}
    AISHIELD_API_KEY: ${{ secrets.ANALYTICS_API_KEY }}
    AISHIELD_ORG_ID: github/${{ github.repository_owner }}
    AISHIELD_TEAM_ID: ${{ github.repository }}
```

**GitLab CI**:

```yaml
security_scan:
  script:
    - aishield scan . --analytics-push
  variables:
    AISHIELD_ANALYTICS_URL: $ANALYTICS_URL
    AISHIELD_API_KEY: $ANALYTICS_API_KEY
    AISHIELD_ORG_ID: $CI_PROJECT_NAMESPACE
```

### How It Works

1. **Scan execution**: AIShield scans your code
2. **Local history**: Results saved to `.aishield-history.log` (backward compatible)
3. **Analytics push**: If `--analytics-push` flag is set, results are sent to the API
4. **Graceful degradation**: Scan completes successfully even if API is unavailable
5. **Git metadata**: Automatically extracts repo ID, branch, commit SHA for context

### Data Sent to Analytics

- Scan summary (finding counts by severity)
- Repository metadata (repo ID, branch, commit)
- Organization and team identifiers
- Scan timestamp and CLI version
- Detailed findings (rule ID, severity, file path, line number)

API keys are never logged and are masked in output.

## License

See root LICENSE file.

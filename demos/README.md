# AIShield Demos — Interactive Walkthrough

This directory contains a comprehensive demo suite showcasing AIShield's vulnerability detection capabilities.

## 🚀 Quick Start

From repository root:

```bash
bash demos/run.sh
```

This generates all demo outputs in approximately **10 seconds**.

---

## 📁 Generated Artifacts

After running `demos/run.sh`, you'll find these files in `demos/output/`:

| File              | Description                 | Use Case                                 |
| ----------------- | --------------------------- | ---------------------------------------- |
| `scan-table.txt`  | Human-readable table format | Quick review, sharing reports            |
| `scan.json`       | Machine-readable JSON       | CI/CD integration, automation            |
| `scan.sarif`      | SARIF format                | GitHub Code Scanning, IDE integration    |
| `scan-github.txt` | GitHub annotation commands  | PR review workflows                      |
| `fix-dry-run.txt` | Remediation suggestions     | Understanding how to fix vulnerabilities |
| `bench.txt`       | Performance benchmarks      | Performance monitoring                   |
| `stats.txt`       | Scan history analytics      | Trend tracking                           |

---

## 🎬 Demo Walkthrough

### Part 1: Running the Scanner

```bash
# Basic scan (human-readable output)
cargo run -p aishield-cli -- scan tests/fixtures
```

**What you'll see**:

```text
Scanning: tests/fixtures
Loaded 169 rules across 13 languages

[CRITICAL] SQL injection via string concatenation
  File: tests/fixtures/vulnerable.py:23
  Rule: AISHIELD-PY-INJECT-001
  AI Confidence: 91%

  23 | query = "SELECT * FROM users WHERE id = " + user_id

  Fix: Use parameterized queries to prevent SQL injection

[HIGH] Timing-unsafe password comparison
  File: tests/fixtures/auth.py:12
  Rule: AISHIELD-PY-AUTH-002
  AI Confidence: 89%

  12 | if user_password == stored_password:

  Fix: Use secrets.compare_digest() for constant-time comparison

...

Summary: 96 findings across 7 files
  critical=6 high=66 medium=19 low=5 info=0
  AI-Generated (estimated): 27 of 96 findings (28%)
```

**Key observations**:

- ✅ Fast scan (< 2 seconds on fixtures)
- ✅ AI confidence scoring highlights likely AI-generated code
- ✅ Clear fix suggestions for each finding
- ✅ Categorized by severity

---

### Part 2: Machine-Readable Outputs

#### JSON Format (for CI/CD)

```bash
cargo run -p aishield-cli -- scan tests/fixtures --format json --output scan.json
```

**Use case**: Parse in CI scripts, integrate with dashboards

**Sample output**:

```json
{
  "findings": [
    {
      "id": "AISHIELD-PY-INJECT-001",
      "title": "SQL injection via string concatenation",
      "severity": "critical",
      "file": "tests/fixtures/vulnerable.py",
      "line": 23,
      "ai_confidence": 0.91,
      "risk_score": 9.1,
      "category": "injection",
      "fix_suggestion": "Use parameterized queries...",
      "tags": ["injection", "sql-injection", "owasp-top10"],
      "cwe": "CWE-89"
    }
  ],
  "summary": {
    "total_findings": 96,
    "critical": 6,
    "high": 66,
    "ai_generated_count": 27
  }
}
```

#### SARIF Format (for GitHub)

```bash
cargo run -p aishield-cli -- scan tests/fixtures --format sarif --output scan.sarif
```

**Use case**: Upload to GitHub Code Scanning API

---

### Part 3: Interactive Fix Mode

```bash
cargo run -p aishield-cli -- fix tests/fixtures/vulnerable.py --interactive
```

**What happens**:

1. Displays each finding
2. Shows suggested fix
3. Asks: Apply fix? (y/n)
4. Applies safe replacements automatically

**Example**:

```text
[CRITICAL] SQL injection at line 23

Current:
  query = "SELECT * FROM users WHERE id = " + user_id

Suggested fix:
  query = "SELECT * FROM users WHERE id = ?"
  cursor.execute(query, [user_id])

✓ Apply this fix? [y/N]: y
✓ Fixed!
```

---

### Part 4: CI/CD Integration

#### GitHub Actions

```bash
cargo run -p aishield-cli -- scan . --format github --dedup normalized
```

**Output** (GitHub annotations):

```
::error file=src/auth.py,line=45::HIGH: Timing-unsafe password comparison (AISHIELD-PY-AUTH-002)
::warning file=src/crypto.js,line=12::MEDIUM: Weak random number generation (AISHIELD-JS-CRYPTO-003)
```

These appear as inline PR comments in GitHub!

#### CI Script Example

```yaml
# .github/workflows/security-scan.yml
- name: Run AIShield
  run: |
    cargo run -p aishield-cli -- scan . \
      --format sarif \
      --output aishield.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: aishield.sarif
```

---

## 💡 Common Scenarios

### Scenario 1: "I just added AI-generated code — is it safe?"

```bash
# Scan specific file
cargo run -p aishield-cli -- scan src/new-feature.py

# Focus on high+ severity
cargo run -p aishield-cli -- scan src/new-feature.py --min-severity high
```

### Scenario 2: "Show only NEW vulnerabilities since last scan"

```bash
# Create baseline
cargo run -p aishield-cli -- scan . --format sarif --output baseline.sarif

# After changes, compare
cargo run -p aishield-cli -- scan . --format sarif --baseline baseline.sarif --output new-findings.sarif
```

### Scenario 3: "I want to fix these vulnerabilities now"

```bash
# Dry run (see what would change)
cargo run -p aishield-cli -- fix . --dry-run

# Interactive mode (review each fix)
cargo run -p aishield-cli -- fix . --interactive

# Auto-apply (use with caution!)
cargo run -p aishield-cli -- fix . --write
```

### Scenario 4: "How fast is the scanner on my large codebase?"

```bash
# Run benchmark
cargo run -p aishield-cli -- bench . --iterations 3 --warmup 1
```

**Sample output**:

```text
Benchmark Results (3 iterations, 1 warmup)
  Average: 1.24s
  Median: 1.22s
  P95: 1.29s
  Throughput: 403 files/sec
```

---

## 🎯 What You'll Discover

Running the demo suite reveals:

### Critical Findings (6)

- SQL injection patterns (string concatenation)
- Hardcoded secrets in source code
- Command injection vulnerabilities
- eval() usage with user input

### High Severity (66)

- Timing-unsafe authentication
- Weak cryptographic algorithms (MD5, SHA1, DES)
- Insecure random number generation
- SSL certificate validation bypass

### Medium Severity (19)

- Information disclosure risks
- Weak password requirements
- Insufficient input validation

### AI-Generated Patterns (28%)

- Many findings show high AI confidence scores (0.8+)
- Patterns match common AI autocomplete suggestions
- Training data bias evident (outdated crypto examples)

---

## 📊 Understanding the Outputs

### Table Output (`scan-table.txt`)

Best for: Quick human review

```text
┌─────────┬──────────────────────────────┬─────────────┬──────────────┐
│ Severity│ Title                        │ File        │ AI Conf      │
├─────────┼──────────────────────────────┼─────────────┼──────────────┤
│ CRITICAL│ SQL injection                │ db.py:23    │ 91%          │
│ HIGH    │ Weak crypto (MD5)            │ auth.py:12  │ 85%          │
└─────────┴──────────────────────────────┴─────────────┴──────────────┘
```

### JSON Output (`scan.json`)

Best for: Automation, dashboards, programmatic processing

Parse with jq:

```bash
# Count findings by severity
jq '.summary' demos/output/scan.json

# List all critical findings
jq '.findings[] | select(.severity=="critical")' demos/output/scan.json

# Get AI-generated findings only
jq '.findings[] | select(.ai_confidence > 0.8)' demos/output/scan.json
```

### SARIF Output (`scan.sarif`)

Best for: IDE integration, GitHub Code Scanning

SARIF is the industry standard. Compatible with:

- GitHub Security Tab
- VS Code (with SARIF viewer extension)
- Azure DevOps
- Jenkins SARIF plugins

---

## 🔧 Customizing the Demo

### Run Specific Languages Only

```bash
# Python only
cargo run -p aishield-cli -- scan tests/fixtures --include "*.py"

# JavaScript/TypeScript
cargo run -p aishield-cli -- scan tests/fixtures --include "*.js" --include "*.ts"
```

### Adjust Deduplication

```bash
# Strict (exact matches only)
cargo run -p aishield-cli -- scan . --dedup strict

# Normalized (merge similar findings)
cargo run -p aishield-cli -- scan . --dedup normalized

# None (show all findings)
cargo run -p aishield-cli -- scan . --dedup none
```

### Enable Experimental Features

```bash
# Cross-file auth route detection
cargo run -p aishield-cli -- scan . --cross-file

# ONNX-based AI classifier (requires --features onnx build)
cargo run -p aishield-cli --features onnx -- scan . --ai-model onnx --onnx-model models/ai-classifier/model.onnx
```

---

## 🐛 Troubleshooting

**Demo script fails with "command not found"**

```bash
# Make sure you're in project root
cd /path/to/AIShield
bash demos/run.sh
```

**Scan finds 0 vulnerabilities**

```bash
# Check fixture files exist
ls tests/fixtures/

# Run with verbose output
cargo run -p aishield-cli -- scan tests/fixtures --verbose
```

**JSON output is malformed**

```bash
# Validate JSON
cat demos/output/scan.json | jq '.'
```

---

## 📚 Next Steps

After running the demo:

1. **Try on real code**: `cargo run -p aishield-cli -- scan /path/to/your/project`
2. **Integrate with CI**: See [docs/ci-github-actions.md](../docs/ci-github-actions.md)
3. **Customize rules**: Read [docs/guides/writing-your-first-rule.md](../docs/guides/writing-your-first-rule.md)
4. **Install VS Code extension**: See `integrations/vscode-extension/README.md`

---

## 💬 Questions?

- 📖 **Docs**: See complete documentation at [docs/](../docs/)
- 💡 **Discussions**: Ask questions in [GitHub Discussions](https://github.com/mackeh/AIShield/discussions)
- 🐛 **Issues**: Report bugs at [GitHub Issues](https://github.com/mackeh/AIShield/issues)

---

Happy scanning! 🛡️✨

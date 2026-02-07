# 🛡️ AIShield — AI-Generated Code Security Validator

> **Catch the vulnerabilities AI writes before they ship.**

A blazing-fast, extensible security analysis platform purpose-built for the age of AI-assisted development. AIShield detects the *specific* vulnerability patterns that LLMs introduce — not just generic lint issues — and provides actionable, context-aware remediation right in your workflow.

---

## Vision

Every day, millions of developers ship AI-generated code. Studies show that **40%+ of Copilot-generated code contains security vulnerabilities** (Stanford, 2023). Generic SAST tools catch some of these, but they miss the *systemic patterns* unique to LLM output: hallucinated APIs, outdated crypto defaults, naïve auth flows, and subtly broken input validation that *looks* correct to a human reviewer.

**AIShield exists to close that gap.** It combines a curated AI-specific vulnerability knowledge base, pluggable static analysis engines, ML-powered confidence scoring, and a developer-first UX across CLI, CI/CD, IDE, and dashboard.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      AIShield Platform                      │
├──────────┬──────────┬──────────┬──────────┬─────────────────┤
│   CLI    │ Pre-Commit│  GitHub  │  VS Code │   Web Dashboard │
│  Tool    │   Hook   │  Action  │Extension │   & Analytics   │
├──────────┴──────────┴──────────┴──────────┴─────────────────┤
│                    Core Analysis Engine                      │
│  ┌────────────┐ ┌────────────┐ ┌──────────────────────────┐ │
│  │ AI Pattern │ │  SAST      │ │  Confidence Scoring      │ │
│  │ Detector   │ │  Bridge    │ │  Engine (ML + Heuristic) │ │
│  └────────────┘ └────────────┘ └──────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Knowledge Layer                           │
│  ┌─────────────┐ ┌───────────┐ ┌──────────────────────────┐│
│  │ AI Vuln     │ │ Ruleset   │ │  Community Rule          ││
│  │ Fingerprint │ │ Engine    │ │  Marketplace             ││
│  │ Database    │ │ (YAML)    │ │                          ││
│  └─────────────┘ └───────────┘ └──────────────────────────┘│
├─────────────────────────────────────────────────────────────┤
│                  Analytics & Telemetry                       │
│  ┌──────────────────┐ ┌────────────────────────────────────┐│
│  │ Pattern Frequency │ │ Org-level Security Posture Trends ││
│  │ Tracker           │ │ & AI Adoption Risk Score          ││
│  └──────────────────┘ └────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. AI Vulnerability Fingerprint Database (`aivfdb`)

The heart of AIShield — a structured, versioned knowledge base of vulnerability patterns *specific to AI code generation*. This is **not** another CVE database. It catalogs the *systemic tendencies* of LLMs.

**Categories tracked:**

| Category | Example | Why AI Gets It Wrong |
|---|---|---|
| **Hallucinated APIs** | Calling `crypto.createCipher()` (deprecated) instead of `crypto.createCipheriv()` | LLMs trained on older code; API exists but is insecure |
| **Outdated Crypto Defaults** | Using MD5/SHA1 for hashing, ECB mode for encryption | Pattern-matches "common" usage from training data |
| **Naïve Auth Patterns** | Storing passwords with `base64`, using `==` for token comparison | Generates "looks correct" code that fails timing attacks |
| **Injection Blind Spots** | SQL concatenation, unsanitized `innerHTML`, template injection | LLMs prioritize readability over parameterization |
| **SSRF / Open Redirect** | Fetching user-provided URLs without allowlisting | Missing threat model awareness |
| **Incomplete Error Handling** | Empty catch blocks, leaking stack traces to clients | LLMs optimize for "happy path" |
| **Insecure Defaults** | `CORS: *`, `verify=False`, `DEBUG=True` in production configs | Training data includes tutorials/examples |
| **Race Conditions** | TOCTOU bugs in file ops, non-atomic DB updates | Concurrency is underrepresented in LLM training |
| **Dependency Confusion** | Suggesting packages that don't exist or are typosquatted | Hallucinated package names |
| **Phantom Permissions** | Over-broad IAM policies, unnecessary `sudo` usage | LLMs default to "make it work" |

**Database format:** YAML with rich metadata, organized by language → category → pattern.

```yaml
# rules/python/crypto/weak-hash.yaml
id: AISHIELD-PY-CRYPTO-001
title: "AI-Suggested Weak Hash Algorithm"
severity: high
confidence_that_ai_generated: 0.85
languages: [python]
ai_tendency: >
  LLMs frequently suggest hashlib.md5() or hashlib.sha1() for
  password hashing or integrity checks, mirroring outdated
  tutorials in training data.
pattern:
  semgrep: "hashlib.$WEAK_ALGO(...)"
  meta_vars:
    WEAK_ALGO: [md5, sha1]
negative_patterns:
  - context: "checksum for non-security file verification"
    action: downgrade_to_info
fix:
  suggestion: "Use hashlib.sha256() for integrity, or bcrypt/argon2 for passwords"
  autofix:
    type: semgrep_autofix
    replacement: "hashlib.sha256(...)"
  safe_example: |
    import bcrypt
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
references:
  - https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
tags: [owasp-top10, crypto, passwords]
```

### 2. AI Pattern Detector

The detection engine that goes beyond regex — combining AST-level analysis with AI-specific heuristics.

**Detection strategies:**

- **Structural Pattern Matching** — AST queries for known insecure code shapes (tree-sitter based for speed and multi-language support)
- **Dataflow Analysis** — Taint tracking from user inputs to dangerous sinks (SQL queries, shell commands, file paths, response bodies)
- **Context-Aware Suppression** — Understands when a pattern is a false positive (e.g., MD5 used for non-security checksums, `CORS: *` in a dev config)
- **Cross-File Analysis** — Detects patterns that span multiple files (e.g., auth middleware defined but never applied to sensitive routes)
- **Semantic Similarity** — Embeds code snippets and compares against the fingerprint DB for "close but wrong" patterns the LLM hallucinated

**Supported languages (launch):**
Python, JavaScript/TypeScript, Go, Rust, Java, C#, Ruby, PHP

**Planned:**
Kotlin, Swift, Terraform/HCL, Dockerfiles, Kubernetes YAML, SQL

### 3. SAST Bridge — Unified Multi-Engine Integration

Rather than reinventing existing SAST, AIShield orchestrates them and enriches their output.

```
         ┌──────────┐
         │ AIShield │
         │   Core   │
         └────┬─────┘
    ┌─────────┼─────────┬──────────┐
    ▼         ▼         ▼          ▼
┌────────┐ ┌───────┐ ┌──────┐ ┌────────┐
│Semgrep │ │Bandit │ │ESLint│ │CodeQL  │
│        │ │       │ │(sec) │ │(custom)│
└───┬────┘ └───┬───┘ └──┬───┘ └───┬────┘
    └──────────┴────────┴──────────┘
                    │
              Unified Results
              + AI Enrichment
              + Deduplication
              + Confidence Score
```

**What the bridge does:**
- **Auto-detects** which engines are available and installs missing ones
- **Runs them in parallel** with a unified configuration
- **Deduplicates** findings across engines (e.g., Semgrep and Bandit both catching the same SQL injection)
- **Enriches** every finding with AI-specific context from the fingerprint DB
- **Prioritizes** findings by combining SAST severity with AI confidence scoring

### 4. Confidence Scoring Engine

Not all findings are equal. The scoring engine assigns a **composite risk score** to every finding:

```
Risk Score = (SAST Severity × 0.3)
           + (AI Likelihood × 0.3)
           + (Context Risk × 0.2)
           + (Exploitability × 0.2)
```

**Factors:**

| Factor | What It Measures | Source |
|---|---|---|
| SAST Severity | Base vulnerability severity | Underlying SAST engine |
| AI Likelihood | Probability this was AI-generated (not human-written) | ML classifier trained on AI vs human code |
| Context Risk | Is this in auth code? Payment processing? Admin panel? | File path heuristics + semantic analysis |
| Exploitability | How easy is it to actually exploit? | CVSS-inspired scoring of the specific pattern |

**AI Likelihood Classifier:**
A lightweight transformer model (distilled, <50MB) that scores code snippets on how likely they are to be AI-generated. Trained on labeled datasets of human vs. LLM code. This lets teams focus specifically on *AI-introduced* risk.

### 5. Remediation Engine

Every finding comes with actionable, context-aware fix suggestions:

- **Inline Autofixes** — One-click safe replacements for common patterns (e.g., `createCipher` → `createCipheriv` with proper IV generation)
- **Safe Code Templates** — Full replacement snippets using current best practices
- **Explanation Cards** — Human-readable explanation of *why* the AI got this wrong and what the secure approach looks like
- **Link to Proof** — References to OWASP, CWE, relevant CVEs, and language-specific security guides

---

## Interfaces & Integrations

### CLI Tool (`aishield`)

The primary interface. Fast, scriptable, beautiful terminal output.

```bash
# Scan a directory
aishield scan ./src

# Scan with specific rulesets
aishield scan ./src --rules crypto,injection,auth

# Scan only AI-generated code (uses git metadata + AI classifier)
aishield scan ./src --ai-only

# Output machine-readable formats
aishield scan ./src --format sarif    # GitHub Security tab compatible
aishield scan ./src --format json
aishield scan ./src --format table

# Interactive fix mode
aishield fix ./src

# Show analytics summary
aishield stats --last 30d
```

**Example output:**

```
 AIShield v1.0.0 — Scanning 142 files...

 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

 🔴 CRITICAL  src/auth/login.py:34
 │  AISHIELD-PY-CRYPTO-003: Password stored with reversible encoding
 │  AI Confidence: 92% — LLMs frequently suggest base64 for "encoding" passwords
 │  
 │    32 │ def store_password(password):
 │    33 │     encoded = base64.b64encode(password.encode())
 │  → 34 │     db.users.update({"password": encoded})
 │  
 │  💡 Fix: Use bcrypt or argon2id for password hashing
 │  🔧 Run `aishield fix src/auth/login.py:34` for interactive fix

 🟠 HIGH  src/api/users.py:87
 │  AISHIELD-JS-INJ-001: SQL query built with string concatenation
 │  AI Confidence: 78% — Common LLM pattern for "simple" queries
 │  ...

 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 Summary: 3 critical · 7 high · 12 medium · 5 low
 AI-Generated (estimated): 18 of 27 findings
 Top pattern: Insecure crypto defaults (8 findings)
```

### Pre-Commit Hook

Zero-config integration — blocks commits with critical AI security issues.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/aishield/aishield
    rev: v1.0.0
    hooks:
      - id: aishield
        args: [--severity, high, --fail-on-findings]
```

### GitHub Action

Full CI/CD integration with PR annotations and Security tab reporting.

```yaml
# .github/workflows/aishield.yml
name: AIShield Security Scan
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aishield/action@v1
        with:
          severity_threshold: medium
          sarif_upload: true          # Populate GitHub Security tab
          pr_comment: true            # Inline PR annotations
          ai_only: false              # Scan all code, flag AI patterns
          rules: default,strict-crypto
```

**PR experience:**

```
🛡️ AIShield found 3 issues in this PR

| Severity | File | Issue | AI Confidence |
|----------|------|-------|---------------|
| 🔴 Critical | auth/handler.go:45 | Timing-unsafe token comparison | 94% |
| 🟠 High | api/upload.go:112 | Path traversal in filename | 87% |
| 🟡 Medium | utils/http.go:23 | TLS MinVersion not set | 72% |

> 💡 2 of 3 findings match known AI code generation patterns.
> Run `aishield fix` locally for interactive remediation.
```

### VS Code Extension

Real-time scanning as you code, with special awareness of AI assistant output.

**Features:**
- Highlights AI-suspect vulnerabilities inline with red/orange squiggles
- Hover cards with explanation + one-click fix
- Detects when code is pasted from an AI assistant (clipboard analysis)
- Sidebar panel showing current file's AI security score
- "AI Security Lens" mode that dims safe code and highlights risky patterns

### Web Dashboard & Analytics

The team-level view of AI code security posture.

**Features:**
- **Org-wide vulnerability heatmap** — Which repos, teams, and languages have the most AI security issues?
- **Trend lines** — Are AI-generated vulnerabilities increasing or decreasing over time?
- **Top AI vulnerability patterns** — The 10 most common AI-specific issues across your org
- **Developer leaderboards** — Gamified security improvement (opt-in, privacy-respecting)
- **AI tool comparison** — How do different AI assistants compare in security quality? (Copilot vs. Claude vs. Cursor, etc.)
- **Compliance reports** — Auto-generated reports for SOC2, ISO 27001, HIPAA audits showing AI code risk management
- **Alert system** — Slack/email/webhook alerts when new critical AI patterns are detected

---

## Technical Implementation Plan

### Tech Stack

| Component | Technology | Rationale |
|---|---|---|
| CLI & Core Engine | **Rust** | Speed (must be <2s for pre-commit), memory safety, excellent CLI ecosystem (clap, indicatif) |
| AST Parsing | **tree-sitter** | Incremental, multi-language, battle-tested |
| Rule Engine | **YAML rules + Rust evaluator** | Declarative, community-contributable, fast execution |
| SAST Bridge | **Rust orchestrator + subprocess** | Parallel execution, unified output normalization |
| AI Classifier | **ONNX Runtime** | Portable, fast inference, no Python dependency for end users |
| GitHub Action | **TypeScript** | Native Actions ecosystem |
| VS Code Extension | **TypeScript** | Required by VS Code extension API |
| Web Dashboard | **Next.js + Postgres + tRPC** | Full-stack type safety, great DX, Vercel-deployable |
| Analytics Pipeline | **ClickHouse** | Column-oriented, perfect for time-series vuln analytics |

### Project Structure

```
aishield/
├── crates/
│   ├── aishield-core/        # Core analysis engine
│   │   ├── src/
│   │   │   ├── detector/     # AI pattern detection
│   │   │   ├── scorer/       # Confidence scoring
│   │   │   ├── bridge/       # SAST engine integration
│   │   │   ├── rules/        # Rule engine & parser
│   │   │   ├── remediation/  # Fix suggestions & autofixes
│   │   │   └── classifier/   # AI vs human code classifier
│   │   └── Cargo.toml
│   ├── aishield-cli/         # CLI interface
│   └── aishield-lib/         # Public Rust API for embedding
├── rules/
│   ├── python/
│   │   ├── crypto/
│   │   ├── injection/
│   │   ├── auth/
│   │   └── ...
│   ├── javascript/
│   ├── go/
│   ├── rust/
│   └── _shared/              # Language-agnostic rules
├── models/
│   └── ai-classifier/        # ONNX model + training scripts
├── integrations/
│   ├── github-action/
│   ├── vscode-extension/
│   ├── pre-commit/
│   └── jetbrains-plugin/     # Future
├── dashboard/
│   ├── app/                  # Next.js app router
│   ├── packages/
│   │   ├── db/               # Prisma + ClickHouse
│   │   └── api/              # tRPC routers
│   └── docker-compose.yml
├── docs/
│   ├── rules-authoring.md    # How to write custom rules
│   ├── architecture.md
│   └── api-reference.md
├── tests/
│   ├── fixtures/             # Vulnerable code samples (AI-generated)
│   ├── integration/
│   └── benchmarks/
└── scripts/
    ├── train-classifier.py   # AI classifier training pipeline
    └── scrape-patterns.py    # Automated pattern discovery
```

---

## Development Roadmap

### Phase 1 — Foundation (Weeks 1–6)

**Goal:** Working CLI that scans Python and JavaScript with 30 core rules.

- [ ] Set up Rust workspace with `aishield-core` and `aishield-cli` crates
- [ ] Implement tree-sitter AST parsing for Python and JavaScript
- [ ] Build YAML rule engine with support for AST patterns, semgrep integration, and negative patterns
- [ ] Write 30 foundational rules (10 crypto, 10 injection, 5 auth, 5 misconfiguration)
- [ ] Implement basic confidence scoring (heuristic-only, no ML yet)
- [ ] Build CLI with `scan`, `fix`, and `init` commands
- [ ] SARIF output format for GitHub Security tab compatibility
- [ ] Comprehensive test suite with 100+ vulnerable code fixtures
- [ ] Pre-commit hook support
- [ ] Documentation site (VitePress or Starlight)

### Phase 2 — Intelligence (Weeks 7–12)

**Goal:** ML classifier, SAST bridge, and GitHub Action.

- [ ] Train AI vs. human code classifier on public datasets (The Stack, etc.)
- [ ] Export classifier to ONNX, integrate into core engine
- [ ] Build SAST bridge: Semgrep, Bandit, ESLint security plugins
- [ ] Parallel engine execution with unified result normalization and dedup
- [ ] Add Go, Rust, and Java language support (20 rules each)
- [ ] GitHub Action with PR annotations and SARIF upload
- [ ] Remediation engine: autofix for top 20 patterns
- [ ] `aishield fix` interactive terminal mode (TUI with ratatui)
- [ ] Benchmarking: target <2s scan time for 10K LOC repos

### Phase 3 — Platform (Weeks 13–20)

**Goal:** VS Code extension, web dashboard, analytics.

- [ ] VS Code extension with inline diagnostics and quick fixes
- [ ] AI paste detection (clipboard monitoring for AI assistant output)
- [ ] Web dashboard: org setup, repo connections, vulnerability views
- [ ] Analytics pipeline: ClickHouse for pattern frequency tracking
- [ ] Trend analysis and AI tool comparison dashboards
- [ ] Alert system (Slack, email, webhooks)
- [ ] Cross-file dataflow analysis for multi-file vulnerability chains
- [ ] Rule marketplace: community-contributed rules with review workflow

### Phase 4 — Ecosystem (Weeks 21–28)

**Goal:** Enterprise features, broad language support, API.

- [ ] JetBrains plugin (IntelliJ, PyCharm, GoLand, WebStorm)
- [ ] Add C#, Ruby, PHP, Kotlin, Swift support
- [ ] Terraform / HCL / Kubernetes YAML scanning
- [ ] Dockerfile security rules (AI-generated Dockerfiles are notoriously insecure)
- [ ] REST API for custom integrations
- [ ] Enterprise SSO, team management, RBAC
- [ ] Compliance report generation (SOC2, ISO 27001)
- [ ] Self-hosted deployment option (Docker Compose + Helm chart)
- [ ] GitLab CI and Bitbucket Pipelines integrations
- [ ] Automated pattern discovery: crawl AI code generation benchmarks to find new vulnerability patterns

---

## Differentiation from Existing Tools

| Feature | AIShield | Semgrep | Snyk Code | CodeQL |
|---|---|---|---|---|
| AI-specific vulnerability patterns | ✅ Core focus | ❌ | ❌ | ❌ |
| AI vs. human code classifier | ✅ | ❌ | ❌ | ❌ |
| AI confidence scoring | ✅ | ❌ | ❌ | ❌ |
| Context-aware suppression | ✅ | Partial | Partial | ✅ |
| Multi-engine orchestration | ✅ | N/A | N/A | N/A |
| AI paste detection (IDE) | ✅ | ❌ | ❌ | ❌ |
| AI tool comparison analytics | ✅ | ❌ | ❌ | ❌ |
| Community rule marketplace | ✅ | ✅ | ❌ | ✅ |
| Sub-2s pre-commit scans | ✅ (Rust) | ✅ | ❌ | ❌ |
| Free for open source | ✅ | ✅ | Limited | ✅ |

---

## Monetization Strategy (Open Core)

| Tier | Price | Features |
|---|---|---|
| **Community** | Free forever | CLI, pre-commit, 100+ rules, GitHub Action, SARIF output |
| **Pro** | $19/dev/mo | VS Code extension, autofix, AI classifier, priority rules |
| **Team** | $39/dev/mo | Dashboard, analytics, Slack alerts, custom rules, API |
| **Enterprise** | Custom | Self-hosted, SSO/SAML, compliance reports, SLA, dedicated support |

---

## Community & Contribution Model

- **Rule contributions** are the lifeblood — make it trivially easy to add new rules
- `aishield create-rule` wizard generates scaffolding from a vulnerability description
- All community rules go through automated testing + security review
- Monthly "AI Vulnerability Spotlight" blog post highlighting new patterns discovered
- Bounty program: $50–$500 for high-quality new vulnerability pattern discoveries
- Discord community for security researchers and AI-aware developers

---

## Success Metrics

| Metric | 6-Month Target | 12-Month Target |
|---|---|---|
| GitHub Stars | 5,000 | 20,000 |
| Rules in database | 200 | 500+ |
| Languages supported | 5 | 12 |
| Weekly active CLI users | 2,000 | 15,000 |
| GitHub Action installs | 500 repos | 5,000 repos |
| Unique AI vuln patterns cataloged | 50 | 150 |
| Community rule contributions | 30 | 200 |

---

## Getting Started (Post-Build)

```bash
# Install
cargo install aishield
# or
brew install aishield

# Initialize in your project
cd your-project
aishield init

# Run your first scan
aishield scan .

# Set up pre-commit hook
aishield hook install
```

---

## Why This Matters

The AI coding revolution is here. GitHub Copilot, Claude, Cursor, and dozens of other tools are writing production code at unprecedented scale. The security community hasn't kept up — existing tools were designed for *human* coding patterns.

**AIShield is the missing security layer for the AI-assisted development era.** It doesn't fight against AI adoption — it makes AI adoption *safe*. Every developer using AI code generation should have AIShield in their pipeline.

The patterns we catalog today will become the security training data of tomorrow. By building the definitive database of AI-specific vulnerabilities, we're not just building a tool — we're building the **immune system for AI-generated code**.

---

*Built with 🛡️ by developers who ship AI code — and want to sleep at night.*

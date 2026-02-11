# AIShield Roadmap

> Last updated: February 2026

---

## Completed Phases

### ✅ Phase 1 — Foundation (Complete)

- Rust-based CLI scanner with pattern matching engine
- Initial rule set for Python, JavaScript, Go
- JSON and plain text output formats
- Sub-2-second scan performance on most codebases
- `.aishield-ignore` file support

### ✅ Phase 2 — Intelligence (Complete)

- AI confidence scoring (heuristic + optional ONNX model)
- Context-aware risk scoring with severity and exploitability
- Cross-file analysis for auth route detection
- SAST bridge integration (Semgrep, Bandit, ESLint)
- Deduplication (normalized and strict modes)

### ✅ Phase 3 — Platform / Ecosystem Core (Complete)

- 237 rules across 13 languages (Python, JavaScript, Go, Rust, Java, C#, Ruby, PHP, Kotlin, Swift, Terraform/HCL, Kubernetes YAML, Dockerfiles)
- Interactive fix mode with TUI
- SARIF and GitHub Annotations output formats
- Pre-commit hook integration
- Analytics dashboard with scan history and severity breakdown
- VitePress documentation site

### 🚧 Phase 4 — Ecosystem Expansion (In Progress)

- [x] Production-grade CI templates (GitHub Actions, GitLab CI, Bitbucket, CircleCI, Jenkins)
- [x] VS Code extension GA (security lens, quick fixes, diagnostics panel, telemetry)
- [x] Analytics API with compliance reporting and threshold gating
- [x] `create-rule` command for custom YAML rule authoring
- [x] C#/Ruby/PHP rulepacks expanded to full 20-rule coverage
- [x] IaC rules expanded: Terraform 15, Kubernetes 15, Dockerfile 15
- [ ] JetBrains IDE plugin (IntelliJ, PyCharm, WebStorm)
- [ ] Neovim/LSP integration
- [ ] Pre-built binary distribution (Homebrew, APT, cargo install from crates.io)

---

## Upcoming Phases

### 🔜 Phase 5 — Usability & Adoption (Q2–Q3 2026)

#### Distribution & Onboarding

- **Package manager installs**: `brew install aishield`, `cargo install aishield-cli` from crates.io, `npx aishield` wrapper for zero-install usage
- **Interactive config wizard**: Enhanced `aishield init` with conversational setup — choose languages, CI platform, severity thresholds, and output format interactively
- **Severity tuning profiles**: Preset configurations — `strict` (all findings), `pragmatic` (high + critical only), `ai-focus` (high AI-confidence findings only) — to reduce noise and support gradual adoption

#### Developer Experience

- **`--watch` mode**: Live file-watching scanner that re-scans changed files on save, integrated with VS Code extension for real-time feedback
- **PR comment bot**: GitHub App that posts inline review comments on exact lines with findings (severity badge, AI confidence, suggested fix), similar to Codecov or SonarCloud
- **Online playground**: Browser-based "paste your code" scanner using a WASM build of the core engine — zero install, instant value demonstration
- **Improved error messages**: Contextual fix suggestions with code snippets, links to documentation, and "why this matters" explanations for each rule

#### Dashboard Enhancements

- **Team/org views**: Multi-repo dashboards with aggregated trends, top recurring vulnerabilities, and per-developer AI-code metrics
- **Scan comparison**: Side-by-side diff between two scans to show remediation progress
- **Export reports**: PDF and CSV export for compliance and management reporting

---

### 🔮 Phase 6 — Advanced Security & Woo Factor (Q3–Q4 2026)

#### Advanced Detection

- **Prompt injection detection**: Identify patterns in LLM API usage where unsanitised user input is passed directly to model prompts — a first-of-its-kind detection category
- **Supply chain / dependency awareness**: Cross-reference AI-suggested imports against OSV, NVD, and GitHub Advisory databases to flag outdated or vulnerable dependencies at scan time
- **Expanded secrets detection**: Beyond hardcoded API keys — detect leaked JWT secrets, private keys, `.env` files committed to source, and cloud credential patterns (AWS, GCP, Azure)
- **Lightweight taint analysis**: Intra-function data flow tracking from user input to dangerous sinks (SQL queries, shell commands, file operations) to catch vulnerabilities that regex alone misses
- **SBOM generation**: Generate Software Bill of Materials tied to scan results, mapping findings to specific components (aligned with US Executive Order and EU CRA requirements)

#### Trust & Compliance

- **Signed scan reports**: Cryptographically signed scan output for tamper-proof audit trails
- **CWE/CVE mapping**: Map every rule to relevant CWE and CVE identifiers for compliance reporting
- **Policy-as-code**: Define organisational security policies in YAML; fail CI builds when policy thresholds are breached

#### Woo Factor

- **AI Vulnerability Score badge**: Embeddable shields.io-style badge (`AIShield Score: A+`) for README files — gamification that drives adoption and visibility
- **"Vibe Check" mode**: Fun, opinionated scan output with personality — *"Your auth module looks like it was written by GPT-3.5 at 2am. 3 timing attacks, 2 hardcoded secrets."* — designed to be screenshot-worthy and shareable
- **VS Code "AI Radar" heatmap**: Gutter overlay showing which lines the AI classifier thinks were AI-generated, colour-coded by risk level — a visual experience unlike anything else on the market
- **LLM-powered auto-fix loop**: One-click "apply AI-safe fix" that uses an LLM to rewrite vulnerable code, then re-scans to verify the fix is clean — scanner finds → AI fixes → scanner verifies
- **Browser extension (Chrome/Firefox)**: WASM-powered extension that highlights vulnerable patterns in code snippets on GitHub, GitLab, and StackOverflow as you browse — catch problems before you copy-paste
- **Attack simulation narratives**: Dashboard view that visualises what an attacker could do with each finding — *"This SQL injection in users.py:23 could expose the users table → PII leak → GDPR violation"* — turns dry findings into threat stories that make non-technical stakeholders care
- **Community threat feed**: Crowd-sourced feed of newly discovered AI-generated vulnerability patterns, pushed as automatic rule updates to keep AIShield current

---

## Long-Term Vision (2027+)

- **AST-based analysis**: Complement regex patterns with tree-sitter-powered abstract syntax tree analysis for deeper, more accurate detection
- **IDE-agnostic Language Server Protocol (LSP)**: Single language server powering all editor integrations
- **AIShield Cloud**: Hosted SaaS offering with org management, SSO, and centralised policy enforcement
- **Model fine-tuning pipeline**: Continuously train the ONNX classifier on community-contributed samples to improve AI-confidence accuracy beyond 92%
- **Multi-repo monorepo support**: First-class support for scanning monorepos with per-package configuration and reporting

---

## How to Contribute

We welcome contributions at every phase! See [CONTRIBUTING.md](../CONTRIBUTING.md) for setup instructions.

**High-impact contribution areas right now:**

- 📝 Adding detection rules for new vulnerability patterns (especially prompt injection and secrets)
- 🌍 Expanding language coverage and improving existing rules
- 🧪 Writing test fixtures for edge cases
- 📚 Improving documentation and writing guides
- 🐛 Bug fixes and performance improvements

Find a [good first issue](https://github.com/mackeh/AIShield/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) to get started.

# AIShield — Detailed Build Process

> Implementation guide for Roadmap Phases 5–6 and Long-Term Vision

---

## Table of Contents

1. [Phase 5: Usability & Adoption](#phase-5-usability--adoption)
2. [Phase 6: Advanced Security & Woo Factor](#phase-6-advanced-security--woo-factor)
3. [Long-Term Vision](#long-term-vision)
4. [Infrastructure & DevOps Requirements](#infrastructure--devops-requirements)
5. [Dependency Map](#dependency-map)

---

## Phase 5: Usability & Adoption

### 5.1 — Package Manager Distribution

**Goal:** Get AIShield installable without a Rust toolchain.

**Steps:**

1. **Publish to crates.io**
   - Ensure `Cargo.toml` metadata is complete (`description`, `license`, `repository`, `keywords`, `categories`)
   - Run `cargo publish --dry-run` to validate
   - Publish: `cargo publish -p aishield-cli`
   - Users install via `cargo install aishield-cli`

2. **Pre-built binaries via GitHub Releases**
   - Add a `release.yml` GitHub Actions workflow triggered on tag push (`v*`)
   - Use `cross` for cross-compilation targets:
     - `x86_64-unknown-linux-gnu`
     - `x86_64-unknown-linux-musl` (static binary)
     - `aarch64-unknown-linux-gnu`
     - `x86_64-apple-darwin`
     - `aarch64-apple-darwin` (Apple Silicon)
     - `x86_64-pc-windows-msvc`
   - Archive each binary as `.tar.gz` (unix) / `.zip` (windows)
   - Upload to GitHub Releases with checksums (`sha256sum`)
   - Generate an `install.sh` script that detects OS/arch and downloads the correct binary

3. **Homebrew tap**
   - Create `homebrew-tap` repo at `mackeh/homebrew-aishield`
   - Write a formula (`Formula/aishield.rb`) that downloads the pre-built binary from GitHub Releases
   - Automate formula updates in the release workflow using `dawidd6/action-homebrew-bump-formula` or a custom script
   - Users install via `brew install mackeh/aishield/aishield`

4. **npx wrapper**
   - Create a small npm package (`aishield`) that downloads and caches the correct binary on first run
   - Use `node-pre-gyp`-style approach or a custom `postinstall` script
   - Publish to npm: `npm publish`
   - Users run via `npx aishield scan .`

**Estimated effort:** 2–3 weeks  
**Dependencies:** CI pipeline, cross-compilation toolchain  
**Key files:** `.github/workflows/release.yml`, `install.sh`, `homebrew-tap/Formula/aishield.rb`, `npm/package.json`

---

### 5.2 — Interactive Config Wizard (`aishield init`)

**Goal:** Guided setup that generates `.aishield.toml` configuration.

**Steps:**

1. **Add `dialoguer` crate** for interactive terminal prompts
   - `cargo add dialoguer` to `aishield-cli`

2. **Implement `init` subcommand flow:**
   ```
   $ aishield init
   
   🛡️  AIShield Setup Wizard
   
   ? What languages does your project use?
     ❯ [x] Python
       [x] JavaScript/TypeScript
       [ ] Go
       [ ] Rust
       ...
   
   ? What CI platform do you use?
     ❯ GitHub Actions
       GitLab CI
       Bitbucket Pipelines
       None / Other
   
   ? Severity threshold for CI failures?
     ❯ Critical only
       Critical + High
       Critical + High + Medium
       All findings
   
   ? Output format?
     ❯ JSON
       SARIF
       Text
       HTML
   
   ✅ Generated .aishield.toml
   ✅ Generated .github/workflows/aishield.yml
   ```

3. **Generate `.aishield.toml`** with selected options:
   ```toml
   [scan]
   languages = ["python", "javascript"]
   severity_threshold = "high"
   output_format = "sarif"
   
   [ci]
   platform = "github-actions"
   fail_on = "high"
   ```

4. **Generate CI template** based on platform selection — reuse existing `init --templates` logic but pre-fill values from wizard answers

5. **Detect project structure** — scan for `package.json`, `Cargo.toml`, `go.mod`, `requirements.txt`, `*.tf` to auto-suggest languages

**Estimated effort:** 1–2 weeks  
**Dependencies:** `dialoguer`, existing `init --templates` code  
**Key files:** `crates/aishield-cli/src/commands/init.rs`

---

### 5.3 — Severity Tuning Profiles

**Goal:** Pre-built configs that reduce noise for different adoption stages.

**Steps:**

1. **Define profile presets** in code:
   ```rust
   enum Profile {
       Strict,     // All severities, all rules, AI confidence >= 0%
       Pragmatic,  // Critical + High only, AI confidence >= 50%
       AiFocus,    // All severities but only AI confidence >= 75%
   }
   ```

2. **Add `--profile` flag** to `scan` command:
   ```
   aishield scan . --profile pragmatic
   ```

3. **Store profiles** as built-in TOML configs embedded via `include_str!`:
   ```toml
   # profiles/pragmatic.toml
   [filter]
   min_severity = "high"
   min_ai_confidence = 50
   ```

4. **Allow custom profiles** in `.aishield.toml`:
   ```toml
   [profiles.my-team]
   min_severity = "medium"
   min_ai_confidence = 60
   exclude_rules = ["AISHIELD-PY-INFO-001"]
   ```

5. **Profile flag overrides** — `--profile` takes precedence over `.aishield.toml` defaults

**Estimated effort:** 1 week  
**Dependencies:** None  
**Key files:** `crates/aishield-cli/src/profiles/`, `profiles/*.toml`

---

### 5.4 — Watch Mode

**Goal:** Re-scan changed files on save for instant feedback during development.

**Steps:**

1. **Add `notify` crate** for file system watching:
   ```
   cargo add notify
   ```

2. **Implement `watch` subcommand:**
   ```rust
   // Watch for file changes, debounce 500ms, scan only changed files
   let (tx, rx) = channel();
   let mut watcher = notify::recommended_watcher(tx)?;
   watcher.watch(path, RecursiveMode::Recursive)?;
   
   for event in rx {
       match event {
           Ok(event) if event.kind.is_modify() || event.kind.is_create() => {
               let changed_files: Vec<PathBuf> = event.paths;
               // Filter to supported extensions
               // Run scan on changed_files only
               // Print results to terminal (clear + reprint)
           }
           _ => {}
       }
   }
   ```

3. **Debouncing** — batch changes within a 500ms window to avoid scanning per-keystroke

4. **Terminal UI** — use `crossterm` for a persistent status bar:
   ```
   🛡️ AIShield watching... (23 files scanned, 3 findings)
   Last scan: 0.1s ago | Press q to quit
   ```

5. **VS Code integration** — send file change events from the VS Code extension to trigger rescans via a local socket/pipe

**Estimated effort:** 2 weeks  
**Dependencies:** `notify`, `crossterm` crates  
**Key files:** `crates/aishield-cli/src/commands/watch.rs`

---

### 5.5 — PR Comment Bot (GitHub App)

**Goal:** Post inline review comments on PRs when CI configs change.

**Steps:**

1. **Create a GitHub App** at github.com/settings/apps:
   - Permissions: `pull_requests: write`, `checks: write`, `contents: read`
   - Subscribe to: `pull_request` webhook events
   - Generate private key for JWT auth

2. **Build a lightweight webhook server** (or use GitHub Actions):
   
   **Option A — GitHub Action (simpler):**
   ```yaml
   # .github/workflows/aishield-pr.yml
   - name: Run AIShield
     run: aishield scan . --format json > results.json
   
   - name: Post PR comments
     uses: mackeh/aishield-pr-action@v1
     with:
       results: results.json
       github-token: ${{ secrets.GITHUB_TOKEN }}
   ```

   **Option B — Standalone GitHub App (richer):**
   - Small Node.js/Deno service using Probot framework
   - On `pull_request.opened` / `synchronize`:
     - Checkout PR branch
     - Run `aishield scan --format json`
     - Parse findings, map to file/line
     - Post review comments via `POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews`

3. **Comment format:**
   ```markdown
   ⚠️ **AIShield: Timing-unsafe token comparison** (HIGH | AI Confidence: 89%)
   
   **Rule:** AISHIELD-PY-AUTH-002
   **Fix:** Use `secrets.compare_digest()` for constant-time comparison
   
   ```python
   # Before (insecure)
   if user_token == valid_token:
   
   # After (secure)
   if secrets.compare_digest(user_token, valid_token):
   ```
   ```

4. **Summary comment** at the top of the review:
   ```
   🛡️ AIShield found 3 issues (1 critical, 2 high) | AI-generated: 2 of 3 (67%)
   ```

5. **Publish GitHub Action** to GitHub Marketplace

**Estimated effort:** 3–4 weeks  
**Dependencies:** GitHub API, Probot (if standalone)  
**Key files:** `integrations/github-action/`, `integrations/github-app/`

---

### 5.6 — Online Playground (WASM)

**Goal:** Browser-based scanner for zero-install demos.

**Steps:**

1. **Compile core scanner to WASM:**
   - Add `wasm32-unknown-unknown` target
   - Create `crates/aishield-wasm` crate that exposes a `scan(code: &str, language: &str) -> String` function
   - Use `wasm-bindgen` for JS interop:
     ```rust
     #[wasm_bindgen]
     pub fn scan_snippet(code: &str, language: &str) -> String {
         let findings = aishield_core::scan_string(code, language);
         serde_json::to_string(&findings).unwrap()
     }
     ```
   - Build: `wasm-pack build --target web crates/aishield-wasm`

2. **Strip non-WASM-compatible features:**
   - Remove file I/O, process spawning, ONNX runtime
   - Use regex-based scanning only (no SAST bridge)
   - Feature-gate with `#[cfg(not(target_arch = "wasm32"))]`

3. **Build frontend:**
   - Simple React/Svelte SPA with:
     - Code editor (Monaco or CodeMirror)
     - Language selector dropdown
     - "Scan" button
     - Results panel with severity badges, AI confidence, and fix suggestions
   - Load WASM module on page load
   - All processing client-side — no backend needed

4. **Host on GitHub Pages** or Vercel:
   - URL: `https://mackeh.github.io/aishield-playground/`
   - Add link to main README

5. **Shareable results** — encode findings in URL hash for link sharing

**Estimated effort:** 3–4 weeks  
**Dependencies:** `wasm-bindgen`, `wasm-pack`, frontend framework  
**Key files:** `crates/aishield-wasm/`, `playground/`

---

### 5.7 — Dashboard Enhancements (Team/Org Views)

**Goal:** Multi-repo aggregated security dashboards.

**Steps:**

1. **Extend analytics database schema:**
   ```sql
   ALTER TABLE scans ADD COLUMN repo_name TEXT;
   ALTER TABLE scans ADD COLUMN team_name TEXT;
   CREATE TABLE repos (
       id SERIAL PRIMARY KEY,
       name TEXT UNIQUE NOT NULL,
       team TEXT,
       last_scan_at TIMESTAMP
   );
   ```

2. **Aggregate API endpoints:**
   ```
   GET /api/v1/dashboard/org?days=30
   GET /api/v1/dashboard/team/{team}?days=30
   GET /api/v1/dashboard/repo/{repo}/compare?from=scan1&to=scan2
   ```

3. **Dashboard views:**
   - **Org overview**: Heatmap of repos by severity, total findings trend, top recurring rules
   - **Team view**: Per-team breakdown with developer AI-code metrics
   - **Scan comparison**: Side-by-side diff showing new/fixed/unchanged findings between two scans
   - **Export**: PDF and CSV download buttons

4. **Frontend implementation** — extend existing dashboard (likely React/Vue) with new route views and chart components (use recharts or Chart.js)

**Estimated effort:** 3–4 weeks  
**Dependencies:** Analytics API, PostgreSQL/TimescaleDB  
**Key files:** `dashboard/src/views/`, `crates/aishield-api/src/routes/`

---

## Phase 6: Advanced Security & Woo Factor

### 6.1 — Prompt Injection Detection

**Goal:** Detect code patterns vulnerable to LLM prompt injection.

**Steps:**

1. **Research and catalogue patterns:**
   - Unsanitised user input concatenated into LLM prompts
   - Missing output validation from LLM responses
   - System prompts exposed in client-side code
   - Direct `f-string` / template literal injection into API calls

2. **Write detection rules** (YAML format, matching existing rule structure):
   ```yaml
   # rules/python/llm/prompt-injection.yaml
   - id: AISHIELD-PY-LLM-001
     name: Unsanitized user input in LLM prompt
     severity: critical
     ai_confidence_boost: 15
     languages: [python]
     patterns:
       - pattern: 'openai\..*\.create\(.*\bf["\'].*\{.*user.*\}'
       - pattern: 'anthropic\..*\.create\(.*\bf["\'].*\{.*input.*\}'
       - pattern: 'prompt\s*=\s*f["\'].*\{.*request\.'
     message: "User input is interpolated directly into an LLM prompt without sanitisation"
     fix: "Sanitise user input and use a structured prompt template with input validation"
     references:
       - https://owasp.org/www-project-top-10-for-large-language-model-applications/
   ```

3. **Cover multiple languages:** Python (openai, anthropic, langchain), JavaScript (openai, @anthropic-ai/sdk), Go, Java, C#

4. **Target ~15–20 rules** across:
   - Prompt injection via string concatenation
   - Missing output parsing/validation
   - Exposed system prompts
   - Unscoped tool/function calling
   - Excessive token limits without guards

5. **Add test fixtures** for each rule in `tests/fixtures/llm/`

6. **Update documentation** with LLM security scanning guide

**Estimated effort:** 2–3 weeks  
**Dependencies:** None (pure rule additions)  
**Key files:** `rules/python/llm/`, `rules/javascript/llm/`, `tests/fixtures/llm/`

---

### 6.2 — Supply Chain / Dependency Awareness

**Goal:** Flag AI-suggested imports against vulnerability databases.

**Steps:**

1. **Parse dependency files:**
   - `requirements.txt`, `Pipfile`, `pyproject.toml` (Python)
   - `package.json`, `package-lock.json`, `yarn.lock` (JS)
   - `go.mod`, `go.sum` (Go)
   - `Cargo.toml`, `Cargo.lock` (Rust)
   - `pom.xml`, `build.gradle` (Java)

2. **Query vulnerability databases:**
   - OSV API (`https://api.osv.dev/v1/query`) — free, no auth required
   - GitHub Advisory Database (via GraphQL API)
   - NVD (optional, requires API key)

3. **Implement as a new scanner module:**
   ```rust
   pub struct DependencyScanner {
       osv_client: OsvClient,
   }
   
   impl DependencyScanner {
       pub async fn scan(&self, lockfile: &Path) -> Vec<Finding> {
           let deps = parse_lockfile(lockfile);
           let mut findings = vec![];
           for dep in deps {
               let vulns = self.osv_client.query(&dep.name, &dep.version).await;
               for vuln in vulns {
                   findings.push(Finding {
                       rule: format!("AISHIELD-DEP-{}", vuln.severity),
                       message: format!("{} {} has known vulnerability: {}", dep.name, dep.version, vuln.id),
                       severity: vuln.severity.into(),
                       fix: format!("Upgrade to {}", vuln.fixed_version.unwrap_or("latest".into())),
                       ..
                   });
               }
           }
           findings
       }
   }
   ```

4. **Enable via flag:** `aishield scan . --deps` or config:
   ```toml
   [scan]
   check_dependencies = true
   ```

5. **Offline mode** — cache vulnerability data locally, update with `aishield deps update`

**Estimated effort:** 3–4 weeks  
**Dependencies:** `reqwest` (HTTP client), OSV API  
**Key files:** `crates/aishield-deps/`, `crates/aishield-cli/src/commands/deps.rs`

---

### 6.3 — Secrets Detection Expansion

**Goal:** Catch leaked tokens, keys, and credentials beyond hardcoded API keys.

**Steps:**

1. **Expand regex pattern library** for:
   - AWS access keys (`AKIA[0-9A-Z]{16}`)
   - AWS secret keys (40-char base64 near `aws_secret`)
   - GCP service account JSON (`"type": "service_account"`)
   - Azure connection strings (`DefaultEndpointsProtocol=`)
   - JWT tokens (`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+`)
   - Private keys (`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)
   - GitHub PATs (`ghp_[A-Za-z0-9]{36}`, `github_pat_`)
   - Slack tokens (`xox[bpras]-`)
   - Generic high-entropy strings near sensitive variable names

2. **Entropy analysis** for generic secret detection:
   ```rust
   fn shannon_entropy(s: &str) -> f64 {
       let mut freq = [0u32; 256];
       for b in s.bytes() { freq[b as usize] += 1; }
       let len = s.len() as f64;
       freq.iter()
           .filter(|&&c| c > 0)
           .map(|&c| { let p = c as f64 / len; -p * p.log2() })
           .sum()
   }
   // Flag strings with entropy > 4.5 near sensitive context
   ```

3. **`.env` file scanning** — detect committed `.env`, `.env.local`, `.env.production` files

4. **`.aishield-ignore` integration** — allow suppressing known-false-positive secrets

5. **Target ~25–30 patterns** across cloud providers, SaaS tokens, and generic credentials

**Estimated effort:** 2 weeks  
**Dependencies:** None  
**Key files:** `rules/secrets/`, `crates/aishield-core/src/entropy.rs`

---

### 6.4 — Lightweight Taint Analysis

**Goal:** Intra-function data flow tracking from user input to dangerous sinks.

**Steps:**

1. **Integrate `tree-sitter`** for AST parsing:
   ```
   cargo add tree-sitter tree-sitter-python tree-sitter-javascript tree-sitter-go
   ```

2. **Define sources and sinks:**
   ```rust
   struct TaintConfig {
       sources: Vec<Pattern>,  // request.args, request.form, sys.argv, os.environ
       sinks: Vec<Pattern>,    // db.execute, os.system, subprocess.run, eval
       sanitizers: Vec<Pattern>, // parameterize(), escape(), sanitize()
   }
   ```

3. **Implement intra-function analysis:**
   - Parse function body into AST
   - Track variable assignments from sources
   - Follow assignments through local variables (single function scope)
   - Flag when a tainted variable reaches a sink without passing through a sanitiser

4. **Start with Python and JavaScript** — most common AI-generated code languages

5. **Enable via flag:** `aishield scan . --taint`
   - Separate flag because it's slower than regex scanning
   - Document performance impact

6. **Scope limitations clearly** — single function only, no inter-procedural, no field sensitivity

**Estimated effort:** 4–6 weeks  
**Dependencies:** `tree-sitter` and language grammars  
**Key files:** `crates/aishield-taint/`, `crates/aishield-taint/src/config/`

---

### 6.5 — SBOM Generation

**Goal:** Generate Software Bill of Materials tied to scan results.

**Steps:**

1. **Parse dependency manifests** (reuse from 6.2)

2. **Generate SPDX 2.3 JSON:**
   ```json
   {
     "spdxVersion": "SPDX-2.3",
     "name": "aishield-scan-sbom",
     "packages": [
       {
         "name": "express",
         "versionInfo": "4.18.2",
         "externalRefs": [{
           "referenceType": "purl",
           "referenceLocator": "pkg:npm/express@4.18.2"
         }]
       }
     ]
   }
   ```

3. **Generate CycloneDX 1.5 JSON** as alternative format

4. **Link findings to SBOM components** — each finding references the SBOM package that contains the vulnerability

5. **CLI command:** `aishield sbom . --format spdx > sbom.json`

6. **Integrate into CI templates** — generate SBOM alongside scan results

**Estimated effort:** 2 weeks  
**Dependencies:** Dependency parsing from 6.2  
**Key files:** `crates/aishield-sbom/`

---

### 6.6 — Signed Scan Reports

**Goal:** Cryptographically signed output for tamper-proof audit trails.

**Steps:**

1. **Generate signing keypair:**
   ```
   aishield keys generate  # Creates ~/.aishield/signing-key.pem
   ```

2. **Sign scan output:**
   - After generating JSON/SARIF, compute SHA-256 hash of the output
   - Sign the hash with Ed25519 private key
   - Embed signature in output metadata:
     ```json
     {
       "scan_results": { ... },
       "_signature": {
         "algorithm": "ed25519",
         "public_key": "...",
         "signature": "...",
         "timestamp": "2026-03-15T10:30:00Z"
       }
     }
     ```

3. **Verify signed reports:**
   ```
   aishield verify aishield-report.json --key public-key.pem
   ✅ Report signature valid. Scan performed at 2026-03-15T10:30:00Z
   ```

4. **Use `ed25519-dalek` crate** for signing

**Estimated effort:** 1–2 weeks  
**Dependencies:** `ed25519-dalek`  
**Key files:** `crates/aishield-cli/src/commands/keys.rs`, `crates/aishield-core/src/signing.rs`

---

### 6.7 — AI Vulnerability Score Badge

**Goal:** Embeddable shields.io badge for READMEs.

**Steps:**

1. **Generate score** from scan results:
   ```
   Score = 100 - (critical * 25 + high * 10 + medium * 3 + low * 1)
   Grade: A+ (95-100), A (85-94), B (70-84), C (50-69), D (25-49), F (0-24)
   ```

2. **CLI output:**
   ```
   aishield scan . --badge
   # Outputs: ![AIShield Score](https://img.shields.io/badge/AIShield-A%2B%20(97)-brightgreen)
   ```

3. **Badge endpoint** (if dashboard is deployed):
   ```
   GET /api/v1/badge/{repo}
   → Redirects to shields.io with dynamic score
   ```

4. **Static badge** for projects without a dashboard — generate markdown snippet after each scan

**Estimated effort:** 1 week  
**Dependencies:** None (shields.io is external)  
**Key files:** `crates/aishield-cli/src/commands/badge.rs`

---

### 6.8 — "Vibe Check" Mode

**Goal:** Fun, shareable scan output with personality.

**Steps:**

1. **Add `--vibe` flag** to scan command

2. **Implement personality engine:**
   ```rust
   fn vibe_message(findings: &ScanResults) -> String {
       match (findings.critical, findings.high, findings.ai_generated_pct) {
           (0, 0, _) => "✨ Your code is immaculate. Did a human even write this?",
           (0, h, _) if h <= 3 => "Not bad! A few rough edges, but you're clearly not copy-pasting from ChatGPT blindly.",
           (c, h, ai) if c > 3 && ai > 50 => "🚨 Yikes. Your auth module looks like it was written by GPT-3.5 at 2am. {} critical issues, {}% likely AI-generated.",
           _ => // ... more personalities
       }
   }
   ```

3. **Coloured terminal output** with emoji, ASCII art header, and a "shareable screenshot" summary box

4. **Include a "share this scan" one-liner** that formats the output for Twitter/LinkedIn

**Estimated effort:** 1 week  
**Dependencies:** None  
**Key files:** `crates/aishield-cli/src/output/vibe.rs`

---

### 6.9 — VS Code AI Radar Heatmap

**Goal:** Gutter overlay showing AI-generated risk per line.

**Steps:**

1. **Extend VS Code extension** (`integrations/vscode-extension/`):
   - Add new "AI Radar" view mode toggle
   - Run `aishield scan --format json` on the current file
   - Parse per-line AI confidence from results

2. **Gutter decoration:**
   ```typescript
   const decorationType = vscode.window.createTextEditorDecorationType({
       gutterIconPath: getHeatmapIcon(confidence), // green/yellow/orange/red
       gutterIconSize: 'contain',
       overviewRulerColor: confidenceToColor(confidence),
   });
   ```

3. **Hover cards** — show AI confidence percentage, matching rule, and fix suggestion on hover

4. **Performance** — cache results and only re-scan on file save (not keystroke)

**Estimated effort:** 2–3 weeks  
**Dependencies:** VS Code Extension API, existing extension codebase  
**Key files:** `integrations/vscode-extension/src/aiRadar.ts`

---

### 6.10 — LLM-Powered Auto-Fix Loop

**Goal:** One-click fix that rewrites vulnerable code and re-scans.

**Steps:**

1. **Design the fix loop:**
   ```
   Finding detected → Extract code context → Send to LLM → Receive fix → Apply fix → Re-scan → Verify clean
   ```

2. **LLM integration** (configurable provider):
   ```toml
   # .aishield.toml
   [autofix]
   provider = "anthropic"  # or "openai", "local"
   model = "claude-sonnet-4-20250514"
   api_key_env = "ANTHROPIC_API_KEY"
   ```

3. **Prompt template:**
   ```
   The following code has a security vulnerability:
   
   File: {file_path}:{line}
   Rule: {rule_id} - {rule_name}
   Severity: {severity}
   
   Vulnerable code:
   ```{language}
   {code_context}
   ```
   
   Fix suggestion: {fix_description}
   
   Please provide ONLY the corrected code that fixes this vulnerability while preserving functionality.
   ```

4. **Apply and verify:**
   - Write fixed code to a temp file
   - Re-scan the temp file with the same rule
   - If finding is gone → offer to apply (interactive mode) or auto-apply (`--write`)
   - If finding persists → retry once with different prompt, then report failure

5. **CLI:** `aishield fix . --autofix --interactive`

6. **VS Code integration** — "Fix with AI" code action on each diagnostic

**Estimated effort:** 3–4 weeks  
**Dependencies:** LLM API client (`reqwest`), user API key  
**Key files:** `crates/aishield-autofix/`, `integrations/vscode-extension/src/autofix.ts`

---

### 6.11 — Browser Extension (WASM)

**Goal:** Highlight vulnerable patterns on GitHub/GitLab/StackOverflow as you browse.

**Steps:**

1. **Reuse WASM scanner** from 5.6 (playground)

2. **Build Chrome/Firefox extension:**
   - Content script that detects code blocks on supported sites
   - Extract code text and language from DOM:
     - GitHub: `.blob-code-inner`, language from file extension
     - GitLab: `.code .line`, language from breadcrumb
     - StackOverflow: `<code>` blocks with language class
   - Run WASM scanner on extracted code
   - Inject inline annotations (coloured underlines, hover tooltips)

3. **Manifest V3 (Chrome):**
   ```json
   {
     "manifest_version": 3,
     "name": "AIShield Scanner",
     "permissions": ["activeTab"],
     "content_scripts": [{
       "matches": ["*://github.com/*", "*://gitlab.com/*", "*://stackoverflow.com/*"],
       "js": ["content.js"]
     }]
   }
   ```

4. **Performance** — only scan visible code blocks, debounce on scroll, cache results per URL

5. **Popup UI** — summary of findings on current page with severity breakdown

6. **Publish** to Chrome Web Store and Firefox Add-ons

**Estimated effort:** 4–5 weeks  
**Dependencies:** WASM build from 5.6, browser extension APIs  
**Key files:** `browser-extension/`

---

## Long-Term Vision

### AST-Based Analysis (tree-sitter)

- Extend taint analysis (6.4) to full cross-function and cross-file analysis
- Replace regex patterns with tree-sitter queries for higher accuracy
- Support pattern matching on AST node types rather than string patterns
- **Effort:** 8–12 weeks (major refactor)

### Language Server Protocol (LSP)

- Single LSP server powering VS Code, JetBrains, Neovim, Emacs
- Provides diagnostics, code actions, hover info from one implementation
- Eliminates per-editor duplication
- **Effort:** 6–8 weeks

### AIShield Cloud (SaaS)

- Multi-tenant API with org/team/user hierarchy
- Centralised policy enforcement
- SSO (SAML/OIDC)
- Hosted dashboards with historical analytics
- **Effort:** 3–6 months (separate project)

---

## Infrastructure & DevOps Requirements

| Component | Technology | Purpose |
|-----------|-----------|---------|
| CI/CD | GitHub Actions | Build, test, release, cross-compile |
| Cross-compilation | `cross` | Multi-platform binary builds |
| WASM | `wasm-pack`, `wasm-bindgen` | Playground and browser extension |
| Package registries | crates.io, npm, Homebrew | Distribution |
| Dashboard hosting | Vercel / GitHub Pages | Playground, docs |
| LLM API | Anthropic / OpenAI | Auto-fix feature |
| Vulnerability DB | OSV API | Dependency scanning |

---

## Dependency Map

```
Phase 5.1 (Distribution) ──→ Phase 5.6 (Playground uses WASM build)
                          ──→ Phase 6.11 (Browser ext uses WASM build)

Phase 5.2 (Init wizard) ──→ Phase 5.3 (Profiles used in wizard)

Phase 5.5 (PR Bot) ──→ Phase 6.7 (Badge in PR comments)

Phase 6.2 (Dependency scan) ──→ Phase 6.5 (SBOM reuses dep parsing)

Phase 6.4 (Taint analysis) ──→ Long-term AST refactor

Phase 5.6 (WASM build) ──→ Phase 6.11 (Browser extension)
```

All other items are independent and can be built in parallel.

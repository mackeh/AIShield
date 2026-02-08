---
layout: home

title: AIShield Documentation

hero:
  name: AIShield
  text: AI-Generated Code Security Validator
  tagline: Catch insecure AI-assisted code before it ships.
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started
    - theme: alt
      text: CLI Reference
      link: /cli
    - theme: alt
      text: View on GitHub
      link: https://github.com/mackeh/AIShield

features:
  - title: AI-focused security rules
    details: Built-in detections target vulnerabilities often introduced by AI-generated code across Python, JavaScript, Go, Rust, Java, C#, Ruby, PHP, Kotlin, and Swift.
  - title: CI-ready outputs
    details: Emit JSON, SARIF, and GitHub annotation output with normalized dedup to reduce noisy duplicate findings in pipelines.
  - title: Practical remediation
    details: Use `aishield fix` in write, dry-run, or interactive TUI mode with search/filter, severity badges, and preview diff panes.
  - title: Multi-engine bridge
    details: Optionally enrich findings with Semgrep, Bandit, and ESLint while preserving a unified result model.
  - title: AI classifier modes
    details: Run default heuristic scoring or ONNX model scoring (`--ai-model onnx`) with runtime fallback safety.
  - title: Contributor-ready workflows
    details: Includes onboarding docs, issue/PR templates, VS Code extension bootstrap, VS Code tasks, and CI examples for GitHub Actions and GitLab CI.
  - title: Dashboard + analytics bootstrap
    details: Local web dashboard with trend KPIs, top-rule/target hotspots, and report ingestion for artifact-based CI pipelines.
---

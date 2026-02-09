# Known Architectural Deviations from Specification

This document outlines intentional deviations from the [project.md](./project.md) architecture specification.

## 1. Pattern Matching Strategy

**Spec** (project.md line 109):

> Structural Pattern Matching — AST queries for known insecure code shapes (tree-sitter based for speed and multi-language support)

**Reality**: Regex and string-based pattern matching

**Rationale**:

- Sufficient for AI vulnerability detection (most patterns are syntactic, not semantic)
- Faster implementation (no AST overhead)
- Multi-language without grammar maintenance burden
- Sub-2-second performance achieved
- False positive control via negative patterns

**Trade-offs**:

- Less precise than AST for complex nested patterns
- Cannot perform deep dataflow analysis
- Simpler implementation and maintenance

**Future Enhancement**: Consider tree-sitter for dataflow taint tracking (Phase 3+)

---

## 2. Analytics Infrastructure

**Spec** (project.md line 335):

> Analytics Pipeline: ClickHouse (Column-oriented, perfect for time-series vuln analytics)

**Reality**: PostgreSQL with TimescaleDB extensions

**Current Implementation**:

- `aishield-analytics` Axum service
- PostgreSQL schema with `scans` and `findings` tables
- Ingestion API for CI/CD artifacts
- Support for org, team, and repo-level rollups

**Rationale**:

- PostgreSQL is more accessible for self-hosting than ClickHouse
- TimescaleDB provides excellent time-series performance for vulnerability trends
- Relational model is better suited for org/team/user metadata management
- Unified tech stack (SQLx) across the workspace

**Phase Alignment**:

- Phase 3 Milestone: **Achieved** (Weeks 13-20)

---

## 3. SAST Bridge Auto-Detection

**Spec** (project.md line 145):

> Auto-detects which engines are available and installs missing ones

**Reality**: Manual configuration via `--bridge semgrep,bandit,eslint|all`

**Current Behavior**:

- User explicitly enables bridge engines
- Graceful degradation with warnings if tool not found
- No automatic installation

**Rationale**:

- Avoids security concerns (unexpected package installation)
- Explicit user control over external tools
- Simpler implementation

---

## Status Summary

| Component        | Spec            | Current              | Impact                      |
| ---------------- | --------------- | -------------------- | --------------------------- |
| Pattern Matching | tree-sitter AST | Regex/string         | Low - functionally adequate |
| Analytics        | ClickHouse      | Postgres+TimescaleDB | Resolved                    |
| SAST Auto-detect | Automatic       | Manual               | Low - minor UX issue        |

**Overall Assessment**: The platform has reached architectural maturity suitable for enterprise adoption. The choice of PostgreSQL/TimescaleDB over ClickHouse is a pragmatic improvement for most deployment scenarios.
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

**Reality**: File-based analytics via `.aishield-history.log`

**Current Implementation**:

- Newline-delimited JSON log file
- Node.js dashboard reads file for analytics
- Adequate for single-user, single-repo scenarios

**Limitations**:

- Cannot aggregate across multiple repositories
- Linear scan performance O(n)
- No concurrent multi-user support
- Blocks enterprise features:
  - Org-wide vulnerability heatmaps
  - Team leaderboards
  - AI tool comparison analytics
  - Compliance report generation

**Phase Alignment**:

- Current: Phase 1 level (local-only analytics)
- Spec requirement: Phase 3 (Weeks 13-20)

**Migration Path** (for Team/Enterprise tiers):

- Evaluate ClickHouse vs alternatives (PostgreSQL+TimescaleDB, InfluxDB)
- Implement ingestion API for CI/CD artifacts
- Design org-level rollup queries

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

**Future Enhancement**: Add auto-detection with explicit user confirmation

---

## Status Summary

| Component        | Spec            | Current      | Impact                            |
| ---------------- | --------------- | ------------ | --------------------------------- |
| Pattern Matching | tree-sitter AST | Regex/string | Low - functionally adequate       |
| Analytics        | ClickHouse      | File-based   | High - blocks enterprise features |
| SAST Auto-detect | Automatic       | Manual       | Low - minor UX issue              |

**Overall Assessment**: Deviations are pragmatic for current scope (Community/Pro tiers). Database migration is critical blocker for Team/Enterprise features.

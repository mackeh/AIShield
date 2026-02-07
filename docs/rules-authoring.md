# AIShield Rule Authoring (Foundation)

AIShield rules are YAML files organized by language and category (for example `rules/python/auth/*.yaml`).

## Required fields

```yaml
id: AISHIELD-PY-AUTH-001
title: Timing-Unsafe Secret Comparison
severity: high
languages: [python]
pattern:
  any:
    - "token == "
```

- `id`: stable unique rule identifier
- `title`: short finding title
- `severity`: `critical|high|medium|low|info`
- `languages`: list (currently `python` and `javascript` scanner support)
- `pattern`: one or more match conditions

## Pattern semantics

```yaml
pattern:
  any:
    - "token === "
    - "apikey === "
  all:
    - "token"
    - "==="
  not:
    - "timingsafeequal("
```

- `pattern.any`: at least one entry must match on a line
- `pattern.all`: all entries must match on the same line
- `pattern.not`: none of these entries may match on that line
- `pattern.contains`: alias of `pattern.any` for compatibility

A rule can use only `all`, only `any`, or both together.

## Optional fields

```yaml
confidence_that_ai_generated: 0.88
category: auth
ai_tendency: AI output often uses simple equality checks for secrets.
negative_patterns:
  - "compare_digest("
fix:
  suggestion: Use hmac.compare_digest for constant-time secret checks.
tags: [auth, timing-attack]
```

- `negative_patterns`: global suppressions checked against line and full file
- `fix.suggestion`: remediation text shown in `aishield fix`
- `tags`: used for filtering (`--rules auth,crypto`)

## Example

```yaml
id: AISHIELD-JS-AUTH-001
title: Timing-Unsafe Token Comparison
severity: high
confidence_that_ai_generated: 0.84
languages: [javascript]
category: auth
pattern:
  any:
    - "token === "
    - "apikey === "
  not:
    - "timingsafeequal("
fix:
  suggestion: Use crypto.timingSafeEqual() for constant-time comparison.
tags: [auth, timing-attack]
```

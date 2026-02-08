# ✍️ Writing Your First Detection Rule

This guide teaches you how to create effective security detection rules for AIShield.

## 🎯 What You'll Learn

- Rule anatomy (required fields, pattern matching)
- Pattern matching strategies (contains, regex, negative patterns)
- AI tendency documentation
- Testing and validation
- Common pitfalls to avoid

**Time Required**: ~45 minutes
**Difficulty**: Beginner to Intermediate

---

## Rule Anatomy

Every AIShield rule is a YAML file with this structure:

```yaml
id: AISHIELD-LANG-CATEGORY-NNN
title: Short descriptive title
severity: [critical|high|medium|low|info]
confidence_that_ai_generated: [0.0-1.0]
languages: [language1, language2]
category: [auth|crypto|injection|misconfig]
ai_tendency: Why do AI tools generate this pattern?
pattern:
  contains: # Or: regex, starts_with, ends_with, any, all
    - "pattern to match"
negative_patterns:
  - "exclude false positives"
fix:
  suggestion: How to remediate this vulnerability
tags: [tag1, tag2]
cwe: CWE-XXX # Optional
owasp: A01:2021 # Optional
```

---

## Step-by-Step: Creating a Rule from Scratch

### Scenario

Let's create a rule to detect timing-unsafe password comparison in Go.

**Vulnerable pattern**:

```go
if password == userPassword {  // Timing attack!
    // grant access
}
```

---

### Step 1: Choose an ID

Format: `AISHIELD-<LANG>-<CATEGORY>-<NUMBER>`

```yaml
id: AISHIELD-GO-AUTH-005
```

**Rules**:

- Use language code: PY, JS, GO, RUST, JAVA, CS, RB, PHP, KT, SWIFT
- Category: AUTH, CRYPTO, INJECT, MISCONFIG
- Number: Check existing rules, increment highest

---

### Step 2: Write Title and Severity

```yaml
title: Timing-unsafe password comparison
severity: high
```

**Severity guidelines**:

- **critical**: Remote code execution, SQL injection, auth bypass
- **high**: Crypto weaknesses, timing attacks, SSRF
- **medium**: Information disclosure, weak validations
- **low**: Minor issues, best practice violations
- **info**: Code smells, potential improvements

---

### Step 3: Set AI Confidence

```yaml
confidence_that_ai_generated: 0.82
```

**How to estimate**:

- 0.9+: Very common in AI autocomplete (e.g., `md5`, `eval()`)
- 0.7-0.9: Frequently suggested (e.g., timing attacks, weak crypto)
- 0.5-0.7: Sometimes suggested (edge cases)
- <0.5: Rare in AI output (human errors)

**Tip**: Check GPT/Copilot suggestions for this pattern to calibrate.

---

### Step 4: Specify Languages and Category

```yaml
languages: [go]
category: auth
```

**Categories**:

- `auth`: Authentication/authorization issues
- `crypto`: Cryptography misuse
- `injection`: SQL/Command/Code injection
- `misconfig`: Configuration issues

---

### Step 5: Document AI Tendency

```yaml
ai_tendency: LLMs autocomplete password checks with == instead of constant-time comparison, creating timing attack vulnerabilities.
```

**Why this matters**: Helps users understand _why_ AI generates this pattern.

**Good AI tendency notes**:

- "LLMs copy this pattern from StackOverflow examples"
- "Autocomplete suggests outdated crypto from training data"
- "AI tools miss the security context of this API"

---

### Step 6: Write Pattern Matching Rules

#### Option A: Simple Contains

```yaml
pattern:
  contains:
    - "== password"
    - "== userPassword"
```

**Use when**: Exact substring matching works

#### Option B: Regex

```yaml
pattern:
  regex: 'if\s+\w+\s*==\s*password'
```

**Use when**: Need flexibility (whitespace, variable names)

#### Option C: Complex Logic

```yaml
pattern:
  all: # ALL must match
    - contains: ["password"]
    - contains: ["=="]
  any: # At least ONE must match
    - starts_with: "if"
    - starts_with: "while"
  not: # Must NOT match
    - contains: ["subtle.ConstantTimeCompare"]
```

**Use when**: Complex detection logic needed

---

### Step 7: Add Negative Patterns

Suppress false positives:

```yaml
negative_patterns:
  - "subtle.ConstantTimeCompare" # Correct implementation
  - "crypto/subtle" # Using safe library
  - "bcrypt.CompareHashAndPassword"
  - "# timing-safe" # User acknowledged
```

**Common false positive suppressions**:

- Safe library usage
- Non-security contexts (`"test"`, `"example"`)
- User annotations (`"# safe"`, `"# noqa"`)

---

### Step 8: Provide Fix Guidance

```yaml
fix:
  suggestion: Use subtle.ConstantTimeCompare() for timing-safe comparison
```

**Good fix suggestions**:

- Specific API/function names
- Code example if simple
- Link to documentation for complex fixes

**Examples**:

```yaml
fix:
  suggestion: "Use crypto/subtle.ConstantTimeCompare(). Example: if subtle.ConstantTimeCompare([]byte(password), []byte(userPassword)) == 1 { /* authenticated */ }"
```

---

### Step 9: Add Tags and CWE

```yaml
tags: [auth, timing-attack, owasp-top10]
cwe: CWE-208 # Observable Timing Discrepancy
owasp: A07:2021 # Identification and Authentication Failures
```

**Useful tags**:

- Category-specific: `auth`, `crypto`, `injection`, `misconfig`
- Framework: `django`, `flask`, `express`, `spring`
- Risk: `owasp-top10`, `sans-top25`, `pci-dss`

**Find CWE**: https://cwe.mitre.org/
**Find OWASP**: https://owasp.org/Top10/

---

### Step 10: Complete Rule

```yaml
id: AISHIELD-GO-AUTH-005
title: Timing-unsafe password comparison
severity: high
confidence_that_ai_generated: 0.82
languages: [go]
category: auth
ai_tendency: LLMs autocomplete password checks with == instead of constant-time comparison, creating timing attack vulnerabilities.
pattern:
  all:
    - contains: ["password"]
    - contains: ["=="]
negative_patterns:
  - "subtle.ConstantTimeCompare"
  - "bcrypt.CompareHashAndPassword"
  - "crypto/subtle"
fix:
  suggestion: Use subtle.ConstantTimeCompare() for constant-time comparison
tags: [auth, timing-attack, owasp-top10]
cwe: CWE-208
owasp: A07:2021
```

**Save to**: `rules/go/auth/timing-unsafe-password-compare.yaml`

---

## Testing Your Rule

### 1. Create Test Fixtures

```bash
# Create: tests/fixtures/go-timing-attack.go
```

```go
package main

// VULNERABLE: Should be detected
func authenticate(password, userPassword string) bool {
    if password == userPassword {  // ❌ Timing attack
        return true
    }
    return false
}

// SAFE: Should NOT be detected (negative pattern)
func authenticateSafe(password, userPassword string) bool {
    if subtle.ConstantTimeCompare([]byte(password), []byte(userPassword)) == 1 {
        return true
    }
    return false
}
```

### 2. Run Detection

```bash
cargo run -p aishield-cli -- scan tests/fixtures/go-timing-attack.go
```

**Expected**:

```
[HIGH] Timing-unsafe password comparison
  File: tests/fixtures/go-timing-attack.go:5
  Rule: AISHIELD-GO-AUTH-005
```

**Should NOT detect**: Line 12 (uses `subtle.ConstantTimeCompare`)

### 3. Test Edge Cases

Try variations:

```go
// Different spacing
if password==userPassword { }

// Different variable names
if pwd == stored_password { }

// Should NOT detect (false positive test)
comment := "password == secret"  // Just a comment
```

---

## Pattern Matching Best Practices

### ✅ DO

- **Be specific enough** to avoid false positives
- **Use negative patterns** generously
- **Test with real code** from GitHub
- **Document AI tendency** with specific examples
- **Keep patterns simple** (regex as last resort)

### ❌ DON'T

- **Overfit** to one specific example
- **Use overly broad patterns** (`contains: ["password"]` alone is too broad)
- **Forget negative patterns** for safe alternatives
- **Skip testing** edge cases
- **Use complex regex** if simple `contains` works

---

## Common Pitfalls

### Pitfall 1: Too Broad

```yaml
# BAD: Matches everything
pattern:
  contains: ["password"]
```

```yaml
# GOOD: More specific context
pattern:
  all:
    - contains: ["password"]
    - contains: ["=="]
```

### Pitfall 2: Missing Negative Patterns

Without negative patterns, you'll flag safe code:

```python
# This is SAFE but would be flagged without negative patterns:
if bcrypt.checkpw(password, hashed):  # Uses bcrypt (safe)
    login()
```

**Solution**: Add `"bcrypt"` to negative patterns.

### Pitfall 3: Language-Specific Syntax

```yaml
# Won't work for other languages:
pattern:
  contains: ["if password == userPassword"] # Too specific to syntax
```

**Solution**: Focus on the core insecure pattern, not syntax details.

### Pitfall 4: Forgetting Comments

```python
sensitive_data = "password123"  # AI-suggested comment might match!
```

**Solution**: Add negative patterns for comments, or use regex to exclude comment lines.

---

## Validating Your Rule

### Checklist

Before submitting:

- [ ] Rule ID follows convention
- [ ] Severity is appropriate
- [ ] AI confidence is calibrated
- [ ] Pattern matches vulnerable code
- [ ] Negative patterns prevent false positives
- [ ] Fix suggestion is actionable
- [ ] Tags and CWE are accurate
- [ ] Tested with fixtures (vulnerable + safe variants)
- [ ] Documented why AI generates this

---

## Gallery: Well-Written Rules

### Example 1: Weak Hash Detection (Python)

```yaml
id: AISHIELD-PY-CRYPTO-001
title: AI-Suggested Weak Hash Algorithm
severity: high
confidence_that_ai_generated: 0.85
languages: [python]
category: crypto
ai_tendency: LLMs frequently suggest md5/sha1 from outdated tutorials and examples.
pattern:
  contains:
    - "hashlib.md5("
    - "hashlib.sha1("
negative_patterns:
  - "checksum"
  - "non-security"
fix:
  suggestion: Use sha256 for integrity checks and bcrypt/argon2id for password hashing.
tags: [crypto, owasp-top10]
```

**Why it's good**: Clear pattern, appropriate negative patterns, specific fix guidance.

### Example 2: SQL Injection (JavaScript)

```yaml
id: AISHIELD-JS-INJECT-002
title: SQL injection via template string
severity: critical
confidence_that_ai_generated: 0.91
languages: [javascript, typescript]
category: injection
ai_tendency: AI autocomplete often suggests template strings for SQL queries without parameterization.
pattern:
  regex: 'query\s*=\s*`SELECT.*?\$\{.*?\}'
negative_patterns:
  - "// sql-safe"
  - "prepared"
fix:
  suggestion: Use parameterized queries with placeholders (e.g., db.query("SELECT * FROM users WHERE id = ?", [userId]))
tags: [injection, sql-injection, owasp-top10]
cwe: CWE-89
```

**Why it's good**: Uses regex for template literal syntax, high AI confidence (very common pattern), critical severity.

---

## Next Steps

1. 📁 **Save your rule** to `rules/<language>/<category>/<name>.yaml`
2. 🧪 **Add fixtures** to `tests/fixtures/`
3. ✅ **Run tests**: `cargo test && cargo run -p aishield-cli -- scan tests/fixtures`
4. 📝 **Update CHANGELOG.md**
5. 🚀 **Submit PR** using the PR template

---

## Resources

- [Rule Template](.github/RULE_TEMPLATE.yaml) - Copy this to start
- [Testing Guide](./testing-guide.md) - Comprehensive testing documentation
- [CWE Database](https://cwe.mitre.org/) - Find CWE numbers
- [OWASP Top 10](https://owasp.org/Top10/) - Security risks reference

---

## Getting Help

Stuck? Ask in:

- 💬 [GitHub Discussions](https://github.com/mackeh/AIShield/discussions)
- 🐛 [Issue Tracker](https://github.com/mackeh/AIShield/issues)

Happy rule writing! 🎉

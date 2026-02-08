# 🌟 Your First Contribution to AIShield

Welcome! This guide will walk you through making your first contribution to AIShield. We're excited to have you here!

## 🎯 Before You Start

**Time Required**: ~30-60 minutes for your first contribution
**Difficulty**: Beginner-friendly

**What You'll Learn**:

- How to set up the development environment
- How to find a good issue to work on
- How to make changes and test them
- How to submit a pull request

---

## Step 1: Set Up Your Development Environment

### Prerequisites

Make sure you have:

- ✅ Rust 1.75+ (`rustc --version`)
- ✅ Git (`git --version`)
- ✅ Node.js 20+ (`node --version`) - for docs

### Fork and Clone

1. **Fork the repository** on GitHub (click "Fork" button)

2. **Clone your fork**:

   ```bash
   git clone https://github.com/YOUR_USERNAME/AIShield.git
   cd AIShield
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/mackeh/AIShield.git
   ```

### Build and Test

```bash
# Build the project
cargo build

# Run tests
cargo test

# Try a scan
cargo run -p aishield-cli -- scan tests/fixtures
```

**Expected**: Build succeeds, tests pass, scan finds ~96 vulnerabilities.

---

## Step 2: Find Something to Work On

### Option A: Good First Issues

Browse [good first issues](https://github.com/mackeh/AIShield/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) for beginner-friendly tasks.

**Recommended for first contribution**:

- 📝 Adding a new detection rule
- 📚 Improving documentation
- 🐛 Fixing a small bug

### Option B: Create Your Own Issue

Found a bug or have an idea? [Open an issue](https://github.com/mackeh/AIShield/issues/new/choose) first to discuss it.

### Option C: Pick From These Ideas

Easy wins:

- Add a rule for a language you know well
- Improve error messages
- Add examples to documentation
- Fix typos or broken links

---

## Step 3: Make Your Changes

### Example: Adding a Detection Rule

Let's add a rule to detect `eval()` usage in Python (common AI suggestion).

1. **Create a new branch**:

   ```bash
   git checkout -b add-python-eval-detection
   ```

2. **Create the rule file**:

   ```bash
   # Create: rules/python/injection/dangerous-eval.yaml
   ```

3. **Write the rule**:

   ```yaml
   id: AISHIELD-PY-INJECT-006
   title: Dangerous eval() usage
   severity: critical
   confidence_that_ai_generated: 0.88
   languages: [python]
   category: injection
   ai_tendency: LLMs frequently suggest eval() for dynamic code execution without security context.
   pattern:
     contains:
       - "eval("
   negative_patterns:
     - "# safe-eval"
     - "ast.literal_eval"
   fix:
     suggestion: Use ast.literal_eval() for safe literal evaluation, or avoid dynamic code execution.
   tags: [injection, owasp-top10, code-injection]
   cwe: CWE-95
   ```

4. **Create a test fixture**:

   ```bash
   # Add to: tests/fixtures/vulnerable.py
   ```

   ```python
   # VULNERABLE: eval() with user input
   user_input = request.GET['calc']
   result = eval(user_input)  # Should be detected
   ```

5. **Test your rule**:

   ```bash
   cargo run -p aishield-cli -- scan tests/fixtures/vulnerable.py
   ```

   **Expected**: Your new rule should detect the `eval()` usage.

---

## Step 4: Test Your Changes

### Run the Test Suite

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_rule_detection
```

### Manual Testing

```bash
# Scan fixtures
cargo run -p aishield-cli -- scan tests/fixtures

# Scan with your new rule
cargo run -p aishield-cli -- scan tests/fixtures --format json | jq '.findings[] | select(.id=="AISHIELD-PY-INJECT-006")'
```

### Check Formatting

```bash
cargo fmt --all --check
```

---

## Step 5: Commit Your Changes

### Write a Good Commit Message

Follow this format:

```
<type>(<scope>): <short description>

<longer description if needed>

Fixes #123
```

**Types**: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

**Example**:

```bash
git add rules/python/injection/dangerous-eval.yaml tests/fixtures/vulnerable.py
git commit -m "feat(rules): Add detection for dangerous eval() in Python

Detects use of eval() which is commonly suggested by AI assistants
but introduces code injection vulnerabilities.

Closes #45"
```

### Push to Your Fork

```bash
git push origin add-python-eval-detection
```

---

## Step 6: Submit a Pull Request

1. **Go to GitHub**: Navigate to your fork

2. **Click "Compare & pull request"**

3. **Fill out the PR template**:
   - Clear title: `feat(rules): Add Python eval() detection`
   - Describe what changed and why
   - Check all relevant checklist items
   - Reference the issue: `Closes #45`

4. **Submit!** 🎉

---

## Step 7: Address Review Feedback

Maintainers will review your PR and may request changes.

### Common Review Comments

**"Can you add a test?"**

```bash
# Add fixture demonstrating detection
echo "eval(user_input)" > tests/fixtures/new-test.py
cargo test
```

**"Please update CHANGELOG.md"**

```markdown
## [Unreleased]

### Added

- Python rule for detecting dangerous eval() usage (#45)
```

**"Code needs formatting"**

```bash
cargo fmt --all
git add -u
git commit -m "chore: Apply code formatting"
git push
```

---

## ✅ Congratulations!

You've made your first contribution! 🎉

### What's Next?

- 🌟 **Star the repo** if you haven't already
- 📢 **Share your experience** in Discussions
- 🔄 **Keep contributing**! Try a harder issue next time
- 📚 **Dive deeper**: Read [Writing Your First Rule](./writing-your-first-rule.md)

### Resources

- [CONTRIBUTING.md](../../CONTRIBUTING.md) - Full contributor guide
- [Writing Rules Guide](./writing-your-first-rule.md) - Detailed rule authoring
- [Testing Guide](./testing-guide.md) - Comprehensive testing documentation
- [Architecture Overview](../ARCHITECTURE.md) - Understand the codebase

---

## 🆘 Getting Help

**Stuck?** Here's how to get help:

1. 💬 **GitHub Discussions**: Ask questions in [Discussions](https://github.com/mackeh/AIShield/discussions)
2. 🐛 **Issues**: File an issue if you think something's broken
3. 📖 **Documentation**: Check [docs/](../../docs/) for more guides

---

## 🎨 Other Ways to Contribute

Not ready to write code? You can still help!

- 📚 **Improve documentation** (fix typos, add examples)
- 🐛 **Report bugs** you encounter
- 💡 **Suggest features** in Issues
- 🧪 **Test pre-releases** and provide feedback
- 🌍 **Share AIShield** with others

Every contribution matters! 🙏

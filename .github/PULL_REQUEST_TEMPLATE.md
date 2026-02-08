# Pull Request

## 📋 Description

<!-- Provide a clear and concise description of your changes -->

## 🎯 Motivation and Context

<!-- Why is this change needed? What problem does it solve? -->
<!-- If it fixes an issue, link it here: Fixes #123 -->

## 🔧 Type of Change

<!-- Mark the relevant option with an "x" -->

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📝 Documentation update
- [ ] ♻️ Refactoring (no functional changes)
- [ ] 🎨 Style/UI change
- [ ] ⚡ Performance improvement
- [ ] ✅ Test update
- [ ] 🔧 Configuration change
- [ ] 📦 Dependency update

## 📝 Checklist

<!-- Mark completed items with an "x" -->

### General

- [ ] My code follows the project's code style (`cargo fmt --all`)
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] My changes generate no new warnings

### Testing

- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes (`cargo test`)
- [ ] I have tested my changes manually

### Documentation

- [ ] I have updated the documentation accordingly
- [ ] I have updated `CHANGELOG.md` with my changes
- [ ] I have added/updated code examples if applicable

### Rules (if adding/modifying detection rules)

- [ ] Rule has a unique ID following convention (AISHIELD-LANG-CATEGORY-NNN)
- [ ] Rule includes all required fields (id, title, severity, pattern, fix)
- [ ] Rule includes AI tendency explanation
- [ ] Rule includes negative patterns to prevent false positives
- [ ] I have added vulnerable fixture demonstrating detection
- [ ] I have added safe fixture demonstrating non-detection
- [ ] Rule tags and CWE/OWASP references are accurate

### Breaking Changes

- [ ] I have documented all breaking changes in the PR description
- [ ] I have updated migration guide (if applicable)

## 🧪 How Has This Been Tested?

<!-- Describe the tests you ran to verify your changes -->

**Test Configuration**:

- OS: <!-- e.g., macOS 13, Ubuntu 22.04 -->
- Rust version: <!-- e.g., 1.75.0 -->
- AIShield version: <!-- e.g., 0.2.0 or commit SHA -->

**Test Commands**:

```bash
# Commands you ran to test
cargo test
cargo run -p aishield-cli -- scan tests/fixtures
```

**Test Results**:

<!-- Paste relevant test output or describe results -->

## 📸 Screenshots (if applicable)

<!-- Add screenshots for UI changes or terminal output examples -->

## 🔗 Related Issues

<!-- Link related issues here -->
<!-- Example: Fixes #123, Related to #456 -->

## 📚 Additional Notes

<!-- Any additional information reviewers should know -->

---

## For Reviewers

<!-- Optional: Any specific areas you'd like reviewers to focus on -->

**Review Focus Areas**:

- [ ] Logic correctness
- [ ] Test coverage
- [ ] Performance impact
- [ ] Documentation clarity
- [ ] Breaking change handling

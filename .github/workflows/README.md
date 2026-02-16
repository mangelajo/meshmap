# GitHub Actions Workflows

This directory contains CI/CD workflows for meshmap.

## Workflows

### 🧪 [tests.yml](tests.yml)
**Complete test suite** - Runs on every push and PR

- **Triggers**: Push to main/develop, all PRs, manual dispatch
- **What it does**:
  - **Always runs the full test suite** (all 16+ tests)
  - Tests on Python 3.12 and 3.13
  - Tests on Ubuntu and macOS
  - Runs linting (ruff)
  - Runs type checking (mypy)
  - Generates coverage reports
  - Uploads to Codecov (optional)

**Jobs**:
- `test` - Linux tests with full coverage
- `test-macos` - macOS compatibility tests (full suite)
- `check-formatting` - Code style checks

**Philosophy**: Always run everything. No shortcuts, no quick checks. Every commit gets the full treatment.

## Status Badges

Add these badges to your README.md:

```markdown
![Tests](https://github.com/YOUR_USERNAME/meshmap/actions/workflows/tests.yml/badge.svg)
![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)
![Coverage](https://img.shields.io/codecov/c/github/YOUR_USERNAME/meshmap)
```

## Running Workflows Locally

### Act (GitHub Actions locally)
```bash
# Install act
brew install act  # macOS
# or download from: https://github.com/nektos/act

# Run full test suite
act -j test

# Run macOS tests
act -j test-macos
```

### Manual test run (same as CI)
```bash
# Exactly what CI runs:
uv pip install -e ".[dev]"
uv run pytest tests/ -v --cov=meshmap --cov-report=term
uv run ruff check meshmap/ tests/
uv run mypy meshmap/
```

## Configuration

### Python Versions
Currently testing on:
- Python 3.12 (primary)
- Python 3.13 (compatibility)

To add more versions, edit `matrix.python-version` in [tests.yml](tests.yml).

### Operating Systems
Currently testing on:
- Ubuntu Latest (primary)
- macOS Latest (compatibility)

To add Windows, add `windows-latest` to `matrix.os`.

### Coverage Reporting

Coverage is uploaded to Codecov automatically if you:
1. Create account at https://codecov.io
2. Connect your GitHub repo
3. Add `CODECOV_TOKEN` to GitHub secrets (optional)

Disable by removing the "Upload coverage" step.

## Troubleshooting

### "uv command not found"
The `astral-sh/setup-uv@v5` action installs uv. If it fails:
1. Check you're using the latest action version
2. Try with `uv` installed via pip as fallback

### Tests fail on Python 3.13
Check if dependencies are compatible:
```bash
uv pip install -e ".[dev]" --python 3.13
```

### macOS tests fail
Some dependencies might have macOS-specific issues. Check:
- PyNaCl compilation (needs libsodium)
- Cryptography library (needs OpenSSL)

Add to workflow if needed:
```yaml
- name: Install system dependencies (macOS)
  run: brew install libsodium
```

## Optimization Tips

### Cache Dependencies
Currently enabled via:
```yaml
- uses: astral-sh/setup-uv@v5
  with:
    enable-cache: true
```

### Parallel Jobs
Tests run in parallel by default:
- Multiple Python versions run concurrently
- Linux and macOS jobs run concurrently

### Skip CI
Add to commit message to skip CI:
```
git commit -m "docs: update README [skip ci]"
```

## Security

### Secrets
If tests need secrets (e.g., API keys):
1. Add to GitHub repository secrets
2. Reference in workflow:
   ```yaml
   env:
     SECRET_KEY: ${{ secrets.SECRET_KEY }}
   ```

### Dependabot
Enable Dependabot to keep actions updated:
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

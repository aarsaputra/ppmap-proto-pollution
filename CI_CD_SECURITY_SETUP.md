# CI/CD Security Scanning Setup Guide

## Overview

This document describes the automated security scanning pipeline for PPMAP, enabling continuous security monitoring throughout the development lifecycle.

**Components:**
- GitHub Actions workflow for automated scanning
- Pre-commit hooks for local checks
- Local security scanning script
- Integration with external security tools

---

## 🚀 Quick Start

### 1. Enable GitHub Actions

```bash
# Already configured in .github/workflows/security-scan.yml
# Just push to trigger automatic scans
git push origin feature/my-feature
```

### 2. Setup Pre-commit Hooks (Local)

```bash
# Install pre-commit framework
pip install pre-commit

# Install hooks defined in .pre-commit-config.yaml
pre-commit install

# Run on all files
pre-commit run --all-files

# Disable temporarily (if needed)
git commit --no-verify
```

### 3. Run Local Security Scan

```bash
# Quick scan (30 seconds)
python scripts/security_scan.py

# Full scan (5 minutes, includes dependencies)
python scripts/security_scan.py --full

# Auto-fix issues where possible
python scripts/security_scan.py --fix

# Verbose output
python scripts/security_scan.py --verbose
```

---

## 📋 Security Scanning Pipeline

### Stage 1: GitHub Actions Workflow

**File:** `.github/workflows/security-scan.yml`  
**Trigger:** Push, PR, Daily 2 AM UTC

#### Scanning Tools

| Tool | Purpose | Severity |
|------|---------|----------|
| **Bandit** | Python security linter | Critical/High |
| **Safety** | Dependency vulnerability DB | Critical |
| **Pip-audit** | Package vulnerability audit | High |
| **Semgrep** | Pattern-based code analysis | Medium |
| **Detect-secrets** | Hardcoded credentials detection | Critical |
| **OWASP Dep Check** | Dependency security check | All |
| **SonarQube** | Code quality & security | Medium |

#### Workflow Stages

```yaml
Security Scan Pipeline:
├── Stage 1: Dependency Checks
│   ├── Safety (known CVEs)
│   ├── Pip-audit (package scan)
│   └── OWASP Dependency Check
├── Stage 2: Static Analysis (SAST)
│   ├── Bandit
│   ├── Pylint
│   ├── Semgrep
│   └── Detect-secrets
├── Stage 3: Custom Tests
│   ├── ReDoS protection
│   ├── Path traversal protection
│   ├── SSL verification config
│   └── Pytest security tests
├── Stage 4: Code Coverage
│   └── Codecov integration
└── Stage 5: Reporting
    ├── PR Comments
    └── Artifact Upload
```

### Stage 2: Pre-commit Hooks

**File:** `.pre-commit-config.yaml`  
**Trigger:** Before commit (local)

```bash
Pre-commit Hooks Chain:
├── YAML validation
├── Secrets detection
├── Bandit (lightweight)
├── Pylint
├── Code formatting (Black)
├── Type checking (MyPy)
└── Markdown linting
```

### Stage 3: Local Security Script

**File:** `scripts/security_scan.py`  
**Trigger:** Manual run before push

---

## 🔧 Configuration Details

### GitHub Actions Config

```yaml
# .github/workflows/security-scan.yml
name: Security Scanning Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: '0 2 * * *'  # Daily scan
```

#### Permissions Required

```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write
```

#### Python Versions Tested

```yaml
matrix:
  python-version: ['3.10', '3.11', '3.12']
```

### Pre-commit Config

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ['-c', 'bandit.yaml']
```

### Bandit Configuration

**File:** `bandit.yaml`

```yaml
assert_used:
  skips: ['*/test_*.py', '*/tests.py']

exec_used:
  exclude_dirs: ['/test']

hardcoded_sql_string:
  skips: ['*/test_*.py']
```

---

## 📊 Understanding Reports

### Bandit Report Format

```json
{
  "metrics": {
    "ppmap": {
      "TOTAL": 15,
      "SEVERITY.HIGH": 2,
      "SEVERITY.MEDIUM": 8,
      "SEVERITY.LOW": 5
    }
  },
  "results": [
    {
      "test_id": "B602",
      "issue_text": "shell=True identified",
      "severity": "HIGH",
      "line_number": 42
    }
  ]
}
```

### Safety Report Format

```json
{
  "25853": {
    "v": "<2.0.0",
    "cve": "CVE-2020-XXXXX",
    "specs": ["paramiko<2.0.0"]
  }
}
```

### Custom Tests Report

```
✅ redos - PASSED
✅ path_traversal - PASSED
✅ ssl_config - PASSED
✅ tests - PASSED (21/21)

Summary: 4/4 checks passed
```

---

## 🔐 Security Best Practices

### 1. Secrets Management

```bash
# Initialize secrets baseline
detect-secrets scan --baseline .secrets.baseline

# Update baseline after audit
detect-secrets audit .secrets.baseline

# Never commit secrets to git
git-crypt enable
```

### 2. Dependency Management

```bash
# Regular updates
pip install --upgrade pip
pip list --outdated

# Audit before updating
pip-audit before-update

# Test after updating
pytest tests/
```

### 3. Code Review Checklist

- ✅ All GitHub Actions checks pass
- ✅ Security test coverage > 80%
- ✅ No new critical/high Issues
- ✅ Dependencies up-to-date
- ✅ No hardcoded secrets

### 4. Release Checklist

```bash
# Run full security scan
python scripts/security_scan.py --full

# Check all tests pass
pytest tests/test_security_fixes.py -v

# Verify no known CVEs
safety check

# Tag release
git tag -a v4.1.0 -m "Security release"
git push origin v4.1.0
```

---

## 🚨 Incident Response

### When Security Scan Fails

#### Step 1: Review Findings

```bash
# Check GitHub Actions log
# Look for SEVERITY.HIGH or SEVERITY.CRITICAL

# Download detailed reports
# From Actions → Artifacts
```

#### Step 2: Triage Issues

```python
# Critical (CVSS 9+): Fix immediately
# High (CVSS 7-8.9): Fix before merge
# Medium (CVSS 4-6.9): Triage & document
# Low (CVSS <4): Log for future fixes
```

#### Step 3: Create Fix

```bash
# Create branch
git checkout -b fix/security-issue-XXX

# Fix issue
# Run local scan
python scripts/security_scan.py --full

# Commit & push
git push origin fix/security-issue-XXX
```

#### Step 4: Document & Review

```markdown
## Security Fix

**Issue:** [Description]
**Severity:** HIGH
**CVSS:** 7.2
**Fixed by:** [Commit]

### Changes
- Modified: ppmap/module.py
- Added: validation function

### Testing
- Unit tests: ✅ Passed
- Security tests: ✅ Passed
```

---

## 🛠️ Customization

### Add Custom Rule

```python
# .pre-commit-hooks.yaml
- id: custom-security-check
  name: Custom Security Check
  entry: python scripts/custom_check.py
  language: python
  types: [python]
```

### Exclude Files

```yaml
# .pre-commit-config.yaml
exclude: |
  (?x)^(
    docs/|
    build/|
    \.venv
  )$
```

### Adjust Bandit Severity

```bash
# Skip specific test
bandit -s B602 ppmap/

# Set minimum severity
bandit -ll ppmap/  # High/Critical only
```

---

## 📈 Monitoring & Metrics

### GitHub Actions Insights

```bash
# View scan history
# GitHub → Actions → Security Scanning Pipeline

# Export metrics
# Artifacts → Download reports
```

### Track Improvements

```python
# Monthly report
import json
from pathlib import Path

reports = sorted(Path('reports').glob('*.json'))
for report in reports:
    with open(report) as f:
        data = json.load(f)
        print(f"{report.name}: {len(data['results'])} issues")
```

### Trend Analysis

| Date | Critical | High | Medium | Low |
|------|----------|------|--------|-----|
| 2026-01 | 5 | 12 | 24 | 8 |
| 2026-02 | 2 | 5 | 15 | 3 |
| 2026-03 | 1 | 2 | 8 | 1 |

---

## 🔗 Integration with External Tools

### SonarQube Setup

```bash
# 1. Create project
# SonarQube → Create Project

# 2. Add token to GitHub
# GitHub → Settings → Secrets → SONAR_TOKEN

# 3. Scan runs automatically
# Check: SonarQube → Dashboards
```

### CodeQL Integration

```yaml
# .github/workflows/codeql.yml (example)
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/init@v2
      - uses: github/codeql-action/analyze@v2
```

---

## 🎓 Training & Documentation

### Team Guidelines

1. **Every developer runs:** `pre-commit install`
2. **Before pushing:** `python scripts/security_scan.py`
3. **Review reports** before submitting PR
4. **Document security decisions** in comments
5. **Escalate findings** to security team

### Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)
- [CWE Top 25](https://cwe.mitre.org/top25)

---

## ✅ Verification Checklist

- [ ] GitHub Actions workflow is enabled
- [ ] Pre-commit hooks installed locally
- [ ] Security scan script is executable
- [ ] All tests pass (`pytest tests/test_security_fixes.py`)
- [ ] Security baselines created (`.secrets.baseline`)
- [ ] SonarQube tokens configured (if using)
- [ ] Team members trained on process
- [ ] Documentation reviewed and approved

---

**Status:** ✅ Complete  
**Last Updated:** 2026-03-04  
**Maintained by:** Security Team

# Contributing to PPMAP

Thank you for your interest in contributing to PPMAP (Prototype Pollution Multi-Purpose Assessment Platform)! This document provides guidelines for contributing to the project.

---

## 🎯 Project Mission

PPMAP aims to be the most comprehensive prototype pollution scanner available, providing security professionals with cutting-edge detection capabilities for both client-side and server-side vulnerabilities.

---

## 🤝 How to Contribute

If you'd like to contribute, start by searching through the [pull requests](https://github.com/aarsaputra/ppmap-proto-pollution/pulls) to see whether someone else has raised a similar idea or question.

If you don't see your idea listed, and you think it fits into the goals of this project, open a pull request.

### 💡 Quick Tip for Beginners

1. Always create a new branch for your changes.
2. Write clear commit messages.
3. Test your changes locally before submitting a PR.
4. Follow the style guide.
5. Be patient during reviews.

### 1. **Bug Reports**
If you find a bug, please open an issue with:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- PPMAP version (`cat VERSION`)
- Environment (OS, Python version, browser)

### 2. **Feature Requests**
For new features, please:
- Check existing issues first
- Describe the use case
- Provide examples or references (CVEs, research papers, etc.)
- Explain why it's valuable for security testing

### 3. **Code Contributions**

#### **Before You Start**
- Fork the repository
- Create a feature branch: `git checkout -b feature/your-feature-name`
- Check existing code style and patterns

#### **Development Setup**
```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/ppmap.git
cd ppmap

# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/

# Test your changes
python ppmap.py --scan http://localhost:3000
```

#### **Code Standards**
- Follow PEP 8 style guide
- Add docstrings to all functions
- Include type hints where applicable
- Keep functions focused and modular
- Add comments for complex logic

#### **Testing Requirements**
- Test against `ppmap_lab` (vulnerable test environment)
- Ensure all existing tests pass
- Add new tests for new features
- Verify no false positives

#### **Commit Guidelines**
```bash
# Good commit messages
git commit -m "Add CVE-2024-XXXXX detection method"
git commit -m "Fix false positive in jQuery detection"
git commit -m "Update documentation for Tier 6 features"

# Bad commit messages (avoid)
git commit -m "fix bug"
git commit -m "update"
```

#### **Pull Request Process**
1. Update documentation (README.md, DOCUMENTATION.md)
2. Add entry to CHANGELOG.md
3. Ensure code compiles: `python -m py_compile ppmap.py`
4. Update VERSION if needed
5. Submit PR with clear description
6. Link related issues

---

## 📚 Areas for Contribution

### **High Priority**
- New CVE-specific payloads
- Framework-specific detection (Angular, Svelte, etc.)
- Performance optimizations
- False positive reduction
- Browser compatibility improvements

### **Medium Priority**
- Additional third-party library gadgets
- Enhanced reporting (PDF, CSV)
- CI/CD integration examples
- Docker improvements
- Additional test cases

### **Low Priority**
- Documentation improvements
- Code refactoring
- UI/UX enhancements
- Translation (i18n)

---

## 🔬 Research Contributions

We welcome research contributions! If you've discovered:
- New prototype pollution vectors
- Novel bypass techniques
- Framework-specific vulnerabilities
- Real-world exploits

Please:
1. Document your findings thoroughly
2. Provide PoC code or lab setup
3. Include references (CVEs, blog posts, etc.)
4. Submit as an issue or PR with `[RESEARCH]` tag

---

## 🧪 Testing Guidelines

### **Lab Testing**
```bash
# Start vulnerable lab
cd ppmap_lab
npm install
npm start

# Run PPMAP against lab
python ppmap.py --scan http://localhost:3000

# Expected: 24-28 vulnerabilities detected
```

### **Unit Tests**
```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test
python -m pytest tests/test_scanner.py -v

# Run with coverage
python -m pytest tests/ --cov=ppmap --cov-report=html
```

### **Manual Testing**
- Test against PortSwigger labs
- Test against real applications (with permission!)
- Verify no crashes or errors
- Check for false positives

---

## 📖 Documentation Standards

### **Code Documentation**
```python
def test_new_vulnerability(self, target_url):
    """
    Test for [Vulnerability Name] (CVE-XXXX-XXXXX).
    
    This method detects [brief description of vulnerability].
    
    Args:
        target_url (str): Target URL to test
        
    Returns:
        list: List of Finding objects
        
    References:
        - CVE-XXXX-XXXXX
        - https://example.com/research
    """
    findings = []
    # Implementation...
    return findings
```

### **README Updates**
- Update statistics (detection methods, CVE coverage)
- Add new features to feature list
- Update examples if needed

### **CHANGELOG Updates**
- Follow Keep a Changelog format
- Categorize: Added, Changed, Fixed, Removed
- Include version and date

---

## 🚨 Security Considerations

### **Responsible Disclosure**
- Do NOT include real credentials or API keys
- Do NOT target systems without authorization
- Report security issues privately first
- Follow responsible disclosure practices

### **Payload Safety**
- All payloads must be safe for testing
- No destructive payloads (file deletion, etc.)
- RCE detection should be safe (no actual execution)
- Document any potentially dangerous payloads

### **Privacy**
- Do NOT include personal information
- Do NOT include company-specific data
- Anonymize any examples or logs

---

## 📋 Checklist for Contributors

Before submitting a PR, ensure:

- [ ] Code follows PEP 8 style guide
- [ ] All functions have docstrings
- [ ] New features have tests
- [ ] All tests pass (`pytest tests/`)
- [ ] Code compiles (`python -m py_compile ppmap.py`)
- [ ] Documentation updated (README, DOCUMENTATION, CHANGELOG)
- [ ] No hardcoded credentials or sensitive data
- [ ] Commit messages are clear and descriptive
- [ ] PR description explains changes
- [ ] Related issues are linked

---

## 🎓 Learning Resources

### **Prototype Pollution**
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/prototype-pollution)
- [HackerOne Reports](https://hackerone.com/hacktivity?querystring=prototype%20pollution)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution)

### **Python Development**
- [PEP 8 Style Guide](https://pep8.org/)
- [Python Type Hints](https://docs.python.org/3/library/typing.html)
- [Pytest Documentation](https://docs.pytest.org/)

### **Security Testing**
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bug Bounty Methodology](https://github.com/jhaddix/tbhm)

---

## 💬 Communication

### **Questions?**
- Open an issue with `[QUESTION]` tag
- Check existing issues first
- Be respectful and professional

### **Discussions**
- Use GitHub Discussions for general topics
- Use Issues for specific bugs/features
- Tag appropriately

---

## 📜 Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

### **Our Standards**
- Be respectful and inclusive
- Welcome newcomers
- Accept constructive criticism
- Focus on what's best for the project
- Show empathy towards others

### **Unacceptable Behavior**
- Harassment or discrimination
- Trolling or insulting comments
- Publishing others' private information
- Unethical security testing practices

---

## 🏆 Recognition

Contributors will be:
- Listed in CHANGELOG.md
- Mentioned in release notes
- Credited in documentation (if significant contribution)

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the same license as the project.

**Important**: This tool is for **AUTHORIZED SECURITY TESTING ONLY**.  
Contributors must ensure their code is used ethically and legally.

---

## 🚀 Getting Started

Ready to contribute? Here's a quick start:

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/ppmap.git
cd ppmap

# 2. Create branch
git checkout -b feature/amazing-feature

# 3. Make changes
# ... edit code ...

# 4. Test
python -m pytest tests/
python ppmap.py --scan http://localhost:3000

# 5. Commit
git add .
git commit -m "Add amazing feature"

# 6. Push
git push origin feature/amazing-feature

# 7. Create Pull Request on GitHub
```

---

**Thank you for contributing to PPMAP!** 🎉

Your contributions help make the security community stronger and safer.

---

**Last Updated**: February 27, 2026  
**Project Version**: 4.1.0  
**Maintainers**: Security Research Team

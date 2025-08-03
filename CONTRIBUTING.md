# Contributing to Signcryption System

## ⚠️ Important Notice

**This project implements cryptographically broken algorithms for educational purposes only.**

Before contributing, please understand:

1. **This is NOT a secure cryptographic library**
2. **The OSS signature scheme is intentionally insecure**
3. **Contributions should maintain educational value**
4. **Security "fixes" to OSS are not needed (it's meant to be broken)**

## How to Contribute

### Types of Contributions Welcome

✅ **Educational Improvements**
- Better explanations of why algorithms are insecure
- Additional educational examples
- Improved documentation
- Clearer security warnings

✅ **Code Quality**
- Bug fixes in implementation (non-cryptographic)
- Better error handling
- Code style improvements
- Performance optimizations

✅ **Testing**
- Additional unit tests
- Integration test improvements
- Better test coverage
- Documentation of test cases

✅ **User Experience**
- GUI improvements
- Better user feedback
- Accessibility enhancements
- Clearer workflows

❌ **Not Welcome**
- "Fixing" the OSS algorithm (it's meant to be broken)
- Making the system "production ready"
- Removing security warnings
- Adding production-grade crypto

### Getting Started

1. **Fork the repository**
   ```bash
   git clone https://github.com/HaikalE/signcryption-schmidt-samoa-oss.git
   cd signcryption-schmidt-samoa-oss
   ```

2. **Set up development environment**
   ```bash
   make dev-setup
   # or manually:
   pip install -r requirements.txt
   pip install pytest pytest-cov flake8 black
   ```

3. **Run tests to ensure everything works**
   ```bash
   make test
   ```

4. **Create a feature branch**
   ```bash
   git checkout -b feature/your-improvement
   ```

### Development Guidelines

#### Code Style
- Follow PEP 8 guidelines
- Use `black` for formatting: `make format`
- Run linting: `make lint`
- Maximum line length: 100 characters
- Use meaningful variable names
- Add docstrings to all functions and classes

#### Security Warnings
- **Always** include security warnings in cryptographic code
- **Never** remove existing security warnings
- Make it clear when algorithms are intentionally insecure
- Reference why algorithms are broken (academic papers)

#### Testing
- Write tests for new functionality
- Maintain test coverage above 80%
- Include both positive and negative test cases
- Test error conditions and edge cases
- Document what each test validates

#### Documentation
- Update README.md if adding new features
- Include docstrings with examples
- Explain the educational purpose of changes
- Reference academic sources when relevant

### Submission Process

1. **Ensure your code passes all checks**
   ```bash
   make check  # Runs lint and test
   ```

2. **Write clear commit messages**
   ```
   feat: add demonstration of Pollard attack on OSS
   
   - Implement educational example showing signature forgery
   - Add academic references to attack methods
   - Include clear warnings about vulnerability
   ```

3. **Create a Pull Request**
   - Use descriptive title
   - Explain the educational value
   - Reference any issues being addressed
   - Include screenshots for UI changes

4. **Ensure PR includes**
   - Tests for new functionality
   - Updated documentation
   - Appropriate security warnings
   - Educational context

### Example Contributions

#### Good Contribution Example
```python
def demonstrate_oss_weakness():
    """
    Educational function showing OSS signature forgery.
    
    This demonstrates why OSS should never be used in production
    by showing how signatures can be forged without private keys.
    
    References:
    - Pollard, J.M. (1988). Monte Carlo methods for index computation
    - Academic paper showing the mathematical weakness
    """
    # Implementation that clearly shows the vulnerability
```

#### Poor Contribution Example
```python
def secure_oss_signature():
    """
    Fixed version of OSS that is actually secure.
    """
    # This misses the point - OSS is meant to be educational!
```

### Issue Reporting

When reporting issues:

1. **Check if it's a "security issue"**
   - OSS being broken is intentional, not a bug
   - Focus on implementation bugs, not cryptographic ones

2. **Provide clear reproduction steps**
   ```
   Steps to reproduce:
   1. Generate keys with size 1024
   2. Encrypt large message (>10KB)
   3. Application crashes with error...
   ```

3. **Include system information**
   - Python version
   - Operating system
   - Dependencies versions

4. **Describe expected vs actual behavior**

### Types of Issues to Report

✅ **Implementation Issues**
- Application crashes
- Memory leaks
- Performance problems
- Incorrect mathematical implementations

✅ **Usability Issues**
- Confusing user interface
- Unclear error messages
- Missing educational context
- Accessibility problems

✅ **Documentation Issues**
- Unclear instructions
- Missing security warnings
- Broken examples
- Outdated information

❌ **Not Issues**
- "OSS is insecure" (this is intentional)
- "Should use real crypto" (this is educational)
- "Add production features" (against project goals)

### Educational Focus

Remember that contributions should enhance the educational value:

- **Explain** why certain approaches are insecure
- **Demonstrate** cryptographic vulnerabilities clearly
- **Reference** academic sources and papers
- **Compare** with secure alternatives
- **Warn** about production use

### Code Review Process

Pull requests will be reviewed for:

1. **Educational Value**: Does it help people learn?
2. **Code Quality**: Is it well-written and tested?
3. **Security Warnings**: Are appropriate warnings included?
4. **Documentation**: Is the purpose clear?
5. **Testing**: Are changes properly tested?

### Questions?

Feel free to open an issue with the "question" label if you:
- Want to discuss a potential contribution
- Need clarification on project goals
- Have ideas for educational improvements
- Want to understand the cryptographic concepts better

---

Thank you for contributing to this educational project! Remember: the goal is to teach people about cryptography and why certain algorithms should not be used in production.

**By contributing, you agree that your contributions will be licensed under the same MIT license as the project, with the same security disclaimers.**
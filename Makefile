# Makefile for Signcryption System
# Educational project - NOT for production use!

.PHONY: help install test lint format clean demo gui docs

# Default target
help:
	@echo "Signcryption System - Educational Cryptography Project"
	@echo "⚠️  WARNING: This system uses INSECURE cryptographic algorithms!"
	@echo "⚠️  For educational purposes only - DO NOT use in production!"
	@echo ""
	@echo "Available targets:"
	@echo "  help     - Show this help message"
	@echo "  install  - Install dependencies"
	@echo "  test     - Run all tests"
	@echo "  lint     - Run code linting"
	@echo "  format   - Format code with black"
	@echo "  clean    - Clean generated files"
	@echo "  demo     - Run basic usage examples"
	@echo "  gui      - Launch GUI application"
	@echo "  docs     - Generate documentation"
	@echo "  security - Show security warnings"

install:
	@echo "Installing dependencies..."
	pip install -r requirements.txt
	@echo "✅ Dependencies installed"

test:
	@echo "Running tests..."
	@echo "⚠️  Note: These tests verify implementation, not security!"
	pytest tests/ -v --tb=short

test-coverage:
	@echo "Running tests with coverage..."
	pytest tests/ --cov=. --cov-report=html --cov-report=term

lint:
	@echo "Running code linting..."
	flake8 *.py tests/ examples/ --max-line-length=100 --ignore=E203,W503

format:
	@echo "Formatting code..."
	black *.py tests/ examples/ --line-length=100
	@echo "✅ Code formatted"

clean:
	@echo "Cleaning generated files..."
	rm -rf __pycache__/
	rm -rf tests/__pycache__/
	rm -rf examples/__pycache__/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf keys/
	rm -rf examples_output/
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -name "*~" -delete
	@echo "✅ Cleanup completed"

demo:
	@echo "Running basic usage examples..."
	@echo "⚠️  Educational demonstration - algorithms are INSECURE!"
	python examples/basic_usage.py

gui:
	@echo "Launching GUI application..."
	@echo "⚠️  WARNING: This uses cryptographically broken algorithms!"
	@echo "⚠️  Educational use only!"
	python main_app.py

docs:
	@echo "Generating documentation..."
	@mkdir -p docs
	@echo "# Signcryption System Documentation" > docs/README.md
	@echo "" >> docs/README.md
	@echo "This is an educational project implementing insecure cryptographic algorithms." >> docs/README.md
	@echo "See the main README.md for details." >> docs/README.md
	@echo "✅ Basic documentation generated"

security:
	@echo ""
	@echo "=================================================================="
	@echo "⚠️  CRITICAL SECURITY WARNING ⚠️"
	@echo "=================================================================="
	@echo "This project implements the Ong-Schnorr-Shamir (OSS) signature"
	@echo "scheme, which is CRYPTOGRAPHICALLY BROKEN and vulnerable to"
	@echo "signature forgery attacks."
	@echo ""
	@echo "NEVER USE THIS SOFTWARE FOR:"
	@echo "  ❌ Production applications"
	@echo "  ❌ Real security needs"
	@echo "  ❌ Protecting actual sensitive data"
	@echo "  ❌ Any security-critical system"
	@echo ""
	@echo "THIS IS FOR EDUCATIONAL PURPOSES ONLY!"
	@echo ""
	@echo "For real applications, use:"
	@echo "  ✅ Industry-standard libraries (OpenSSL, libsodium)"
	@echo "  ✅ Proven algorithms (AES, RSA, ECDSA, EdDSA)"
	@echo "  ✅ Established cryptographic frameworks"
	@echo "=================================================================="
	@echo ""

# Development targets
dev-setup: install
	@echo "Setting up development environment..."
	pip install pytest pytest-cov flake8 black
	@echo "✅ Development environment ready"

check: lint test
	@echo "✅ All checks passed"

# Package building (for educational distribution)
build:
	@echo "Building package..."
	@echo "⚠️  This package is for educational use only!"
	python setup.py sdist bdist_wheel
	@echo "✅ Package built in dist/"

install-dev:
	@echo "Installing in development mode..."
	pip install -e .

# Quick start
quickstart: install demo
	@echo "✅ Quick start completed!"
	@echo "Next steps:"
	@echo "  - Run 'make gui' to try the graphical interface"
	@echo "  - Run 'make test' to verify the implementation"
	@echo "  - Read README.md for detailed information"
	@echo ""
	@echo "⚠️  Remember: This is educational software only!"
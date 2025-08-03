#!/usr/bin/env python3
"""
Setup script for Signcryption System

Author: Claude
Date: August 2025
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name="signcryption-schmidt-samoa-oss",
    version="1.0.0",
    author="Claude (AI Assistant)",
    author_email="noreply@example.com",
    description="Educational implementation of signcryption using Schmidt-Samoa cryptosystem and OSS digital signature (INSECURE - Educational Only)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/HaikalE/signcryption-schmidt-samoa-oss",
    packages=find_packages(exclude=["tests*", "examples*"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Education",
        "Intended Audience :: Developers", 
        "Topic :: Security :: Cryptography",
        "Topic :: Education",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: X11 Applications :: Qt",
        "Environment :: Win32 (MS Windows)",
        "Environment :: MacOS X"
    ],
    python_requires=">=3.8",
    install_requires=[
        "PyCryptodome>=3.18.0",
        "cryptography>=41.0.0",
        "sympy>=1.12"
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "flake8>=6.0.0",
            "black>=23.0.0"
        ],
        "docs": [
            "sphinx>=7.0.0",
            "sphinx-rtd-theme>=1.3.0"
        ]
    },
    entry_points={
        "console_scripts": [
            "signcryption-demo=examples.basic_usage:main",
            "signcryption-gui=main_app:main"
        ]
    },
    project_urls={
        "Bug Reports": "https://github.com/HaikalE/signcryption-schmidt-samoa-oss/issues",
        "Source": "https://github.com/HaikalE/signcryption-schmidt-samoa-oss",
        "Documentation": "https://github.com/HaikalE/signcryption-schmidt-samoa-oss#readme"
    },
    keywords="cryptography education signcryption schmidt-samoa oss digital-signature insecure-algorithm",
    zip_safe=False,
    include_package_data=True
)
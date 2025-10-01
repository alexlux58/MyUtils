"""
Setup script for the Enhanced Security Reconnaissance Framework.
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="enhanced-security-reconnaissance",
    version="1.0.0",
    author="Security Research Team",
    author_email="security@example.com",
    description="Enhanced Security Reconnaissance & OSINT Automation Framework",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/example/enhanced-security-reconnaissance",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-mock>=3.11.0",
            "pytest-cov>=4.0.0",
            "flake8>=6.0.0",
            "black>=23.0.0",
            "bandit>=1.7.0",
        ],
        "google": [
            "google-api-python-client>=2.0.0",
            "google-auth>=2.0.0",
            "google-auth-oauthlib>=1.0.0",
        ],
        "crypto": [
            "cryptography>=41.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "recon-framework=src.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml", "*.json", "*.md", "*.txt"],
    },
    keywords="security, reconnaissance, osint, penetration-testing, red-team, cybersecurity",
    project_urls={
        "Bug Reports": "https://github.com/example/enhanced-security-reconnaissance/issues",
        "Source": "https://github.com/example/enhanced-security-reconnaissance",
        "Documentation": "https://github.com/example/enhanced-security-reconnaissance/docs",
    },
)

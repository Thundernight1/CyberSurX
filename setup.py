#!/usr/bin/env python3
"""
RedTeam Physical Suite - Setup Configuration
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
if readme_path.exists():
    with open(readme_path, "r", encoding="utf-8") as f:
        long_description = f.read()
else:
    long_description = "CyberSurX RedTeam Physical Suite - Modern CLI for Pentesting"

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
if requirements_path.exists():
    with open(requirements_path, "r", encoding="utf-8") as f:
        requirements = [
            line.strip() 
            for line in f 
            if line.strip() and not line.startswith("#") and not line.startswith(";")
        ]
else:
    requirements = [
        "typer>=0.9.0",
        "rich>=13.0.0",
        "pyfiglet>=1.0.0",
    ]

setup(
    name="cybersurx",
    version="1.0.0",
    author="CyberSurX",
    author_email="redteam@cybersurx.dev",
    description="RedTeam Physical Security Suite - Kali + Physical Devices",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cybersurx/cybersurx",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "cybersurx=src.cli:app",
            "rtphys=src.cli:app",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)

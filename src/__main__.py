#!/usr/bin/env python3
"""
CyberSurX Suite - CLI Entry Point

Usage:
    python -m src --target 192.168.1.0/24
    python -m src --target 10.0.0.1 --devices pineapple,flipper
    python -m src --config config.yaml --full-pipeline
"""

import sys
from src.redteam_master import main

if __name__ == '__main__':
    sys.exit(main())

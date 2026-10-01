#!/usr/bin/env python3
"""
Recon Toolkit Entry Point.

Usage:
    python main.py example.com [options]
"""

import sys
from recon_toolkit.cli import run_cli

if __name__ == "__main__":
    sys.exit(run_cli())

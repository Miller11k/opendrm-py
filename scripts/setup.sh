#!/usr/bin/env bash
set -euo pipefail
python -m venv .venv
. .venv/bin/activate
pip install -U pip
# pip install -r requirements.txt  # or: pip install -e .
echo "Dev env ready."

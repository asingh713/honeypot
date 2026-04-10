#!/usr/bin/env bash
# Launch all honeypot services locally without Docker.
# Requires: pip install -r requirements.txt
set -euo pipefail

cd "$(dirname "$0")/.."

# Create required directories
mkdir -p data logs

echo "Starting honeypot (Ctrl+C to stop)..."
python main.py

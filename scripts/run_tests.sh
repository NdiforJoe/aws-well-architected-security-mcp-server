#!/bin/bash
set -euo pipefail

echo "=== Setting up virtual environment ==="
python -m venv venv
source venv/bin/activate

echo "=== Installing dependencies ==="
pip install --upgrade pip
pip install -r requirements.txt
pip install pytest pytest-cov pytest-mock pytest-asyncio

echo "=== Running tests with coverage ==="
pytest tests/unit --cov=src --cov-report=term-missing --cov-report=xml --cov-fail-under=80

echo "=== Tests complete! ==="
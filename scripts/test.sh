#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -x "$ROOT_DIR/venv/bin/python" ]]; then
  PYTHON="$ROOT_DIR/venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON="python"
else
  echo "Python was not found on PATH." >&2
  exit 1
fi

if ! "$PYTHON" -m pytest --version >/dev/null 2>&1; then
  echo "pytest is not installed for $PYTHON." >&2
  echo "Install development dependencies with:" >&2
  echo "  $PYTHON -m pip install -r requirements.txt -r requirements-dev.txt" >&2
  exit 1
fi

exec "$PYTHON" -m pytest -q "$@"

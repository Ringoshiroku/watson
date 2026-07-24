#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 not found on PATH" >&2
    exit 1
fi

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    found="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    echo "error: watson requires Python 3.10 or later, found $found" >&2
    exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment at $VENV_DIR..."
    if ! python3 -m venv "$VENV_DIR"; then
        echo "error: failed to create a virtual environment." >&2
        echo "on Debian/Kali/Ubuntu, you may need: sudo apt install python3-venv" >&2
        exit 1
    fi
else
    echo "Reusing existing virtual environment at $VENV_DIR"
fi

echo "Upgrading pip, setuptools, and wheel..."
"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel

echo "Installing watson (editable) and dev dependencies..."
"$VENV_DIR/bin/pip" install -e ".[dev]"

echo
echo "watson installed. Running 'watson setup' to check/install optional analysis tools..."
echo
"$VENV_DIR/bin/watson" setup

echo
echo "Done. In future shells, activate the virtual environment first:"
echo "  source $VENV_DIR/bin/activate"
echo "Then run: watson analyze <file>"

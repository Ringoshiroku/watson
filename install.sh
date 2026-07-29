#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"

PYTHON=""
for candidate in python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "error: no python3 found on PATH" >&2
    exit 1
fi

if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    found="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    echo "error: watson requires Python 3.10 or later, found $found ($PYTHON)" >&2
    exit 1
fi

if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info < (3, 12) else 1)'; then
    found="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    installed=false
    if command -v pyenv >/dev/null 2>&1; then
        # pyenv < 2.3 lacks the `latest` subcommand; 3.11.13 is the newest 3.11.x as of writing.
        target="$(pyenv latest -k 3.11 2>/dev/null || echo 3.11.13)"
        if [ -t 0 ] && [ -t 1 ]; then
            read -r -p "Python $found found ($PYTHON); stringsifter needs 3.11 or earlier. install Python $target now with 'pyenv install $target'? [y/N] " answer
        else
            answer="n"
        fi
        if [ "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" = "y" ]; then
            if pyenv install -s "$target"; then
                pyenv_python="$(pyenv root)/versions/$target/bin/python3.11"
                if [ -x "$pyenv_python" ]; then
                    PYTHON="$pyenv_python"
                    installed=true
                    echo "Using pyenv-installed Python $target for the venv."
                    if ! "$PYTHON" -c 'import bz2, sqlite3, readline' >/dev/null 2>&1; then
                        echo "warning: this pyenv build is missing some stdlib extensions (bz2/sqlite3/readline), likely missing system dev headers." >&2
                        echo "warning: see https://www.kali.org/docs/general-use/using-eol-python-versions/ for the build dependencies to install, then 'pyenv uninstall $target && pyenv install $target' to rebuild with full support." >&2
                    fi
                else
                    echo "warning: pyenv install succeeded but $pyenv_python not found; falling back to Python $found." >&2
                fi
            else
                echo "warning: 'pyenv install $target' failed; falling back to Python $found." >&2
            fi
        fi
    fi
    if [ "$installed" = false ]; then
        echo "warning: using Python $found ($PYTHON). stringsifter's pinned numpy build has no wheel past 3.11 and may fail to build from source on this version." >&2
        echo "warning: install Python 3.11 (e.g. 'pyenv install 3.11', or your distro's package) and re-run this script; it will be picked automatically and every optional tool will install cleanly." >&2
        echo "warning: on Kali, python3.11 isn't packaged in apt; see https://www.kali.org/docs/general-use/using-eol-python-versions/ for installing pyenv itself and its build dependencies." >&2
    fi
fi

selected_version="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"

if [ -d "$VENV_DIR" ]; then
    existing_version=""
    if [ -x "$VENV_DIR/bin/python" ]; then
        existing_version="$("$VENV_DIR/bin/python" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
    fi
    if [ "$existing_version" != "$selected_version" ]; then
        echo "Existing $VENV_DIR uses Python ${existing_version:-an unreadable version}, but Python $selected_version was selected for this run; recreating it..."
        rm -rf "$VENV_DIR"
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment at $VENV_DIR..."
    if ! "$PYTHON" -m venv "$VENV_DIR"; then
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
echo "When you're done, leave the virtual environment with: deactivate"

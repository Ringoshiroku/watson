#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"

pyenv_installed_python() {
    # look up an already pyenv-installed interpreter directly by path, since
    # pyenv's python3.11/python3.10 shims only work when that version is the
    # active one (global/local/shell); an installed-but-inactive version's
    # shim exists on PATH but fails to dispatch.
    command -v pyenv >/dev/null 2>&1 || return 1
    local prefix="${1//./\\.}" match
    match="$(pyenv versions --bare 2>/dev/null | grep -E "^${prefix}(\\.[0-9]+)?\$" | sort -V | tail -1)"
    [ -n "$match" ] || return 1
    local candidate="$(pyenv root)/versions/$match/bin/python3"
    [ -x "$candidate" ] || return 1
    printf '%s' "$candidate"
}

stdlib_apt_package() {
    case "$1" in
        bz2) echo libbz2-dev ;;
        sqlite3) echo libsqlite3-dev ;;
        readline) echo libreadline-dev ;;
        lzma) echo liblzma-dev ;;
    esac
}

check_pyenv_build_deps() {
    # python-build silently skips optional C extensions (bz2, sqlite3,
    # readline, tkinter) when their -dev headers are missing, and still
    # exits 0; catching this before the multi-minute compile is much
    # cheaper than after.
    command -v dpkg >/dev/null 2>&1 || return 0
    local pkg missing=()
    for pkg in build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libffi-dev liblzma-dev tk-dev; do
        dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "warning: missing build headers for a full Python build (${missing[*]}); the build will still succeed but silently skip modules like bz2/sqlite3/readline/tkinter." >&2
        echo "warning: install them first with: sudo apt install ${missing[*]}" >&2
    fi
}

PYTHON=""
for prefix in 3.11 3.10; do
    if candidate="$(pyenv_installed_python "$prefix")"; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    for candidate in python3.11 python3.10 python3; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c '' >/dev/null 2>&1; then
            PYTHON="$candidate"
            break
        fi
    done
fi

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
            check_pyenv_build_deps
            if pyenv install -s "$target"; then
                pyenv_python="$(pyenv root)/versions/$target/bin/python3.11"
                if [ -x "$pyenv_python" ]; then
                    PYTHON="$pyenv_python"
                    installed=true
                    echo "Using pyenv-installed Python $target for the venv."
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
        if command -v pyenv >/dev/null 2>&1; then
            echo "warning: install Python 3.11 yourself with 'pyenv install 3.11' and re-run this script; it will be picked automatically and every optional tool will install cleanly." >&2
        else
            echo "warning: install pyenv first (e.g. 'curl -fsSL https://pyenv.run | bash'), then 'pyenv install 3.11', then re-run this script; it will be picked automatically." >&2
        fi
        echo "warning: on Kali, python3.11 isn't packaged in apt; see https://www.kali.org/docs/general-use/using-eol-python-versions/ for installing pyenv itself and its build dependencies." >&2
    fi
fi

selected_version="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"

# Check completeness of whichever pyenv-managed interpreter got selected,
# whether it was just built above or was already installed from a previous
# run; a stale broken build (missing bz2/sqlite3/readline) would otherwise
# go unnoticed on every rerun that finds it already installed.
if command -v pyenv >/dev/null 2>&1; then
    pyenv_root="$(pyenv root)"
    case "$PYTHON" in
        "$pyenv_root"/*)
            missing_modules=()
            for module in bz2 sqlite3 readline lzma; do
                "$PYTHON" -c "import $module" >/dev/null 2>&1 || missing_modules+=("$module")
            done
            if [ "${#missing_modules[@]}" -gt 0 ]; then
                pyenv_version="${PYTHON#"$pyenv_root"/versions/}"
                pyenv_version="${pyenv_version%%/*}"
                missing_packages=()
                for module in "${missing_modules[@]}"; do
                    missing_packages+=("$(stdlib_apt_package "$module")")
                done
                echo "warning: this pyenv-managed Python ($PYTHON) is missing some stdlib modules: ${missing_modules[*]}." >&2
                echo "warning: install the matching headers with: sudo apt install ${missing_packages[*]}" >&2
                echo "warning: then rebuild it with: pyenv uninstall $pyenv_version && pyenv install $pyenv_version" >&2
            fi
            ;;
    esac
fi

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

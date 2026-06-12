#!/usr/bin/env bash
set -euo pipefail

function _resolve_python() {
  if [[ -n "${SYSTEM_PYTHON:-}" ]]; then
    if _probe_python "$SYSTEM_PYTHON"; then
      echo "$SYSTEM_PYTHON"
      return 0
    fi
  fi

  local candidates=()

  if [[ -x "./.venv-test/Scripts/python.exe" ]]; then
    candidates+=("./.venv-test/Scripts/python.exe")
  fi

  if command -v py >/dev/null 2>&1; then
    local py_path
    py_path="$(py -3 -c 'import sys; print(sys.executable)' 2>/dev/null | tr -d '\r' || true)"
    if [[ -n "$py_path" ]]; then
      candidates+=("$py_path")
    fi
  fi

  if command -v python3 >/dev/null 2>&1; then
    candidates+=( "$(command -v python3)" )
  fi

  if command -v python >/dev/null 2>&1; then
    candidates+=( "$(command -v python)" )
  fi

  local candidate
  for candidate in "${candidates[@]}"; do
    if _probe_python "$candidate"; then
      echo "$candidate"
      return 0
    fi
  done

  echo ""
  return 1
}

function _probe_python() {
  local candidate="$1"
  if [[ ! -x "$candidate" ]]; then
    return 1
  fi

  if ! "$candidate" -c "import sys" >/dev/null 2>&1; then
    return 1
  fi

  if "$candidate" -m pip --version >/dev/null 2>&1; then
    return 0
  fi

  return 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if [[ "${1:-}" == "." || "${1:-}" == "" ]]; then
  PROJECT_PATH="$SCRIPT_PROJECT_ROOT"
else
  PROJECT_PATH="$1"
fi
SYSTEM_PYTHON="$(_resolve_python || true)"
if [[ -z "$SYSTEM_PYTHON" ]]; then
  echo "ERROR: no usable Python interpreter found. Install Python and re-run." >&2
  exit 1
fi
VENV_PATH="${2:-.venv-test}"
SKIP_VENV="${SKIP_VENV:-0}"
NO_PAUSE="${NO_PAUSE:-0}"

function _safedeps_wait_exit() {
  local code="${1:-0}"
  if [[ -t 0 && "$NO_PAUSE" != "1" ]]; then
    if (( code == 0 )); then
      read -r -p "Premi INVIO per chiudere..."
    else
      read -r -p "Terminato con errori (exit $code). Premi INVIO per chiudere..."
    fi
  fi
  exit "$code"
}
trap '_safedeps_wait_exit $?' EXIT

PROJECT_PATH="$(cd "$PROJECT_PATH" 2>/dev/null && pwd || true)"
if [[ -z "$PROJECT_PATH" ]]; then
  echo "ERROR: cannot enter project path '$1'." >&2
  exit 1
fi

if [[ ! -f "$PROJECT_PATH/pyproject.toml" && ! -f "$PROJECT_PATH/setup.py" ]]; then
  echo "ERROR: $PROJECT_PATH is not a Python project directory (missing pyproject.toml/setup.py)." >&2
  echo "Tip: run from project root or pass an explicit project path." >&2
  exit 1
fi

cd "$PROJECT_PATH"

echo "1) System install: uninstall + editable reinstall"
"$SYSTEM_PYTHON" -m pip uninstall safedeps -y || true
"$SYSTEM_PYTHON" -m pip install -e .

if [[ "$SKIP_VENV" != "1" ]]; then
  if [[ -x "$VENV_PATH/bin/python" ]]; then
    VENV_PY="$VENV_PATH/bin/python"
  elif [[ -x "$VENV_PATH/Scripts/python.exe" ]]; then
    VENV_PY="$VENV_PATH/Scripts/python.exe"
  else
    echo "ERROR: no usable python in venv path '$VENV_PATH' (expected bin/python or Scripts/python.exe)." >&2
    exit 1
  fi
  echo "2) Local .venv install: uninstall + editable reinstall"
  "$VENV_PY" -m pip uninstall safedeps -y || true
  "$VENV_PY" -m pip install -e .
fi

echo "3) Recreate SafeDeps wrappers in project"
"$SYSTEM_PYTHON" -m safedeps.cli setup .
. ./.safedeps/activate.sh

echo "4) Checks from current shell"
which pip || true
which python || true
which safedeps || true
"$SYSTEM_PYTHON" -m safedeps.cli --version
"$SYSTEM_PYTHON" -m pip --version
"$SYSTEM_PYTHON" -m pip show safedeps

echo "Tip: open UI with safedeps ui . (in another shell with same venv if needed)."
echo "$SYSTEM_PYTHON -m safedeps.cli ui . --open-browser"

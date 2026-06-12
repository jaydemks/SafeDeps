#!/usr/bin/env bash
set -euo pipefail

PROJECT_PATH="${1:-}"
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
trap '_safedeps_wait_exit $?' ERR EXIT

if [[ "${PROJECT_PATH,,}" == "/?" || "${PROJECT_PATH,,}" == "-h" || "${PROJECT_PATH,,}" == "--help" ]]; then
  cat <<'EOF'
Usage:
  ./reset-safedeps.sh [project-path]

Optional project path removes that project's .safedeps folder.
EOF
  exit 0
fi

cleanup_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    return 0
  fi

  local tmp
  tmp="$(mktemp)"
  awk '
    BEGIN {skip=0}
    /SafeDeps Auto Guard >>>/ {skip=1; next}
    /SafeDeps Auto Guard <<</ {if (skip) {skip=0}; next}
    {
      if (skip) { next }
      if ($0 ~ /\\.safedeps[\\/].*bin/ ) { next }
      if ($0 ~ /activate\.ps1/) { next }
      if ($0 ~ /SafeDeps Auto Guard/) { next }
      print
    }
  ' "$file" > "$tmp" && mv "$tmp" "$file"
}

echo "Cleaning PATH in current process..."
if [[ -n "${PATH-}" ]]; then
  PATH="$(printf '%s\n' "${PATH}" | tr ':' '\n' | awk '{
    if ($0 !~ /[\\/]\\.safedeps[\\/]bin/) {
      printf "%s%s", $0, (NR==1?"":"\n")
    }
  }' | sed '/^$/d' | tr '\n' ':')"
fi

echo "Cleaning shell startup files..."
for f in \
  "$HOME/.bashrc" \
  "$HOME/.bash_profile" \
  "$HOME/.profile" \
  "$HOME/.zshrc" \
  "$HOME/.zprofile" \
  "$HOME/.config/fish/config.fish"; do
  cleanup_file "$f"
done

if [[ -d "$HOME/.safedeps" ]]; then
  rm -rf "$HOME/.safedeps"
  echo "Removed: $HOME/.safedeps"
fi

if command -v lsof >/dev/null 2>&1; then
  PIDS=$(lsof -ti tcp:5200 2>/dev/null || true)
  if [[ -n "$PIDS" ]]; then
    echo "Stopping processes using 5200: $PIDS"
    kill -f $PIDS 2>/dev/null || true
  fi
fi

if [[ -n "$PROJECT_PATH" ]]; then
  if [[ -d "$PROJECT_PATH/.safedeps" ]]; then
    rm -rf "$PROJECT_PATH/.safedeps"
    echo "Removed: $PROJECT_PATH/.safedeps"
  fi
fi

echo "SafeDeps environment reset completed."
echo "Start a new shell, then run:"
echo "which pip || true"
echo "which python || true"
echo "which safedeps || true"

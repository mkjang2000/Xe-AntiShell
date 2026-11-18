#!/usr/bin/env bash
# Check the one-time bootstrap with a disposable host filesystem and tools.
set -euo pipefail
test_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
test_work=$(mktemp -d /tmp/xeas-bootstrap-test.XXXXXXXX)
trap 'rm -rf -- "$test_work"' EXIT
export XEAS_BOOTSTRAP_TEST_WORK=$test_work
export XEAS_BOOTSTRAP_TEST_TARGET='xe-antishell|0|0.1.0|33.el10|x86_64'
export XEAS_BOOTSTRAP_TEST_RPM_FAILURE=0
export XEAS_BOOTSTRAP_TEST_REQUIRE_DROPIN=0

unit_path=$test_work/usr/lib/systemd/system/sentinel-updater.service
dropin_dir=$test_work/etc/systemd/system/sentinel-updater.service.d
repair=$dropin_dir/90-rpm-selinux.conf
state_dir=$test_work/var/lib/xe-antishell/updates
tools=$test_work/tools
mkdir -p "${unit_path%/*}" "$dropin_dir" "$state_dir" "$tools"
printf 'ID="rocky"\nVERSION_ID="10.1"\n' > "$test_work/etc/os-release"
printf 'NoNewPrivs:\t0\n' > "$test_work/proc-status"
printf 'reviewed RPM fixture\n' > "$test_work/agent.rpm"
digest=$(sha256sum < "$test_work/agent.rpm")
digest=${digest%% *}

# Keep host access out of the fixture even when run as the real root user.
# Ownership checks still run against files owned by the test's invoking user.
sed \
  -e "s|^PATH=.*|PATH=$tools:/usr/sbin:/usr/bin:/sbin:/bin|" \
  -e 's|EUID == 0|EUID == UID|' \
  -e 's|== 0 ]]|== "$UID" ]]|' \
  -e "s|/proc/\$\$/status|$test_work/proc-status|g" \
  -e "s|/usr/lib/systemd/system/sentinel-updater.service|$unit_path|g" \
  -e "s|/etc/systemd/system/sentinel-updater.service.d|$dropin_dir|g" \
  -e "s|/var/lib/xe-antishell/updates|$state_dir|g" \
  -e "s|/etc/os-release|$test_work/etc/os-release|g" \
  -e "s|/usr/bin/sentinel status|$tools/sentinel status|g" \
  "$test_root/scripts/bootstrap-rpm-updater.sh" > "$test_work/bootstrap"

cat > "$tools/rpm" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
work=$XEAS_BOOTSTRAP_TEST_WORK
repair=$work/etc/systemd/system/sentinel-updater.service.d/90-rpm-selinux.conf
case "$1" in
  -qp) printf '%s\n' "$XEAS_BOOTSTRAP_TEST_TARGET" ;;
  -q) cat "$work/installed" ;;
  -Uvh)
    if [[ "$2" == --test ]]; then
      [[ "$3" == -- && -f "$4" ]]
      printf 'rpm test\n' >> "$work/calls"
      exit 0
    fi
    [[ "$2" == -- && -f "$3" ]]
    printf 'rpm upgrade\n' >> "$work/calls"
    if [[ "$XEAS_BOOTSTRAP_TEST_REQUIRE_DROPIN" == 1 ]]; then
      [[ -f "$repair" ]] || { printf 'drop-in was removed before rpm succeeded\n' >&2; exit 2; }
    fi
    [[ "$XEAS_BOOTSTRAP_TEST_RPM_FAILURE" == 0 ]] || exit 1
    printf '%s\n' "$XEAS_BOOTSTRAP_TEST_TARGET" > "$work/installed"
    printf '[Service]\nNoNewPrivileges=false\n' > "$work/usr/lib/systemd/system/sentinel-updater.service"
    ;;
  *) exit 2 ;;
esac
MOCK

cat > "$tools/systemctl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
work=$XEAS_BOOTSTRAP_TEST_WORK
unit=$work/usr/lib/systemd/system/sentinel-updater.service
case "$1" in
  show)
    [[ "$2" == sentinel-updater.service ]]
    shopt -s nullglob
    dropins=("$work/etc/systemd/system/sentinel-updater.service.d/"*.conf)
    nnp=yes
    if (("${#dropins[@]}")) || grep -Fxq 'NoNewPrivileges=false' "$unit"; then nnp=no; fi
    printf 'LoadState=loaded\nFragmentPath=%s\nDropInPaths=%s\nNoNewPrivileges=%s\n' "$unit" "${dropins[*]}" "$nnp"
    ;;
  daemon-reload) printf 'reload\n' >> "$work/calls" ;;
  restart)
    [[ "$2" == sentineld.service ]]
    printf 'restart agent\n' >> "$work/calls"
    ;;
  *) exit 2 ;;
esac
MOCK

cat > "$tools/sentinel" <<'MOCK'
#!/usr/bin/env bash
[[ "$1" == status ]] || exit 2
printf 'Version: 0.1.0-33.el10.x86_64\nHealth: healthy\n'
MOCK
printf '#!/usr/bin/env bash\nprintf "Enforcing\\n"\n' > "$tools/getenforce"
printf '#!/usr/bin/env bash\nprintf "x86_64\\n"\n' > "$tools/uname"
chmod 0755 "$tools/"*

run_bootstrap() {
  bash "$test_work/bootstrap" "$test_work/agent.rpm" "$@" > "$test_work/output" 2>&1
}

expect_success() {
  if ! run_bootstrap "$@"; then
    cat "$test_work/output" >&2
    exit 1
  fi
}

expect_failure() {
  if run_bootstrap "$@"; then
    printf 'Expected bootstrap failure\n' >&2
    cat "$test_work/output" >&2
    exit 1
  fi
}

printf 'xe-antishell|0|0.1.0|32.el10|x86_64\n' > "$test_work/installed"
printf '[Service]\nNoNewPrivileges=true\n' > "$unit_path"
: > "$test_work/calls"
expect_success "$digest"
[[ ! -s "$test_work/calls" ]]
grep -Fq 'Bootstrap preflight passed for EL10' "$test_work/output"

expect_failure "${digest//?/0}" --apply
[[ ! -s "$test_work/calls" ]]
grep -Fq 'RPM SHA-256 differs' "$test_work/output"

printf '[Service]\nPrivateTmp=no\n' > "$dropin_dir/99-unexpected.conf"
expect_failure "$digest" --apply
[[ ! -s "$test_work/calls" ]]
grep -Fq 'only the known temporary drop-in' "$test_work/output"
rm -- "$dropin_dir/99-unexpected.conf"

printf 'NoNewPrivs:\t1\n' > "$test_work/proc-status"
expect_failure "$digest" --apply
[[ ! -s "$test_work/calls" ]]
grep -Fq 'Use an administrator shell with NoNewPrivs=0' "$test_work/output"
printf 'NoNewPrivs:\t0\n' > "$test_work/proc-status"

printf '[Service]\nNoNewPrivileges=no\n' > "$repair"
XEAS_BOOTSTRAP_TEST_REQUIRE_DROPIN=1
(
  exec 8>>"$state_dir/.apply.lock"
  flock -xn 8
  expect_failure "$digest" --apply
  [[ ! -s "$test_work/calls" && -f "$repair" ]]
  grep -Fq 'already using the installer lock' "$test_work/output"
)

XEAS_BOOTSTRAP_TEST_RPM_FAILURE=1
expect_failure "$digest" --apply
[[ $(< "$test_work/calls") == $'rpm test\nrpm upgrade' ]]
[[ -f "$repair" && "$(< "$test_work/installed")" == 'xe-antishell|0|0.1.0|32.el10|x86_64' ]]

XEAS_BOOTSTRAP_TEST_RPM_FAILURE=0
: > "$test_work/calls"
expect_success "$digest" --apply
[[ $(< "$test_work/calls") == $'rpm test\nrpm upgrade\nreload\nrestart agent' ]]
[[ ! -e "$repair" && "$(< "$test_work/installed")" == "$XEAS_BOOTSTRAP_TEST_TARGET" ]]

: > "$test_work/calls"
expect_success "$digest" --apply
[[ ! -s "$test_work/calls" ]]
grep -Fq 'RPM 33 is already running' "$test_work/output"
printf 'RPM updater bootstrap checks passed using a disposable fixture.\n'

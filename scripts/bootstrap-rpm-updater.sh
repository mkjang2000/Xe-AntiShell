#!/usr/bin/env bash
# One-time, host-local bootstrap for existing SELinux-enforcing RPM agents.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin

bootstrap_fail() { printf 'bootstrap-rpm-updater: %s\n' "$*" >&2; return 1; }

bootstrap_secure_root_path() {
  local path=$1 kind=$2 mode
  [[ ! -L "$path" && "$(/usr/bin/stat -c '%u' -- "$path")" == 0 ]] || return 1
  if [[ "$kind" == directory ]]; then [[ -d "$path" ]] || return 1
  else [[ -f "$path" ]] || return 1
  fi
  mode=$(/usr/bin/stat -c '%a' -- "$path") || return 1
  (( (8#$mode & 8#22) == 0 ))
}

bootstrap_verify_digest() {
  local actual
  actual=$(sha256sum < "$1") || return 1
  [[ "${actual%% *}" == "$2" ]]
}

bootstrap_check_unit() {
  local state
  state=$(systemctl show sentinel-updater.service -p LoadState -p FragmentPath -p DropInPaths -p NoNewPrivileges) || return 1
  [[ "$state"$'\n' == *$'LoadState=loaded\n'* ]] || return 1
  [[ "$state"$'\n' == *"FragmentPath=$1"$'\n'* ]] || return 1
  [[ "$state"$'\n' == *"DropInPaths=$2"$'\n'* ]] || return 1
  if [[ "$3" == fixed ]]; then
    [[ "$state"$'\n' == *$'NoNewPrivileges=no\n'* ]] || return 1
  fi
}

bootstrap_no_new_privileges() {
  awk '/^NoNewPrivs:/ { found=1; allowed=($2==0) } END { exit !(found && allowed) }' /proc/$$/status
}

bootstrap_running() {
  local status
  status=$(timeout 4s /usr/bin/sentinel status) &&
    grep -Fxq "Version: 0.1.0-33.el$1.x86_64" <<< "$status" &&
    grep -Fxq 'Health: healthy' <<< "$status"
}

bootstrap_main() (
  if [[ "${1:-}" == -h || "${1:-}" == --help ]]; then
    printf 'Usage: sudo scripts/bootstrap-rpm-updater.sh RPM PUBLISHER_VERIFIED_SHA256 [--apply]\n'
    return
  fi
  if (( $# < 2 || $# > 3 )) || [[ "${3:-}" != '' && "$3" != --apply ]]; then
    bootstrap_fail 'Expected RPM, its verified SHA-256 and optionally --apply.'
    return 1
  fi
  local source=$1 digest=$2 action=${3:-} stage='' distro major target installed dropin='' attempt
  local vendor=/usr/lib/systemd/system/sentinel-updater.service
  local override=/etc/systemd/system/sentinel-updater.service.d/90-rpm-selinux.conf
  local state_dir=/var/lib/xe-antishell/updates
  local format='%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}'
  (( EUID == 0 )) || bootstrap_fail 'Run through the existing root administration channel.'
  umask 077
  [[ "$digest" =~ ^[0-9a-f]{64}$ && -f "$source" && ! -L "$source" ]] || bootstrap_fail 'Expected a regular RPM and a lowercase SHA-256 digest.'
  distro=$(awk -F'[="]+' '/^ID=/ {print $2; exit}' /etc/os-release)
  major=$(awk -F'[=."]+' '/^VERSION_ID=/ {print $2; exit}' /etc/os-release)
  [[ "$distro" =~ ^(rhel|rocky|almalinux|centos)$ && ( "$major" == 9 || "$major" == 10 ) ]] &&
    [[ "$(uname -m)" == x86_64 ]] || bootstrap_fail 'Expected EL9 or EL10 x86_64.'
  [[ "$(getenforce)" == Enforcing ]] || bootstrap_fail 'This bootstrap is for a host running SELinux Enforcing.'
  target="xe-antishell|0|0.1.0|33.el$major|x86_64"
  bootstrap_verify_digest "$source" "$digest" || bootstrap_fail 'RPM SHA-256 differs from the verified publisher artifact.'
  [[ "$(rpm -qp --qf "$format" -- "$source")" == "$target" ]] || bootstrap_fail 'Unexpected RPM 33 platform or identity.'
  installed=$(rpm -q --qf "$format" xe-antishell)
  if [[ "$installed" != "$target" ]]; then
    [[ "$installed" =~ ^xe-antishell\|0\|0\.1\.0\|(2[3-9]|3[012])\.el$major\|x86_64$ ]] || bootstrap_fail 'Installed package is outside the supported bootstrap range.'
  fi

  if [[ -e "$override" || -L "$override" ]]; then
    bootstrap_secure_root_path "${override%/*}" directory &&
      bootstrap_secure_root_path "$override" file &&
      cmp -s "$override" <(printf '[Service]\nNoNewPrivileges=no\n') ||
      bootstrap_fail 'The local drop-in differs from the known temporary repair.'
    dropin=$override
  fi
  bootstrap_check_unit "$vendor" "$dropin" original || bootstrap_fail 'Expected the packaged updater and only the known temporary drop-in.'
  if [[ "$action" != --apply ]]; then
    printf 'Bootstrap preflight passed for EL%s. Installed package: %s\n' "$major" "$installed"
    return
  fi
  if [[ "$installed" == "$target" && -z "$dropin" ]] &&
     bootstrap_check_unit "$vendor" '' fixed && bootstrap_running "$major"; then
    printf 'RPM 33 is already running and the packaged updater is ready.\n'
    return
  fi

  bootstrap_no_new_privileges || bootstrap_fail 'Use an administrator shell with NoNewPrivs=0.'
  bootstrap_secure_root_path "${state_dir%/*}" directory || bootstrap_fail 'Agent data directory is missing or unsafe.'
  if [[ ! -e "$state_dir" && ! -L "$state_dir" ]]; then
    mkdir -m 0700 -- "$state_dir" || [[ -d "$state_dir" ]]
  fi
  bootstrap_secure_root_path "$state_dir" directory || bootstrap_fail 'Updater state directory is missing or unsafe.'
  if [[ -e "$state_dir/.apply.lock" || -L "$state_dir/.apply.lock" ]]; then
    bootstrap_secure_root_path "$state_dir/.apply.lock" file || bootstrap_fail 'Updater lock path is unsafe.'
  fi
  exec 9>>"$state_dir/.apply.lock"
  flock -xn 9 || bootstrap_fail 'A managed update is already using the installer lock.'

  stage=$(mktemp -d "$state_dir/.rpm-bootstrap.XXXXXXXX")
  trap 'rm -rf -- "$stage"' EXIT
  cp -- "$source" "$stage/agent.rpm"
  bootstrap_verify_digest "$stage/agent.rpm" "$digest" || bootstrap_fail 'RPM contents changed during staging.'
  if [[ "$installed" != "$target" ]]; then
    rpm -Uvh --test -- "$stage/agent.rpm"
    rpm -Uvh -- "$stage/agent.rpm"
  fi
  [[ "$(rpm -q --qf "$format" xe-antishell)" == "$target" ]] || bootstrap_fail 'RPM 33 was not installed.'

  # Confirm the fixed vendor file before discarding the exact temporary drop-in.
  bootstrap_secure_root_path "$vendor" file && grep -Fxq 'NoNewPrivileges=false' "$vendor" ||
    bootstrap_fail 'The installed vendor unit lacks the SELinux transition setting.'
  if [[ -n "$dropin" ]]; then
    bootstrap_secure_root_path "$dropin" file &&
      cmp -s "$dropin" <(printf '[Service]\nNoNewPrivileges=no\n') ||
      bootstrap_fail 'The temporary drop-in changed during installation.'
    rm -- "$dropin"
  fi
  systemctl daemon-reload
  bootstrap_check_unit "$vendor" '' fixed || bootstrap_fail 'The effective updater unit is not ready for managed updates.'
  systemctl restart sentineld.service
  for ((attempt=0; attempt<45; attempt++)); do
    if bootstrap_running "$major"; then
      printf 'RPM 33 is running and the packaged updater is ready. Verify this host in Central.\n'
      return
    fi
    sleep 1
  done
  bootstrap_fail 'RPM 33 is installed. The agent did not report healthy before the deadline.'
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  bootstrap_main "$@"
fi

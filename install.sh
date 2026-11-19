#!/usr/bin/env bash
# Install a local, published or source-built agent RPM.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin

XEAS_OS_RELEASE_FILE=/etc/os-release
XEAS_WEB_AUTH_FILE=/etc/xe-antishell/web-auth.json
XEAS_WEB_PASSWORD_FILE=/root/xe-antishell-web-initial-password.txt
XEAS_CENTRAL_STATE_DIR=/var/lib/xe-antishell-central
XEAS_INSTALL_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
XEAS_BUILD_SCRIPT=$XEAS_INSTALL_ROOT/scripts/build-rpm.sh
XEAS_WIZARD_SCRIPT=$XEAS_INSTALL_ROOT/packaging/install-wizard.sh
XEAS_RECOVERY_FILE=/root/xe-antishell-offline-recovery
XEAS_TETRAGON_SCRIPT=$XEAS_INSTALL_ROOT/packaging/install-tetragon.sh
if [[ -f "$XEAS_TETRAGON_SCRIPT" && ! -L "$XEAS_TETRAGON_SCRIPT" ]]; then
  source "$XEAS_TETRAGON_SCRIPT"
fi

usage() {
  cat <<'USAGE'
Usage: sudo ./install.sh (--rpm PATH | --build) [OPTIONS]
       sudo ./install.sh                 Korean interactive setup on a terminal
       sudo ./install.sh --tetragon-only  Add verified collection to an installed agent

Choose one package source:
  --rpm PATH              Local xe-antishell RPM (no package download)
  --build                 Build this source checkout with scripts/build-rpm.sh

The wizard offers a verified GitHub release on Rocky Linux 9/10 x86_64 if
no compatible local RPM or source build is available.

Optional central enrollment with an installation code:
  --enrollment-file PATH  Root-owned owner-only installation code file
  --recovery-file PATH    Offline recovery file (default: /root/xe-antishell-offline-recovery)

Legacy central enrollment (supply all five together; cannot mix with --enrollment-file):
  --central HTTPS_URL     Trusted central server URL
  --agent-id ID           Unique agent identifier
  --ca-file PATH          Already trusted central CA certificate
  --token-file PATH       Root-owned owner-only enrollment token file
  --recovery-file PATH    Root-only offline recovery file to create or reuse

Other options:
  --with-tetragon         Install and verify the pinned Tetragon process collector
  --tetragon-only         Configure Tetragon only; no RPM transaction or enrollment
  --tetragon-archive PATH Use the verified v1.8.0 amd64 archive offline (requires Tetragon)
  --enable-web            Initialize missing web credentials and start the panel
  -h, --help              Show this help

The installer preserves existing configuration and credentials. It does not
change firewall rules or enable enforcement. Scripted Tetragon setup is opt-in;
the terminal wizard offers it by default. Setup downloads the pinned official
release and may install Python3/PyYAML dependencies through dnf. An existing
unrelated Tetragon installation requires manual integration.
RPM dependencies must already be available. OS/version and kernel capabilities
need their own validation; a successful install does not certify OS support.
--build additionally requires the documented Go, make and rpmbuild toolchain.
This installer installs only the agent. A legacy bundled central deployment
must first use the documented migration with both agent and central RPMs in
one reviewed RPM transaction; this installer stops before that upgrade.
USAGE
}

fail() { printf 'install.sh: %s\n' "$*" >&2; return 1; }
warn() { printf 'install.sh: warning: %s\n' "$*" >&2; }

require_root() {
  (( EUID == 0 )) || fail 'Run this installer as root.'
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command is missing: $1"
}

check_regular_file() {
  [[ -f "$1" && -r "$1" && ! -L "$1" ]] || fail "Expected a readable regular file, not a symlink: $1"
}

check_private_file() {
  local owner mode
  check_regular_file "$1" || return 1
  owner=$(stat -c '%u' -- "$1") || return 1
  mode=$(stat -c '%a' -- "$1") || return 1
  if [[ "$owner" != 0 ]]; then
    fail "Secret file must be owned by root: $1"; return 1
  fi
  (( (8#$mode & 8#77) == 0 )) || fail "Secret file must have owner-only permissions (for example 0600): $1"
}

check_file_size() {
  local size
  size=$(stat -c '%s' -- "$1") || return 1
  if [[ ! "$size" =~ ^[0-9]+$ ]] || (( size < 1 || size > $2 )); then
    fail "Input file is empty or exceeds its size limit: $1"; return 1
  fi
}

detect_os() {
  local os_id os_version major
  read_install_os
  major=${os_version%%.*}
  printf 'Detected OS: %s %s. Runtime probes determine available features.\n' "$os_id" "$os_version"
  case "$os_id:$major" in
    rocky:8|rocky:9|rocky:10|rhel:8|rhel:9|rhel:10|almalinux:8|almalinux:9|almalinux:10|centos:7) ;;
    *) warn 'This OS is outside the intended Rocky/RHEL/Alma 8–10 or CentOS 7 families. RPM compatibility is unverified.' ;;
  esac
  if [[ "$os_id:$major" == centos:7 ]]; then
    warn 'The packaged web service uses modern systemd credentials; CentOS 7 needs a compatible web service unit before web use.'
  fi
}

read_install_os() {
  local key value
  os_id=unknown os_version=unknown
  if [[ -r "$XEAS_OS_RELEASE_FILE" ]]; then
    while IFS='=' read -r key value; do
      value=${value#\"}; value=${value%\"}
      value=${value#\'}; value=${value%\'}
      case "$key" in ID) os_id=$value ;; VERSION_ID) os_version=$value ;; esac
    done < "$XEAS_OS_RELEASE_FILE"
  fi
}

# Keep the release digests and helper revision in the script distributed to users.
# The downloaded SHA256SUMS file is not a trust anchor for a first installation.
fetch_install_file() {
  local url=$1 file=$2 expected=$3 limit=$4 actual
  require_command curl && require_command sha256sum || return 1
  curl --disable --fail --silent --show-error --location --proto '=https' \
    --proto-redir '=https' --connect-timeout 15 --max-time 180 \
    --max-filesize "$limit" --output "$file" -- "$url" || {
    fail "Download failed: $url"; return 1
  }
  check_file_size "$file" "$limit" || return 1
  actual=$(sha256sum < "$file") || return 1
  [[ "${actual%% *}" == "$expected" ]] || fail "SHA-256 verification failed: $url"
}

prepare_download_directory() {
  if [[ -z "$download_directory" ]]; then
    download_directory=$(mktemp -d /tmp/xeas-install-download.XXXXXX) || return 1
  fi
}

fetch_install_helper() {
  local path=$1 expected=$2
  local revision=ac93457cc5a3f0567aa7c4b1e395ea6142774718
  prepare_download_directory || return 1
  mkdir -p -- "$download_directory/${path%/*}" || return 1
  fetch_install_file "https://raw.githubusercontent.com/mkjang2000/Xe-AntiShell/$revision/$path" \
    "$download_directory/$path" "$expected" 262144
}

load_install_wizard() {
  if [[ ! -e "$XEAS_WIZARD_SCRIPT" && ! -L "$XEAS_WIZARD_SCRIPT" ]]; then
    fetch_install_helper packaging/install-wizard.sh 517386a629ea51e57cff4ccd9dc1f2fc0024fd601deb6fedc459e1118d32729a || return 1
    XEAS_WIZARD_SCRIPT=$download_directory/packaging/install-wizard.sh
  fi
  check_regular_file "$XEAS_WIZARD_SCRIPT" || return 1
  source "$XEAS_WIZARD_SCRIPT"
}

prepare_wizard_release() {
  local os_id os_version major architecture digest name metadata
  local -a wizard_packages=()
  require_command rpm && require_command uname || return 1
  architecture=$(uname -m) || return 1
  wizard_package_choices "$architecture" || return 1
  if (( ${#wizard_packages[@]} )) ||
     [[ -f "$XEAS_INSTALL_ROOT/go.mod" && -f "$XEAS_INSTALL_ROOT/Makefile" && -x "$XEAS_BUILD_SCRIPT" ]]; then
    return 0
  fi
  read_install_os
  major=${os_version%%.*}
  case "$os_id:$major:$architecture" in
    rocky:9:x86_64) digest=79e20b44addae3947b77d85fb3a1f7dee2050bf99efbcc401eeedeffcfb44a15 ;;
    rocky:10:x86_64) digest=43314708a6e03d5d872aaf73f74aa72456335bcfa20ec4e88cf50fa47763b638 ;;
    *)
      warn 'Automatic RPM download supports Rocky Linux 9/10 x86_64. Select a local RPM.'
      return 0 ;;
  esac
  prepare_download_directory || return 1
  name=xe-antishell-0.1.0-37.el$major.x86_64.rpm
  printf 'Rocky Linux %s용 GitHub 릴리즈를 확인합니다. (%s)\n' "$major" "$name" >&2
  fetch_install_file "https://github.com/mkjang2000/Xe-AntiShell/releases/download/v0.1.0-r37/$name" \
    "$download_directory/$name" "$digest" 67108864 || return 1
  metadata=$(rpm -qp --queryformat '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}' -- "$download_directory/$name") || return 1
  [[ "$metadata" == "xe-antishell|0|0.1.0|37.el$major|x86_64" ]] || {
    fail 'Downloaded RPM metadata does not match the selected release.'; return 1
  }
  # The existing wizard lists RPMs adjacent to the installer root.
  XEAS_INSTALL_ROOT=$download_directory
}

load_downloaded_tetragon_helper() {
  local path digest
  if [[ -e "$XEAS_TETRAGON_SCRIPT" || -L "$XEAS_TETRAGON_SCRIPT" ]]; then
    return 0
  fi
  while read -r path digest; do
    fetch_install_helper "$path" "$digest" || return 1
  done <<'PINS'
    packaging/install-tetragon.sh 1b1e864b33ddee3c19902276038f94e4036bd5697243564b413cf067504ce198
    packaging/tetragon/artifacts.py 18b1d58756d39901a00abc3805ca185b2434d45376948d98ce5bc6d691793b71
    packaging/tetragon/observation_policies.py cd8e04a2c71a517ba3b8efae5f05179ab34eaee715ed54ef368dad0ed8fb0276
    packaging/tetragon/observation_state.py 388ba4e680cdfc17e5a4844480560270450de690eb18419c9cc8f4832e454ed3
    packaging/tetragon/setup.py 4af42ae43519f7a6c5a4789a692acb39c1daa60b12c5c6d11d9525ac8116c4b9
    packaging/tetragon/setup_common.py 1e296ac25d7b96399a4eeb8e0bceff0acb6abbb4b40a7a4f363d42517a9952e8
    packaging/tetragon/setup_config.py 632b5e84c85c1819e19bdccfe82da35a565b33e314cfafbeb3915ccb447806ae
    packaging/tetragon/setup_runtime.py 4cdb8f496bbc6e321d029fd6745123e927fd995ede7ffcd4b2d8632c6aadff6b
    packaging/tetragon/setup_services.py db8201998c0698900067339a13b652cad951e17c3be7601d984ba749fd4f08c9
    packaging/tetragon/setup_state.py 244bd74716bc6212cccddc90c58f83dcaea34dc3f0389e61d1957a7378e67f8a
    packaging/tetragon/setup_workflow.py 8a6216228b6467523f07f9977ea7651ec886ec80c829056ba2d7891288b99b83
PINS
  XEAS_INSTALL_ROOT=$download_directory
  XEAS_TETRAGON_SCRIPT=$download_directory/packaging/install-tetragon.sh
  source "$XEAS_TETRAGON_SCRIPT"
}

wait_for_agent() {
  local attempt
  for (( attempt=0; attempt<30; attempt++ )); do
    if sentinel status >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail 'The agent API did not become ready within 30 seconds. Check journalctl -u sentineld.'
}

systemd_manager_version() {
  local output
  output=$(systemctl show --property=Version --no-pager) || {
    fail 'A running systemd system manager is required for installation.'; return 1
  }
  if [[ ! "$output" =~ ^Version=([0-9]+) ]]; then
    fail 'Cannot identify the running systemd manager version.'; return 1
  fi
  printf '%s\n' "${BASH_REMATCH[1]}"
}

check_web_preflight() {
  if (( 10#$1 < 247 )); then
    fail 'The packaged web service requires systemd 247 or newer for LoadCredential. Install the agent without --enable-web on this host.'; return 1
  fi
  if [[ -e "$XEAS_WEB_AUTH_FILE" || -L "$XEAS_WEB_AUTH_FILE" ]]; then
    check_private_file "$XEAS_WEB_AUTH_FILE" || return 1
    check_file_size "$XEAS_WEB_AUTH_FILE" 16384 || return 1
  elif [[ -e "$XEAS_WEB_PASSWORD_FILE" || -L "$XEAS_WEB_PASSWORD_FILE" ]]; then
    fail 'An initial password file already exists without a matching web authentication file. Preserve it and resolve the incomplete setup before retrying.'; return 1
  fi
  if [[ -e "$XEAS_WEB_PASSWORD_FILE" || -L "$XEAS_WEB_PASSWORD_FILE" ]]; then
    check_private_file "$XEAS_WEB_PASSWORD_FILE" || return 1
    check_file_size "$XEAS_WEB_PASSWORD_FILE" 4096 || return 1
  fi
}

build_local_rpm() {
  "$XEAS_BUILD_SCRIPT" --output-dir "$1"
}

check_legacy_central_preflight() {
  local installed_files path bundled=false
  [[ -n "$1" ]] || return 0
  installed_files=$(rpm -q --list xe-antishell 2>/dev/null) || {
    fail 'Cannot inspect the installed xe-antishell file list before upgrade.'; return 1
  }
  while IFS= read -r path; do
    case "$path" in
      /usr/sbin/sentinel-central|/usr/lib/systemd/system/sentinel-central.service|/lib/systemd/system/sentinel-central.service)
        bundled=true ;;
    esac
  done <<< "$installed_files"
  [[ "$bundled" == true ]] || return 0
  if [[ -e "$XEAS_CENTRAL_STATE_DIR" || -L "$XEAS_CENTRAL_STATE_DIR" ]] || \
      systemctl is-active --quiet sentinel-central.service || \
      systemctl is-enabled --quiet sentinel-central.service; then
    fail 'This host has a legacy central deployment owned by the bundled xe-antishell RPM. Preserve the central state and follow the documented migration: upgrade xe-antishell and install xe-antishell-central together in one reviewed RPM transaction. An agent-only upgrade would remove the central binary and unit.'
    return 1
  fi
}

check_web_active() {
  # Type=simple can briefly be active before credential loading or bind fails.
  systemctl is-active --quiet sentinel-web.service || return 1
  sleep 1
  systemctl is-active --quiet sentinel-web.service
}

enable_web() {
  require_command sentinel-web || return 1
  if [[ -L "$XEAS_WEB_AUTH_FILE" ]]; then
    fail 'Refusing a symlink at the web authentication path.'
    return 1
  fi
  if [[ ! -e "$XEAS_WEB_AUTH_FILE" ]]; then
    sentinel-web init-auth --file "$XEAS_WEB_AUTH_FILE" \
      --initial-password-file "$XEAS_WEB_PASSWORD_FILE" --username admin || return 1
  else
    check_regular_file "$XEAS_WEB_AUTH_FILE" || return 1
    printf 'Preserving existing web administrator credentials.\n'
  fi
  chown root:root "$XEAS_WEB_AUTH_FILE" || return 1
  chmod 0600 "$XEAS_WEB_AUTH_FILE" || return 1
  systemctl enable --now sentinel-web.service || return 1
  check_web_active || {
    fail 'The web service is not active. Check journalctl -u sentinel-web.'; return 1
  }
  printf 'Web panel enabled. Initial password, when newly created: %s\n' "$XEAS_WEB_PASSWORD_FILE"
}

restore_install_terminal() {
  if [[ -n "${wizard_tty_state:-}" ]]; then
    stty "$wizard_tty_state" 2>/dev/null || return 1
    wizard_tty_state=''
  fi
}

cleanup_install() {
  restore_install_terminal || :
  if [[ -n "${wizard_code_file:-}" ]]; then rm -f -- "$wizard_code_file" || :; fi
  if [[ -n "${build_directory:-}" ]]; then rm -rf -- "$build_directory" || :; fi
  if [[ -n "${download_directory:-}" ]]; then rm -rf -- "$download_directory" || :; fi
}

run_install() {
  local saved_signal_traps exit_status
  saved_signal_traps=$(trap -p INT TERM HUP)
  # Keep the calling shell alive until main's subshell finishes EXIT cleanup.
  trap ':' INT TERM HUP
  main "$@"
  exit_status=$?
  trap - INT TERM HUP
  eval "$saved_signal_traps"
  return "$exit_status"
}

main() (
  local rpm_path='' central_url='' agent_id='' ca_file='' token_file='' recovery_file='' enrollment_file=''
  local with_web=false with_build=false with_tetragon=false tetragon_only=false tetragon_archive='' tetragon_python=''
  local option value supplied=0 package_name recovery_parent candidate_nevra installed_nevra manager_version
  local build_directory='' download_directory='' wizard_code_file='' wizard_tty_state='' interactive=false
  local initial_install_root=$XEAS_INSTALL_ROOT
  local nevra_format='%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}'
  trap cleanup_install EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  if (( $# == 0 )); then
    [[ -t 0 && -t 1 ]] || { fail '인자 없는 설치는 터미널에서 실행하세요. 자동 설치는 --rpm 또는 --build 옵션과 --help를 사용하세요.'; return 1; }
    require_root || return 1
    umask 077
    load_install_wizard || return 1
    prepare_wizard_release || return 1
    run_install_wizard || return 1
    XEAS_INSTALL_ROOT=$initial_install_root
    interactive=true
  fi
  while (( $# )); do
    option=$1
    case "$option" in
      -h|--help) usage; return 0 ;;
      --enable-web) with_web=true; shift ;;
      --build) with_build=true; shift ;;
      --with-tetragon) with_tetragon=true; shift ;;
      --tetragon-only) tetragon_only=true; with_tetragon=true; shift ;;
      --rpm|--central|--agent-id|--ca-file|--token-file|--recovery-file|--enrollment-file|--tetragon-archive)
        if (( $# < 2 )) || [[ -z "$2" || "$2" == --* ]]; then
          fail "Missing value for $option"; return 1
        fi
        value=$2
        case "$option" in
          --rpm) rpm_path=$value ;; --central) central_url=$value ;;
          --agent-id) agent_id=$value ;; --ca-file) ca_file=$value ;;
          --token-file) token_file=$value ;; --recovery-file) recovery_file=$value ;;
          --enrollment-file) enrollment_file=$value ;;
          --tetragon-archive) tetragon_archive=$value ;;
        esac
        shift 2 ;;
      *) fail "Unknown option: $option"; return 1 ;;
    esac
  done
  if [[ "$tetragon_only" == true ]]; then
    if [[ -n "$rpm_path$central_url$agent_id$ca_file$token_file$recovery_file$enrollment_file" || "$with_build" == true || "$with_web" == true ]]; then
      fail '--tetragon-only cannot be combined with RPM/build, enrollment, recovery or web setup.'; return 1
    fi
  elif [[ "$with_build" == true && -n "$rpm_path" ]] || [[ "$with_build" == false && -z "$rpm_path" ]]; then
    fail 'Choose exactly one of --rpm PATH or --build. Use --help for examples.'; return 1
  fi
  if [[ -n "$tetragon_archive" && "$with_tetragon" != true ]]; then
    fail '--tetragon-archive requires --with-tetragon or --tetragon-only.'; return 1
  fi
  for value in "$central_url" "$agent_id" "$ca_file" "$token_file"; do
    if [[ -n "$value" ]]; then (( supplied+=1 )); fi
  done
  if [[ -n "$enrollment_file" ]]; then
    (( supplied == 0 )) || { fail '--enrollment-file cannot be mixed with --central --agent-id --ca-file or --token-file.'; return 1; }
    recovery_file=${recovery_file:-$XEAS_RECOVERY_FILE}
  else
    if [[ -n "$recovery_file" ]]; then (( supplied+=1 )); fi
    if (( supplied != 0 && supplied != 5 )); then
      fail 'Central enrollment requires all five of --central --agent-id --ca-file --token-file --recovery-file.'
      return 1
    fi
  fi
  require_root || return 1
  umask 077
  for value in rpm systemctl stat; do require_command "$value" || return 1; done
  if [[ "$with_build" == true ]]; then
    for value in mktemp rm; do require_command "$value" || return 1; done
    check_regular_file "$XEAS_BUILD_SCRIPT" || return 1
    [[ -x "$XEAS_BUILD_SCRIPT" ]] || { fail 'The RPM build helper must be executable.'; return 1; }
  elif [[ "$tetragon_only" != true ]]; then
    check_regular_file "$rpm_path" || return 1
  fi
  if [[ -n "$tetragon_archive" ]]; then check_regular_file "$tetragon_archive" || return 1; fi
  if [[ -n "$enrollment_file" ]]; then
    check_private_file "$enrollment_file" || return 1
    check_file_size "$enrollment_file" 16384 || return 1
  fi
  if (( supplied )); then
    [[ "$central_url" =~ ^https://[^/?#@[:space:]]+/?$ ]] || { fail '--central must be an HTTPS origin without credentials, query, or fragment.'; return 1; }
    [[ "$agent_id" =~ ^[a-zA-Z0-9_.:-]{1,128}$ ]] || { fail 'Invalid --agent-id.'; return 1; }
    check_regular_file "$ca_file" || return 1
    check_file_size "$ca_file" 65536 || return 1
    check_private_file "$token_file" || return 1
    check_file_size "$token_file" 4096 || return 1
  fi
  if (( supplied )) || [[ -n "$enrollment_file" ]]; then
    if [[ -e "$recovery_file" || -L "$recovery_file" ]]; then
      check_private_file "$recovery_file" || return 1
      check_file_size "$recovery_file" 4096 || return 1
    else
      recovery_parent=$(dirname -- "$recovery_file")
      [[ -d "$recovery_parent" && -w "$recovery_parent" ]] || { fail 'The recovery file parent directory must already exist and be writable.'; return 1; }
    fi
  fi
  manager_version=$(systemd_manager_version) || return 1
  if [[ "$with_web" == true ]]; then check_web_preflight "$manager_version" || return 1; fi
  installed_nevra=$(rpm -q --queryformat "$nevra_format" xe-antishell 2>/dev/null) || installed_nevra=''
  check_legacy_central_preflight "$installed_nevra" || return 1
  if [[ "$with_tetragon" == true ]]; then
    load_downloaded_tetragon_helper || return 1
    check_regular_file "$XEAS_TETRAGON_SCRIPT" || return 1
    check_tetragon_preflight || return 1
  fi
  if [[ "$interactive" == false ]]; then detect_os; fi
  if [[ "$tetragon_only" == true ]]; then
    [[ -n "$installed_nevra" ]] || { fail '--tetragon-only requires an installed xe-antishell agent.'; return 1; }
    require_command sentinel || return 1
    systemctl is-active --quiet sentineld.service || { fail 'Start sentineld before adding Tetragon.'; return 1; }
    wait_for_agent || return 1
    install_tetragon || return 1
    return 0
  fi
  if [[ "$with_build" == true ]]; then
    build_directory=$(mktemp -d /tmp/xeas-install-build.XXXXXX) || return 1
    printf 'Building the supplied source checkout before installing packages.\n'
    build_local_rpm "$build_directory" || return 1
    shopt -s nullglob
    local artifacts=("$build_directory"/*.rpm)
    if (( ${#artifacts[@]} != 1 )); then
      fail 'The build helper must produce exactly one RPM in its output directory.'; return 1
    fi
    rpm_path=${artifacts[0]}
    check_regular_file "$rpm_path" || return 1
  fi
  package_name=$(rpm -qp --queryformat '%{NAME}' -- "$rpm_path") || return 1
  [[ "$package_name" == xe-antishell ]] || { fail 'The supplied RPM is not the xe-antishell package.'; return 1; }
  candidate_nevra=$(rpm -qp --queryformat "$nevra_format" -- "$rpm_path") || return 1
  if [[ "$installed_nevra" == "$candidate_nevra" ]]; then
    printf 'The same RPM version and architecture are installed; continuing setup.\n'
  else
    printf 'Installing supplied local RPM.\n'
    rpm -Uvh -- "$rpm_path" || return 1
  fi
  systemctl daemon-reload || return 1
  systemctl enable --now sentineld.service || return 1
  require_command sentinel || return 1
  wait_for_agent || return 1
  if [[ -n "$enrollment_file" ]]; then
    printf '보호된 설치 코드 파일로 중앙 서버에 등록합니다.\n'
    sentinel managed enroll-code --code-file "$enrollment_file" --recovery-file "$recovery_file" || return 1
    printf '비상 제거에 필요한 복구 파일을 이 호스트 외부에 안전하게 백업하세요: %s\n' "$recovery_file"
  elif (( supplied )); then
    printf 'Enrolling with the central server using protected file inputs.\n'
    sentinel managed enroll --central "$central_url" --agent-id "$agent_id" \
      --ca-file "$ca_file" --token-file "$token_file" --recovery-file "$recovery_file" || return 1
    printf 'Preserve the recovery file securely outside this host for emergency removal.\n'
  fi
  if [[ "$with_tetragon" == true ]]; then install_tetragon || return 1; fi
  if [[ "$with_web" == true ]]; then enable_web || return 1; fi
  printf 'Package and agent API setup completed. Verify observed collection with sentinel capabilities and the monitoring panel.\n'
  if [[ "$with_tetragon" != true ]]; then
    printf 'Tetragon setup was not selected. Run --tetragon-only later to add and verify process collection.\n'
  fi
  printf 'Audit-rule activation and detection accuracy validation require separate host review.\n'
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then run_install "$@"; fi

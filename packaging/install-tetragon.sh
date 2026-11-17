#!/usr/bin/env bash
# Sourced by install.sh. Host changes happen only after explicit Tetragon opt-in.

select_tetragon_python() {
  local candidate candidate_path
  tetragon_python=''
  for candidate in python3 python3.12 python3.11 python3.10 python3.9; do
    candidate_path=$(type -P "$candidate") || continue
    [[ "$candidate_path" == /* && -f "$candidate_path" && -x "$candidate_path" ]] || continue
    if "$candidate_path" -c 'import sys, yaml; sys.exit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
      tetragon_python=$candidate_path
      return 0
    fi
  done
  return 1
}

check_tetragon_preflight() {
  local helper
  require_command uname || return 1
  [[ $(uname -m) == x86_64 ]] || {
    fail 'Automatic Tetragon setup currently supports x86_64 only.'; return 1
  }
  [[ -r /sys/kernel/btf/vmlinux ]] || {
    fail 'Kernel BTF is unavailable. Tetragon setup cannot proceed; retain the current collector and review audit fallback.'; return 1
  }
  check_regular_file "$XEAS_TETRAGON_SCRIPT" || return 1
  check_regular_file "$XEAS_INSTALL_ROOT/packaging/tetragon/setup.py" || return 1
  for helper in "$XEAS_INSTALL_ROOT"/packaging/tetragon/*.py; do
    check_regular_file "$helper" || return 1
  done
  if [[ -n "$tetragon_archive" ]]; then check_regular_file "$tetragon_archive" || return 1; fi
  if ! select_tetragon_python; then
    require_command dnf || {
      fail 'Install Python 3.9+ and PyYAML before Tetragon setup on this distribution.'; return 1
    }
  fi
}

install_tetragon() {
  local key value os_major=''
  local -a options=()
  local -a packages=(python3 python3-pyyaml)
  if ! select_tetragon_python; then
    if [[ -r "$XEAS_OS_RELEASE_FILE" ]]; then
      while IFS='=' read -r key value; do
        [[ "$key" == VERSION_ID ]] || continue
        value=${value#\"}; value=${value%\"}; value=${value#\'}; value=${value%\'}
        os_major=${value%%.*}
      done < "$XEAS_OS_RELEASE_FILE"
    fi
    if [[ "$os_major" == 8 ]]; then packages=(python39 python39-pyyaml); fi
    printf 'Tetragon 설치에 필요한 Python3/PyYAML 패키지를 설치합니다.\n'
    dnf -y install "${packages[@]}" || return 1
  fi
  select_tetragon_python || {
    fail 'Python 3.9+ with PyYAML is required for Tetragon setup.'; return 1
  }
  if [[ -n "$tetragon_archive" ]]; then options+=(--archive "$tetragon_archive"); fi
  "$tetragon_python" "$XEAS_INSTALL_ROOT/packaging/tetragon/setup.py" "${options[@]}"
}

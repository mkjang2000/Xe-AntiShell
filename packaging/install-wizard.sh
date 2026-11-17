#!/usr/bin/env bash
# Sourced by install.sh only for its no-argument terminal workflow.

wizard_read() {
  printf '%s' "$1" >&2
  IFS= read -r "$2" || { fail '입력이 종료되어 설치를 취소했습니다.'; return 1; }
}

wizard_yes_no() {
  local answer
  while true; do
    wizard_read "$1" answer || return 1
    answer=${answer,,}
    case "${answer:-$2}" in
      y|yes) wizard_yes=true; return 0 ;;
      n|no) wizard_yes=false; return 0 ;;
      *) printf 'y 또는 n을 입력하세요.\n' >&2 ;;
    esac
  done
}

wizard_package_choices() {
  local candidate metadata name architecture release key value os_major=''
  local host_architecture=$1
  if [[ -r "$XEAS_OS_RELEASE_FILE" ]]; then
    while IFS='=' read -r key value; do
      if [[ "$key" == VERSION_ID ]]; then
        value=${value#\"}; value=${value%\"}; value=${value#\'}; value=${value%\'}
        os_major=${value%%.*}
      fi
    done < "$XEAS_OS_RELEASE_FILE"
  fi
  for candidate in "$XEAS_INSTALL_ROOT"/*.rpm "$XEAS_INSTALL_ROOT"/rpms/*.rpm "$XEAS_INSTALL_ROOT"/dist/rpm/*.rpm; do
    [[ -f "$candidate" && -r "$candidate" && ! -L "$candidate" ]] || continue
    metadata=$(rpm -qp --queryformat '%{NAME}|%{ARCH}|%{RELEASE}' -- "$candidate" 2>/dev/null) || continue
    IFS='|' read -r name architecture release <<< "$metadata"
    [[ "$name" == xe-antishell && ( "$architecture" == "$host_architecture" || "$architecture" == noarch ) ]] || continue
    if [[ "$os_major" =~ ^[0-9]+$ ]]; then
      [[ "$release" =~ (^|[.])el${os_major}([._]|$) ]] || continue
    fi
    wizard_packages+=("$candidate")
  done
}

wizard_installation_code() {
  # Disable tracing and automatic exports before any secret enters a variable.
  set +x
  set +a
  local installation_code='' input_character='' LC_ALL=C
  export -n installation_code input_character
  require_command mktemp || return 1
  require_command rm || return 1
  require_command stty || return 1
  wizard_tty_state=$(stty -g) || return 1
  stty -echo -icanon min 1 time 0 || return 1
  printf '중앙 관리 웹에서 발급한 xeas1. 설치 코드를 붙여 넣고 Enter를 누르세요.\n' >&2
  printf '설치 코드 (화면에 표시되지 않음): ' >&2
  # Single-character reads keep interrupt handling responsive during a paste.
  while true; do
    if ! IFS= read -r -n 1 input_character || [[ "$input_character" == $'\004' ]]; then
      printf '\n' >&2
      fail '입력이 종료되어 설치를 취소했습니다.'; return 1
    fi
    [[ -n "$input_character" ]] || break
    installation_code+=$input_character
    if (( ${#installation_code} > 16384 )); then
      unset installation_code input_character
      fail '설치 코드 길이가 제한을 초과했습니다.'; return 1
    fi
  done
  unset input_character
  restore_install_terminal || return 1
  printf '\n' >&2
  if [[ ! "$installation_code" =~ ^xeas1\.[A-Za-z0-9_-]+$ ]]; then
    unset installation_code
    fail '설치 코드 형식 또는 길이가 올바르지 않습니다. 중앙 웹에서 발급한 전체 설치 코드를 사용하세요.'; return 1
  fi
  wizard_code_file=$(mktemp /tmp/xeas-install-code.XXXXXX) || return 1
  printf '%s' "$installation_code" > "$wizard_code_file" || return 1
  unset installation_code
  enrollment_file=$wizard_code_file
  recovery_file=$XEAS_RECOVERY_FILE
}

run_install_wizard() {
  local host_architecture choice manual_choice build_choice='' index wizard_yes
  local -a wizard_packages=()
  require_command rpm || return 1
  require_command uname || return 1
  printf 'Xe-AntiShell 설치 안내\n\n1/7 운영체제 및 아키텍처 확인\n' >&2
  detect_os
  host_architecture=$(uname -m) || return 1
  printf '아키텍처: %s\n\n2/7 설치 패키지 선택\n' "$host_architecture" >&2
  wizard_package_choices "$host_architecture" || return 1
  for (( index=0; index<${#wizard_packages[@]}; index++ )); do
    printf '  %d) 로컬 RPM: %s\n' "$((index+1))" "${wizard_packages[index]}" >&2
  done
  manual_choice=$((${#wizard_packages[@]}+1))
  printf '  %d) RPM 경로 직접 입력\n' "$manual_choice" >&2
  if [[ -f "$XEAS_INSTALL_ROOT/go.mod" && -f "$XEAS_INSTALL_ROOT/Makefile" && -x "$XEAS_BUILD_SCRIPT" ]]; then
    build_choice=$((manual_choice+1))
    printf '  %d) 현재 소스에서 RPM 빌드 (Go, make, rpmbuild 필요)\n' "$build_choice" >&2
  fi
  if (( ${#wizard_packages[@]} == 0 )); then
    printf '현재 OS 버전과 아키텍처에 맞는 로컬 RPM을 찾지 못했습니다.\n' >&2
  fi
  while true; do
    wizard_read '설치 방법 선택 [1]: ' choice || return 1
    choice=${choice:-1}
    if [[ "$choice" == "$manual_choice" ]]; then
      wizard_read '설치할 RPM 경로: ' rpm_path || return 1
      check_regular_file "$rpm_path" || return 1
      break
    elif [[ -n "$build_choice" && "$choice" == "$build_choice" ]]; then
      with_build=true
      break
    elif [[ "$choice" =~ ^[1-9][0-9]{0,3}$ ]] && (( choice <= ${#wizard_packages[@]} )); then
      rpm_path=${wizard_packages[choice-1]}
      break
    fi
    printf '목록에 있는 번호를 입력하세요.\n' >&2
  done
  printf '\n3/7 중앙 관리 방식 선택\n' >&2
  wizard_yes_no '중앙 관리 서버에 등록하시겠습니까? [Y/n]: ' y || return 1
  if [[ "$wizard_yes" == true ]]; then wizard_installation_code || return 1; fi
  printf '\n4/7 Tetragon 프로세스 수집기\n' >&2
  printf '공식 Tetragon v1.8.0 고정 릴리스(약 90MB)를 내려받아 체크섬을 검증합니다.\n' >&2
  printf 'Python 3와 PyYAML이 없으면 OS 패키지 관리자로 설치합니다.\n' >&2
  printf 'root 전용 Unix 소켓으로 연결하고 관찰 전용(observe-only)으로 실행하며 실제 프로세스 이벤트를 확인합니다.\n' >&2
  wizard_yes_no 'Tetragon 프로세스 수집기를 설치·연결하시겠습니까? [Y/n]: ' y || return 1
  with_tetragon=$wizard_yes
  printf '\n5/7 로컬 모니터링 웹\n' >&2
  wizard_yes_no '이 호스트의 로컬 모니터링 웹을 켜시겠습니까? [y/N]: ' n || return 1
  with_web=$wizard_yes
  printf '\n6/7 설치 내용 확인\n' >&2
  if [[ "$with_build" == true ]]; then printf '패키지: 현재 소스에서 RPM 빌드\n' >&2
  else printf '패키지: %s\n' "$rpm_path" >&2; fi
  if [[ -n "$enrollment_file" ]]; then
    printf '중앙 관리: 설치 코드로 등록\n오프라인 복구 파일: %s\n' "$recovery_file" >&2
  else printf '중앙 관리: 사용 안 함 (독립 실행)\n' >&2; fi
  if [[ "$with_tetragon" == true ]]; then printf 'Tetragon 프로세스 수집기: 설치·연결 (관찰 전용, 실제 이벤트 확인)\n' >&2
  else printf 'Tetragon 프로세스 수집기: 설치 안 함\n' >&2; fi
  if [[ "$with_web" == true ]]; then printf '로컬 모니터링 웹: 사용\n' >&2
  else printf '로컬 모니터링 웹: 사용 안 함\n' >&2; fi
  printf '기존 설정과 인증 정보는 유지합니다. audit 수집 활성화는 별도 작업입니다.\n\n7/7 최종 확인\n' >&2
  wizard_yes_no '위 내용으로 설치를 진행하시겠습니까? [y/N]: ' n || return 1
  [[ "$wizard_yes" == true ]] || { fail '설치를 취소했습니다. 패키지와 서비스는 변경하지 않았습니다.'; return 1; }
}

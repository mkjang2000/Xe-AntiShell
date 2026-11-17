#!/usr/bin/env python3
"""Drive the real installer terminal flow with mocked package and service commands."""

import os
from pathlib import Path
import pty
import select
import shlex
import signal
import subprocess
import tempfile
import termios
import time


REPO = Path(__file__).resolve().parents[1]
SECRET = "xeas1.PTY_SECRET_INSTALLATION_CODE_NEVER_PRINT"
PACKAGE_PROMPT = "설치 방법 선택 [1]: "
CENTRAL_PROMPT = "중앙 관리 서버에 등록하시겠습니까? [Y/n]: "
CODE_PROMPT = "설치 코드 (화면에 표시되지 않음): "
TETRAGON_PROMPT = "Tetragon 프로세스 수집기를 설치·연결하시겠습니까? [Y/n]: "
WEB_PROMPT = "이 호스트의 로컬 모니터링 웹을 켜시겠습니까? [y/N]: "
CONFIRM_PROMPT = "위 내용으로 설치를 진행하시겠습니까? [y/N]: "

HARNESS = r'''#!/usr/bin/env bash
set -euo pipefail
source "$1/install.sh"
work=$2
XEAS_INSTALL_ROOT=$work
XEAS_WIZARD_SCRIPT=$1/packaging/install-wizard.sh
XEAS_TETRAGON_SCRIPT=$1/packaging/install-tetragon.sh
XEAS_BUILD_SCRIPT=$work/build-rpm.sh
XEAS_OS_RELEASE_FILE=$work/os-release
XEAS_RECOVERY_FILE=$work/recovery
XEAS_WEB_AUTH_FILE=$work/web-auth.json
XEAS_WEB_PASSWORD_FILE=$work/web-password
XEAS_CENTRAL_STATE_DIR=$work/no-central-state
calls=$work/calls
require_root() { return 0; }
uname() { [[ "$1" == -m ]] || return 1; printf 'x86_64\n'; }
stat() {
  if [[ "$1" == -c && "$2" == %u ]]; then printf '0\n';
  else command stat "$@"; fi
}
mktemp() {
  if [[ "$1" == /tmp/xeas-install-code.* ]]; then
    command env > "$work/code-creation-environment"
    command mktemp "$work/code.XXXXXX";
  elif [[ "$1" == -d ]]; then command mktemp -d "$work/build.XXXXXX";
  else return 1; fi
}
rpm() {
  printf 'rpm %s\n' "$*" >> "$calls"
  case "$1" in
    -q) return 1 ;;
    -Uvh) [[ -f "${@: -1}" ]] ;;
    -qp)
      [[ -f "${@: -1}" ]] || return 1
      case "$3" in
        '%{NAME}|%{ARCH}|%{RELEASE}')
          case "${@: -1}" in
            *central*) printf 'xe-antishell-central|x86_64|17.el10' ;;
            *aarch64*) printf 'xe-antishell|aarch64|17.el10' ;;
            *el9*) printf 'xe-antishell|x86_64|17.el9' ;;
            *) printf 'xe-antishell|x86_64|17.el10' ;;
          esac ;;
        '%{NAME}') printf 'xe-antishell' ;;
        *) printf 'xe-antishell-(none):0.1.0-17.el10.x86_64' ;;
      esac ;;
    *) return 1 ;;
  esac
}
systemctl() {
  printf 'systemctl %s\n' "$*" >> "$calls"
  if [[ "$1" == show ]]; then printf 'Version=257\n'; fi
}
sleep() { :; }
chown() { printf 'chown %s\n' "$*" >> "$calls"; }
stty() {
  local restoring=false
  if [[ "${XEAS_TEST_SLOW_TERMINAL_RESTORE:-0}" == 1 && "$1" != -g && "$1" != -echo ]]; then
    restoring=true
    printf 'terminal restore started\n' >> "$calls"
    command sleep 0.15
  fi
  command stty "$@" || return 1
  if [[ "$restoring" == true ]]; then printf 'terminal restore completed\n' >> "$calls"; fi
}
check_tetragon_preflight() { printf 'tetragon preflight\n' >> "$calls"; }
install_tetragon() { printf 'tetragon install\n' >> "$calls"; }
sentinel() {
  printf 'sentinel %s\n' "$*" >> "$calls"
  if [[ "$1" == status ]]; then return 0; fi
  [[ "$1 $2" == 'managed enroll-code' && "$3" == --code-file && "$5" == --recovery-file ]] || return 1
  [[ "$(command stat -c '%a' -- "$4")" == 600 ]] || return 1
  [[ "$(< "$4")" == "$(< "$work/expected-code")" ]] || return 1
  printf '%s\n' "$4" > "$work/enrollment-path"
  command env > "$work/enrollment-environment"
  if [[ ! -e "$6" ]]; then printf 'DURABLE_RECOVERY_FIXTURE\n' > "$6"; chmod 0600 "$6"; fi
  [[ "${XEAS_TEST_ENROLL_FAIL:-0}" == 0 ]]
}
sentinel-web() {
  printf 'sentinel-web %s\n' "$*" >> "$calls"
  printf 'auth fixture\n' > "$XEAS_WEB_AUTH_FILE"
  printf 'LOCAL_PASSWORD_FIXTURE\n' > "$XEAS_WEB_PASSWORD_FILE"
  chmod 0600 "$XEAS_WEB_AUTH_FILE" "$XEAS_WEB_PASSWORD_FILE"
}
run_install
'''


def fixture(directory):
    work = Path(directory)
    (work / "harness.sh").write_text(HARNESS)
    (work / "os-release").write_text('ID=rocky\nVERSION_ID="10.1"\n')
    for name in (
        "xe-antishell-0.1.0-17.el10.x86_64.rpm",
        "xe-antishell-0.1.0-17.el9.x86_64.rpm",
        "xe-antishell-0.1.0-17.el10.aarch64.rpm",
        "xe-antishell-central-0.1.0-17.el10.x86_64.rpm",
        "go.mod", "Makefile", "calls",
    ):
        (work / name).write_text("fixture\n")
    (work / "calls").write_text("")
    (work / "expected-code").write_text(SECRET)
    (work / "expected-code").chmod(0o600)
    (work / "manual").mkdir()
    (work / "manual" / "manual package.rpm").write_text("fixture\n")
    build = "#!/usr/bin/env bash\nset -euo pipefail\n"
    build += '[[ "$1" == --output-dir ]]\n'
    build += "printf 'build\n' >> " + shlex.quote(str(work / "calls")) + "\n"
    build += 'printf fixture > "$2/built.rpm"\n'
    (work / "build-rpm.sh").write_text(build)
    (work / "build-rpm.sh").chmod(0o755)
    return work


def assert_no_mutations(work):
    calls = (work / "calls").read_text()
    for mutation in ("rpm -Uvh", "systemctl enable", "systemctl daemon-reload", "sentinel managed", "sentinel-web", "chown ", "build\n", "tetragon install\n"):
        assert mutation not in calls, f"Cancellation reached a host mutation: {mutation}"


def run_terminal(work, exchanges, expected=0, terminate=None, enrollment_failure=False, allexport=False, slow_terminal_restore=False):
    master, slave = pty.openpty()
    original_terminal = termios.tcgetattr(slave)
    env = dict(os.environ)
    # An inherited exported name must never cause a pasted code to be exported.
    env["installation_code"] = "previous-nonsecret-value"
    env["XEAS_TEST_ENROLL_FAIL"] = "1" if enrollment_failure else "0"
    env["XEAS_TEST_SLOW_TERMINAL_RESTORE"] = "1" if slow_terminal_restore else "0"
    process = subprocess.Popen(
        ["bash", *(["-a"] if allexport else []), str(work / "harness.sh"), str(REPO), str(work)],
        stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True,
    )
    output = bytearray()
    position = 0

    def drain_until(needle=None):
        nonlocal position
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if needle is not None:
                found = output.find(needle.encode(), position)
                if found >= 0:
                    position = found + len(needle.encode())
                    return
            ready, _, _ = select.select([master], [], [], 0.05)
            if ready:
                output.extend(os.read(master, 65536))
            elif process.poll() is not None:
                if needle is not None:
                    raise AssertionError(f"Installer exited before prompt {needle!r}: {output.decode(errors='replace')}")
                return
        raise AssertionError(f"Installer terminal timed out: {output.decode(errors='replace')}")

    try:
        for prompt, response in exchanges:
            drain_until(prompt)
            if response is not None:
                os.write(master, response if isinstance(response, bytes) else (response + "\n").encode())
        if terminate is not None:
            os.killpg(process.pid, terminate)
        drain_until()
        result = process.wait(timeout=2)
        wanted = 128 + terminate if terminate is not None else expected
        assert result == wanted, f"Unexpected installer exit {result}, expected {wanted}: {output.decode(errors='replace')}"
        assert termios.tcgetattr(slave) == original_terminal, "Original terminal settings were not restored"
        text = output.decode(errors="replace")
        assert SECRET not in text and "LOCAL_PASSWORD_FIXTURE" not in text and "DURABLE_RECOVERY_FIXTURE" not in text, "A secret reached terminal output"
        assert SECRET not in (work / "calls").read_text(), "A code reached command arguments"
        assert not list(work.glob("code.*")), "Temporary installation code was retained"
        assert not list(work.glob("build.*")), "Temporary RPM build was retained"
        for environment in work.glob("*-environment"):
            assert SECRET not in environment.read_text(), "A code reached the environment"
        return text
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
        os.close(master)
        os.close(slave)


def main():
    wrapper_check = r'''
set -euo pipefail
source "$1/install.sh"
main() ( return "$1"; )
trap 'true' INT
trap 'exit 87' TERM
trap 'exit 88' HUP
saved=$(trap -p INT TERM HUP)
run_install 0
[[ "$(trap -p INT TERM HUP)" == "$saved" ]]
if run_install 7; then exit 1; else result=$?; fi
[[ "$result" == 7 && "$(trap -p INT TERM HUP)" == "$saved" ]]
'''
    subprocess.run(["bash", "-c", wrapper_check, "wrapper-check", str(REPO)], check=True)

    with tempfile.TemporaryDirectory(prefix="xeas-wizard-test-") as directory:
        work = fixture(directory)
        result = subprocess.run(["bash", str(work / "harness.sh"), str(REPO), str(work)], input="", capture_output=True, text=True, check=False)
        assert result.returncode != 0 and "터미널" in result.stderr
        assert_no_mutations(work)

    cases = [
        ("standalone", [(PACKAGE_PROMPT, ""), (CENTRAL_PROMPT, "n"), (TETRAGON_PROMPT, "n"), (WEB_PROMPT, ""), (CONFIRM_PROMPT, "y")]),
        ("central-web", [(PACKAGE_PROMPT, ""), (CENTRAL_PROMPT, ""), (CODE_PROMPT, SECRET), (TETRAGON_PROMPT, "n"), (WEB_PROMPT, "y"), (CONFIRM_PROMPT, "y")]),
        ("tetragon-default", [(PACKAGE_PROMPT, ""), (CENTRAL_PROMPT, "n"), (TETRAGON_PROMPT, ""), (WEB_PROMPT, "n"), (CONFIRM_PROMPT, "y")]),
        ("cancel", [(PACKAGE_PROMPT, ""), (CENTRAL_PROMPT, "y"), (CODE_PROMPT, SECRET), (TETRAGON_PROMPT, "n"), (WEB_PROMPT, ""), (CONFIRM_PROMPT, "")]),
        ("cancel-tetragon", [(PACKAGE_PROMPT, ""), (CENTRAL_PROMPT, "n"), (TETRAGON_PROMPT, ""), (WEB_PROMPT, "n"), (CONFIRM_PROMPT, "n")]),
        ("invalid-code", [(PACKAGE_PROMPT, ""), (CENTRAL_PROMPT, ""), (CODE_PROMPT, "invalid-code")]),
        ("end-of-input", [(PACKAGE_PROMPT, ""), (CENTRAL_PROMPT, ""), (CODE_PROMPT, b"\x04")]),
        ("oversized-code", [(PACKAGE_PROMPT, ""), (CENTRAL_PROMPT, ""), (CODE_PROMPT, "xeas1." + "A" * 16379)]),
        ("build", [(PACKAGE_PROMPT, "3"), (CENTRAL_PROMPT, "n"), (TETRAGON_PROMPT, "n"), (WEB_PROMPT, "n"), (CONFIRM_PROMPT, "yes")]),
        ("enrollment-failure", [(PACKAGE_PROMPT, ""), (CENTRAL_PROMPT, "y"), (CODE_PROMPT, SECRET), (TETRAGON_PROMPT, "n"), (WEB_PROMPT, "n"), (CONFIRM_PROMPT, "y")]),
    ]
    for name, exchanges in cases:
        with tempfile.TemporaryDirectory(prefix="xeas-wizard-test-") as directory:
            work = fixture(directory)
            if name == "cancel":
                (work / "recovery").write_text("PRESERVED_RECOVERY\n")
                (work / "recovery").chmod(0o600)
            expected = 1 if name in ("cancel", "cancel-tetragon", "invalid-code", "end-of-input", "oversized-code", "enrollment-failure") else 0
            output = run_terminal(work, exchanges, expected, enrollment_failure=name == "enrollment-failure")
            assert "로컬 RPM:" in output and "17.el10.x86_64.rpm" in output
            assert "17.el9.x86_64.rpm" not in output and "17.el10.aarch64.rpm" not in output
            calls = (work / "calls").read_text()
            if name in ("cancel", "cancel-tetragon", "invalid-code", "end-of-input", "oversized-code"):
                assert_no_mutations(work)
                assert "A" * 64 not in output
            elif name in ("central-web", "enrollment-failure"):
                assert "sentinel managed enroll-code --code-file " in calls
                assert (work / "recovery").read_text() == "DURABLE_RECOVERY_FIXTURE\n"
                if name == "central-web":
                    assert "sentinel-web init-auth" in calls
            else:
                assert "sentinel managed" not in calls and "sentinel-web" not in calls
            if name == "cancel":
                assert (work / "recovery").read_text() == "PRESERVED_RECOVERY\n"
            if name == "build":
                assert "build\n" in calls
            if name == "tetragon-default":
                assert "tetragon preflight\n" in calls and "tetragon install\n" in calls
                assert calls.index("tetragon preflight\n") < calls.index("rpm -Uvh")
                assert "Tetragon 프로세스 수집기: 설치·연결" in output
                assert "v1.8.0" in output and "체크섬" in output and "PyYAML" in output
                for step in range(1, 8):
                    assert f"{step}/7 " in output
            else:
                assert "tetragon preflight\n" not in calls and "tetragon install\n" not in calls

    with tempfile.TemporaryDirectory(prefix="xeas-wizard-test-") as directory:
        work = fixture(directory)
        manual = str(work / "manual" / "manual package.rpm")
        run_terminal(work, [(PACKAGE_PROMPT, "2"), ("설치할 RPM 경로: ", manual), (CENTRAL_PROMPT, "n"), (TETRAGON_PROMPT, "n"), (WEB_PROMPT, "n"), (CONFIRM_PROMPT, "y")])
        assert f"rpm -Uvh -- {manual}" in (work / "calls").read_text()

    for interrupt in (signal.SIGINT, signal.SIGTERM):
        for interrupted_step in (
            [(CODE_PROMPT, None)],
            [(CODE_PROMPT, SECRET.encode())],
            [(CODE_PROMPT, SECRET), (TETRAGON_PROMPT, None)],
            [(CODE_PROMPT, SECRET), (TETRAGON_PROMPT, "n"), (WEB_PROMPT, None)],
        ):
            with tempfile.TemporaryDirectory(prefix="xeas-wizard-test-") as directory:
                work = fixture(directory)
                (work / "recovery").write_text("PRESERVED_RECOVERY\n")
                (work / "recovery").chmod(0o600)
                run_terminal(work, [(PACKAGE_PROMPT, ""), (CENTRAL_PROMPT, ""), *interrupted_step], terminate=interrupt)
                assert_no_mutations(work)
                assert (work / "recovery").read_text() == "PRESERVED_RECOVERY\n"

    # A group signal must not let the outer installer exit before main restores
    # the terminal, even when the restoring stty child is scheduled slowly.
    for interrupt in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        with tempfile.TemporaryDirectory(prefix="xeas-wizard-test-") as directory:
            work = fixture(directory)
            run_terminal(work, [(PACKAGE_PROMPT, ""), (CENTRAL_PROMPT, ""), (CODE_PROMPT, None)], terminate=interrupt, slow_terminal_restore=True)
            assert "terminal restore completed\n" in (work / "calls").read_text()
            assert_no_mutations(work)

    with tempfile.TemporaryDirectory(prefix="xeas-wizard-test-") as directory:
        work = fixture(directory)
        run_terminal(work, [(PACKAGE_PROMPT, ""), (CENTRAL_PROMPT, ""), (CODE_PROMPT, SECRET), (TETRAGON_PROMPT, "n"), (WEB_PROMPT, "n"), (CONFIRM_PROMPT, "y")], allexport=True)
        assert (work / "code-creation-environment").exists()

    print("Installer PTY checks passed. No host packages or services were changed.")


if __name__ == "__main__":
    main()

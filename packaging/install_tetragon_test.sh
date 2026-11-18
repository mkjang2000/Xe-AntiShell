#!/usr/bin/env bash
# Verify interpreter and dependency selection without installing packages.
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$repo_root/install.sh"
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
tools=$test_root/tools
mkdir "$tools" "$test_root/ready"
calls=$test_root/calls
XEAS_OS_RELEASE_FILE=$test_root/os-release
XEAS_INSTALL_ROOT=$test_root/source
tetragon_archive=''
tetragon_python=''
mock_dnf_success=true
mock_dnf_provides=true
export XEAS_TEST_TETRAGON_CALLS=$calls
export XEAS_TEST_TETRAGON_READY=$test_root/ready

cat > "$test_root/interpreter" <<'INTERPRETER'
#!/usr/bin/env bash
set -euo pipefail
name=${0##*/}
if [[ "$1" == -c ]]; then
  [[ "$2" == 'import sys, yaml; sys.exit(sys.version_info < (3, 9))' ]]
  [[ -e "$XEAS_TEST_TETRAGON_READY/$name" ]]
else
  printf 'setup %s argc=%d\n' "$name" "$#" >> "$XEAS_TEST_TETRAGON_CALLS"
  printf 'arg %s\n' "$@" >> "$XEAS_TEST_TETRAGON_CALLS"
fi
INTERPRETER
chmod 0755 "$test_root/interpreter"
for interpreter in python3 python3.12 python3.11 python3.10 python3.9; do
  cp "$test_root/interpreter" "$tools/$interpreter"
done

# Restrict candidate resolution to the private mocked interpreters.
type() {
  [[ "$1" == -P && -f "$tools/$2" ]] || return 1
  printf '%s/%s\n' "$tools" "$2"
}
dnf() {
  printf 'dnf %s\n' "$*" >> "$calls"
  [[ "$mock_dnf_success" == true ]] || return 1
  [[ "$mock_dnf_provides" == true ]] || return 0
  case "$*" in
    '-y install python39 python39-pyyaml') : > "$test_root/ready/python3.9" ;;
    '-y install python3 python3-pyyaml') : > "$test_root/ready/python3" ;;
    *) return 1 ;;
  esac
}
reset_fixture() {
  rm -f -- "$test_root/ready/"*
  : > "$calls"
  tetragon_python=''
  tetragon_archive=''
  mock_dnf_success=true
  mock_dnf_provides=true
}

# EL8's default Python 3.6 must not hide an already prepared versioned runtime.
for interpreter in python3.12 python3.11 python3.10 python3.9; do
  reset_fixture
  : > "$test_root/ready/$interpreter"
  select_tetragon_python
  [[ "$tetragon_python" == "$tools/$interpreter" && ! -s "$calls" ]]
done
reset_fixture
: > "$test_root/ready/python3"
: > "$test_root/ready/python3.12"
select_tetragon_python
[[ "$tetragon_python" == "$tools/python3" ]]

# A caller's previous path cannot bypass the fixed list of checked candidates.
reset_fixture
tetragon_python=$test_root/interpreter
if select_tetragon_python; then exit 1; fi
[[ -z "$tetragon_python" && ! -s "$calls" ]]

# EL8 installs matching 3.9 packages and invokes that interpreter afterward.
reset_fixture
printf 'ID=rocky\nVERSION_ID="8.10"\n' > "$XEAS_OS_RELEASE_FILE"
tetragon_archive="$test_root/local archive.tar.gz"
install_tetragon > "$test_root/stdout" 2> "$test_root/stderr"
trace=$(< "$calls")
[[ "$trace" == *'dnf -y install python39 python39-pyyaml'*'setup python3.9 argc=3'* ]]
[[ "$trace" == *"arg $tetragon_archive"* ]]

# EL9/EL10 use the distribution's default Python and its matching YAML package.
for os_version in 9.6 10.1; do
  reset_fixture
  printf "ID=rocky\nVERSION_ID='%s'\n" "$os_version" > "$XEAS_OS_RELEASE_FILE"
  install_tetragon > "$test_root/stdout" 2> "$test_root/stderr"
  trace=$(< "$calls")
  [[ "$trace" == *'dnf -y install python3 python3-pyyaml'*'setup python3 argc=1'* ]]
done

# os-release values are data and cannot select packages through shell expansion.
reset_fixture
printf '%s\n' 'ID=rocky' 'VERSION_ID="$(printf 8)"' > "$XEAS_OS_RELEASE_FILE"
install_tetragon > "$test_root/stdout" 2> "$test_root/stderr"
[[ "$(< "$calls")" == *'dnf -y install python3 python3-pyyaml'* ]]

# A compatible runtime with PyYAML requires no package operation.
reset_fixture
: > "$test_root/ready/python3.9"
install_tetragon > "$test_root/stdout" 2> "$test_root/stderr"
trace=$(< "$calls")
[[ "$trace" == *'setup python3.9 argc=1'* && "$trace" != *dnf* ]]

# Failed package installation or missing imports never execute setup.py.
for failure in package imports; do
  reset_fixture
  if [[ "$failure" == package ]]; then mock_dnf_success=false
  else mock_dnf_provides=false; fi
  if install_tetragon > "$test_root/stdout" 2> "$test_root/stderr"; then exit 1; fi
  [[ "$(< "$calls")" != *'setup '* ]]
done
[[ "$(< "$test_root/stderr")" == *'Python 3.9+ with PyYAML is required'* ]]

# Exercise the real Python preflight with only the standalone helper files.
# Byte checks and the production helper list still run in this fixture.
(
  fetch_install_file() {
    local url=$1 output=$2 expected=$3 checksum
    cp -- "$repo_root/packaging/${url#*/packaging/}" "$output"
    checksum=$(sha256sum < "$output")
    [[ "${checksum%% *}" == "$expected" ]]
  }
  download_directory=$test_root/download
  XEAS_TETRAGON_SCRIPT=$test_root/missing/packaging/install-tetragon.sh
  load_downloaded_tetragon_helper
  python3 -I - "$download_directory/packaging/tetragon" "$test_root/preflight" <<'PY'
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
from setup_common import Paths
from setup_services import check_conflicts


class Services:
    def show(self, service, property_name):
        if service == "sentineld.service" and property_name == "ExecStart":
            return "{ path=/usr/sbin/sentineld ; argv[]=/usr/sbin/sentineld ; }"
        return ""

    def call(self, *args, check):
        assert args == ("show-environment",) and not check
        return 0, b""


check_conflicts(Paths(Path(sys.argv[2])), Services())
PY
)

printf 'Tetragon interpreter checks passed. No host packages or services were changed.\n'

#!/usr/bin/env bash
# Check the build orchestration with real source archives and mocked compilers.
set -euo pipefail
test_source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
source "$test_source_root/scripts/build-rpm.sh"
test_work=$(mktemp -d)
trap 'rm -rf -- "$test_work"' EXIT
export XEAS_MOCK_WORK=$test_work
export XEAS_MOCK_CALLS=$test_work/calls
export XEAS_MOCK_CAPTURE=$test_work/source.tar.gz
export XEAS_MOCK_GO_VERSION=go1.22.0
export XEAS_MOCK_MACROS=available
export XEAS_MOCK_GUARD=success
export XEAS_MOCK_COUNT=1
export XEAS_MOCK_PAYLOAD=COMPLETE_RPM_FIXTURE
export XEAS_MOCK_PYTHON_OK=true
export XEAS_TEST_PYTHON
XEAS_TEST_PYTHON=$(type -P python3)
test_missing_tool=''
mkdir -p "$test_work/tools" "$test_work/source"
XEAS_BUILD_ROOT=$test_work/source

for test_path in go.mod go.sum Makefile install.sh README.md Project_tree.md \
  LICENSE THIRD_PARTY_NOTICES.md third_party/licenses/upstream-LICENSE.txt \
  protocol/go.mod protocol/LICENSE protocol/README.md \
  protocol/managed/protocol.go protocol/managed/protocol_test.go protocol/model/model.go \
  protocol/managed/testdata/legacy-policy.json \
  configs/sentineld.yaml packaging/rpm/xe-antishell.spec \
  packaging/systemd/sentineld.service packaging/systemd/sentinel-web.service packaging/systemd/sentinel-updater.service \
  packaging/systemd/sentinel-removal.service \
  packaging/audit/xe-antishell.conf \
  packaging/audit/90-xe-antishell.rules packaging/tetragon/monitor.conf \
  packaging/tetragon/sentineld.conf packaging/install_test.sh \
  packaging/install-wizard.sh packaging/install_wizard_test.py \
  packaging/install-tetragon.sh packaging/install_tetragon_test.sh packaging/tetragon/setup.py packaging/tetragon/setup_config.py \
  packaging/tetragon/test_setup.py \
  cmd/sentineld/main.go internal/model/model.go internal/storage/schema.sql \
  internal/privileges/credential-policy.yaml \
  internal/webpanel/assets/index.html internal/webpanel/assets/app.js \
  scripts/check-source.py scripts/build-rpm.sh testdata/events/replay.jsonl \
  configs/examples/monitor.yaml devdocs/plans/install.md devdocs/reviews/security.md \
  devdocs/analysis/managed-v1-operations.md devdocs/analysis/release-signing.ko.md Linux_Host_Security_Platform_Design_v0.1.md; do
  mkdir -p -- "$XEAS_BUILD_ROOT/$(dirname -- "$test_path")"
  printf 'maintained fixture\n' > "$XEAS_BUILD_ROOT/$test_path"
done
# Archive the real RPM definition and units so the fixture guards the shipped
# service configuration as well as the source allowlist.
cp -- "$test_source_root/packaging/rpm/xe-antishell.spec" "$XEAS_BUILD_ROOT/packaging/rpm/"
for unit in sentineld sentinel-web sentinel-updater sentinel-removal; do
  cp -- "$test_source_root/packaging/systemd/$unit.service" "$XEAS_BUILD_ROOT/packaging/systemd/"
done
printf 'internal/private.go\nscripts/private_notes.py\n' > "$XEAS_BUILD_ROOT/.gitignore"
for test_path in .aws/credentials .codex/session.json .git/config .env \
  internal/private.go internal/site.json internal/signing.key internal/private.pem \
  internal/.private/hidden.go scripts/private_notes.py configs/hosts/real.yaml \
  protocol/site.json protocol/signing.key protocol/.private/hidden.go \
  packaging/systemd/sentinel-central-local-ports.conf devdocs/analysis/private-host.md \
  build/sentineld dist/rpm/old.rpm; do
  mkdir -p -- "$XEAS_BUILD_ROOT/$(dirname -- "$test_path")"
  printf 'DO_NOT_ARCHIVE_PRIVATE_FIXTURE\n' > "$XEAS_BUILD_ROOT/$test_path"
done

cat > "$test_work/tools/go" <<'MOCK'
#!/usr/bin/env bash
[[ "$GOTOOLCHAIN" == local && "$1" == version ]] || exit 1
printf 'go version %s linux/amd64\n' "$XEAS_MOCK_GO_VERSION"
MOCK
cat > "$test_work/tools/rpm" <<'MOCK'
#!/usr/bin/env bash
[[ "$1" == --eval ]] || exit 1
printf '%s\n' "$XEAS_MOCK_MACROS"
MOCK
cat > "$test_work/tools/python3" <<'MOCK'
#!/usr/bin/env bash
if [[ "${2:-}" == *sys.version_info* && "$XEAS_MOCK_PYTHON_OK" != true ]]; then exit 1; fi
exec "$XEAS_TEST_PYTHON" "$@"
MOCK
cat > "$test_work/tools/make" <<'MOCK'
#!/usr/bin/env bash
printf 'source-guard\n' >> "$XEAS_MOCK_CALLS"
[[ "$1" == -C && "$3" == check-source && "$XEAS_MOCK_GUARD" == success ]]
MOCK
cat > "$test_work/tools/rpmbuild" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$GOWORK" == off && "$GOTOOLCHAIN" == local && "$CGO_ENABLED" == 0 ]] || exit 1
printf 'rpmbuild\n' >> "$XEAS_MOCK_CALLS"
topdir=''; nodeps=false
while (( $# )); do
  case "$1" in
    --define) [[ "$2" != '_topdir '* ]] || topdir=${2#_topdir }; shift 2 ;;
    --nodeps) nodeps=true; shift ;;
    *) shift ;;
  esac
done
[[ -n "$topdir" && "$nodeps" == true ]]
cp "$topdir/SOURCES/xe-antishell-0.1.0.tar.gz" "$XEAS_MOCK_CAPTURE"
mkdir -p "$topdir/RPMS/x86_64"
for (( n=0; n<XEAS_MOCK_COUNT; n++ )); do
  printf '%s\n' "$XEAS_MOCK_PAYLOAD" > "$topdir/RPMS/x86_64/xe-antishell-0.1.0-$((n+1)).x86_64.rpm"
done
MOCK
chmod 0755 "$test_work/tools/"*

build_find_tool() {
  [[ "$1" != "$test_missing_tool" ]] || return 1
  case "$1" in
    go|rpm|rpmbuild|make|python3) printf '%s/tools/%s\n' "$test_work" "$1" ;;
    *) type -P "$1" ;;
  esac
}

expect_failure() {
  if build_main "$@" > "$test_work/stdout" 2> "$test_work/stderr"; then
    printf 'Expected build failure: %s\n' "$*" >&2; exit 1
  fi
}
assert_no_build() { [[ ! -s "$XEAS_MOCK_CALLS" ]] || { printf 'Invalid input started a build.\n' >&2; exit 1; }; }
: > "$XEAS_MOCK_CALLS"
build_main --help > "$test_work/help"
expect_failure --unknown; assert_no_build
expect_failure --output-dir; assert_no_build
printf 'not a directory\n' > "$test_work/output-file"
expect_failure --output-dir "$test_work/output-file"; assert_no_build
mkdir "$test_work/real-output"
ln -s "$test_work/real-output" "$test_work/output-link"
expect_failure --output-dir "$test_work/output-link"; assert_no_build
test_missing_tool=go
expect_failure --output-dir "$test_work/not-created"; assert_no_build
[[ ! -e "$test_work/not-created" ]]
test_missing_tool=''
XEAS_MOCK_PYTHON_OK=false
expect_failure --output-dir "$test_work/not-created"; assert_no_build
[[ ! -e "$test_work/not-created" ]]
XEAS_MOCK_PYTHON_OK=true
XEAS_MOCK_GO_VERSION=go1.21.9
expect_failure --output-dir "$test_work/not-created"; assert_no_build
XEAS_MOCK_GO_VERSION=devel
expect_failure --output-dir "$test_work/not-created"; assert_no_build
XEAS_MOCK_GO_VERSION=go1.22.0
XEAS_MOCK_MACROS=missing
expect_failure --output-dir "$test_work/not-created"; assert_no_build
XEAS_MOCK_MACROS=available
XEAS_MOCK_GUARD=fail
expect_failure --output-dir "$test_work/not-created"
[[ $(< "$XEAS_MOCK_CALLS") == source-guard ]]
XEAS_MOCK_GUARD=success

: > "$XEAS_MOCK_CALLS"
output="$test_work/output with spaces"
build_main --output-dir "$output" > "$test_work/stdout" 2> "$test_work/stderr"
artifact="$output/xe-antishell-0.1.0-1.x86_64.rpm"
[[ -f "$artifact" && $(< "$artifact") == COMPLETE_RPM_FIXTURE ]]
[[ $(stat -c '%a' "$artifact") == 644 ]]
[[ $(< "$XEAS_MOCK_CALLS") == $'source-guard\nrpmbuild' ]]
python3 - "$XEAS_MOCK_CAPTURE" <<'PY'
import configparser
import sys
import tarfile

with tarfile.open(sys.argv[1], 'r:gz') as archive:
    names = set(archive.getnames())
    root = 'xe-antishell-0.1.0/'
    for expected in ['README.md','LICENSE','THIRD_PARTY_NOTICES.md','third_party/licenses/upstream-LICENSE.txt','go.mod','protocol/go.mod','protocol/LICENSE','protocol/README.md','protocol/managed/protocol.go','protocol/managed/protocol_test.go','protocol/managed/testdata/legacy-policy.json','protocol/model/model.go','internal/model/model.go','internal/storage/schema.sql','configs/examples/monitor.yaml','devdocs/plans/install.md','devdocs/analysis/managed-v1-operations.md','Linux_Host_Security_Platform_Design_v0.1.md']:
        assert root+expected in names, expected
    assert root+'internal/privileges/credential-policy.yaml' in names
    assert root+'packaging/systemd/sentinel-central.service' not in names
    assert root+'packaging/install-wizard.sh' in names
    assert root+'packaging/install_wizard_test.py' in names
    assert root+'devdocs/analysis/release-signing.ko.md' in names
    spec = archive.extractfile(root + 'packaging/rpm/xe-antishell.spec').read().decode()
    install_section = spec.split('\n%install\n', 1)[1].split('\n%files\n', 1)[0]
    unit_settings = {
        'sentinel-updater': {
            'Type': 'oneshot',
            'User': 'root',
            'Group': 'root',
            'ExecStart': '/usr/sbin/sentinel-updater',
            'UMask': '0077',
            'NoNewPrivileges': 'false',
            'PrivateTmp': 'true',
            'ProtectHome': 'true',
        },
        'sentinel-removal': {
            'Type': 'oneshot',
            'User': 'root',
            'Group': 'root',
            'ExecStart': '/usr/sbin/sentinel-updater --remote-removal',
            'NoNewPrivileges': 'false',
        },
        'sentineld': {'NoNewPrivileges': 'true', 'ProtectSystem': 'strict'},
        'sentinel-web': {'NoNewPrivileges': 'true', 'ProtectSystem': 'strict'},
    }
    for name, expected in unit_settings.items():
        unit_path = f'packaging/systemd/{name}.service'
        install = f'install -D -m 0644 {unit_path} %{{buildroot}}%{{_unitdir}}/{name}.service'
        assert install in install_section.splitlines(), unit_path
        unit = configparser.ConfigParser(interpolation=None)
        unit.read_string(archive.extractfile(root + unit_path).read().decode())
        for key, value in expected.items():
            assert unit['Service'].get(key) == value, (name, key, unit['Service'].get(key))
    preun = spec.split('\n%preun\n', 1)[1].split('\n%postun\n', 1)[0]
    assert '--operation "$XEAS_REMOTE_REMOVAL_OPERATION"' in preun
    assert 'sentinel-removal.service' not in next(line for line in preun.splitlines() if line.startswith('%systemd_preun'))
    for expected in ['packaging/install-tetragon.sh','packaging/install_tetragon_test.sh','packaging/tetragon/setup.py','packaging/tetragon/setup_config.py','packaging/tetragon/test_setup.py']:
        assert root+expected in names, expected
    for member in archive.getmembers():
        assert member.name.startswith(root)
        assert member.isfile()
        assert b'DO_NOT_ARCHIVE_PRIVATE_FIXTURE' not in archive.extractfile(member).read(), member.name
PY
[[ "$(< "$test_work/stdout")" != *'DO_NOT_ARCHIVE_PRIVATE_FIXTURE'* ]]

# The compiled fixed sensor is required, never silently omitted from archives.
mv "$XEAS_BUILD_ROOT/internal/privileges/credential-policy.yaml" "$test_work/sensor-policy-backup"
expect_failure --output-dir "$test_work/missing-sensor-output"
[[ ! -e "$test_work/missing-sensor-output" ]]
mv "$test_work/sensor-policy-backup" "$XEAS_BUILD_ROOT/internal/privileges/credential-policy.yaml"

# Ordinary repeat builds preserve existing bytes; replacement is explicit.
XEAS_MOCK_PAYLOAD=SECOND_COMPLETE_RPM_FIXTURE
expect_failure --output-dir "$output"
[[ $(< "$artifact") == COMPLETE_RPM_FIXTURE ]]
build_main --output-dir "$output" --force > "$test_work/stdout" 2> "$test_work/stderr"
[[ $(< "$artifact") == SECOND_COMPLETE_RPM_FIXTURE ]]
printf 'preserved unrelated file\n' > "$output/notes.txt"
build_main --output-dir "$output" --force > "$test_work/stdout" 2> "$test_work/stderr"
[[ $(< "$output/notes.txt") == 'preserved unrelated file' ]]
rm "$artifact"
ln -s "$output/notes.txt" "$artifact"
expect_failure --output-dir "$output" --force
[[ $(< "$output/notes.txt") == 'preserved unrelated file' ]]

# Missing/extra artifacts or source symlinks do not publish an output RPM.
XEAS_MOCK_COUNT=0
expect_failure --output-dir "$test_work/no-output"
[[ ! -e "$test_work/no-output" ]]
XEAS_MOCK_COUNT=2
expect_failure --output-dir "$test_work/no-output"
[[ ! -e "$test_work/no-output" ]]
XEAS_MOCK_COUNT=1
mv "$XEAS_BUILD_ROOT/third_party/licenses/upstream-LICENSE.txt" "$test_work/license-backup"
expect_failure --output-dir "$test_work/no-output"
[[ ! -e "$test_work/no-output" ]]
mv "$test_work/license-backup" "$XEAS_BUILD_ROOT/third_party/licenses/upstream-LICENSE.txt"
mv "$XEAS_BUILD_ROOT/LICENSE" "$test_work/project-license-backup"
expect_failure --output-dir "$test_work/no-output"
[[ ! -e "$test_work/no-output" ]]
mv "$test_work/project-license-backup" "$XEAS_BUILD_ROOT/LICENSE"
mv "$XEAS_BUILD_ROOT/protocol/go.mod" "$test_work/protocol-module-backup"
expect_failure --output-dir "$test_work/no-output"
[[ ! -e "$test_work/no-output" ]]
mv "$test_work/protocol-module-backup" "$XEAS_BUILD_ROOT/protocol/go.mod"
ln -s "$test_work/output-file" "$XEAS_BUILD_ROOT/protocol/source-link.go"
expect_failure --output-dir "$test_work/no-output"
[[ ! -e "$test_work/no-output" ]]
rm "$XEAS_BUILD_ROOT/protocol/source-link.go"
ln -s "$test_work/output-file" "$XEAS_BUILD_ROOT/internal/source-link.go"
expect_failure --output-dir "$test_work/no-output"
[[ ! -e "$test_work/no-output" ]]

printf 'RPM build command-mock and source-archive checks passed. No host packages or services were changed.\n'

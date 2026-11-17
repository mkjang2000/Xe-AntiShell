#!/usr/bin/env bash
# Orchestration regression: no real signing key, GitHub request or RPM install.
set -euo pipefail
test_source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
source "$test_source_root/scripts/publish-release.sh"
test_work=$(mktemp -d)
trap 'rm -rf -- "$test_work"' EXIT
export XEAS_PUBLISH_TEST_WORK=$test_work
export XEAS_PUBLISH_TEST_FAILURE=''
export XEAS_PUBLISH_TEST_SECRET='NONPRODUCTION_SIGNER_FIXTURE_NEVER_PRINT'
# A publisher's enterprise-host default must not change the public destination.
export GH_HOST=enterprise.invalid
test_python=$(type -P python3)
test_tar=$(type -P tar)
test_missing_tool=''
XEAS_PUBLISH_ROOT=$test_work/source
mkdir -p "$test_work/source/build" "$test_work/source/third_party/licenses" "$test_work/tools" "$test_work/input"
printf 'project license\n' > "$test_work/source/LICENSE"
printf 'upstream notices\n' > "$test_work/source/THIRD_PARTY_NOTICES.md"
printf 'upstream license\n' > "$test_work/source/third_party/licenses/upstream.txt"
# Intentionally not a real PEM or usable private key.
printf '%s\n' "$XEAS_PUBLISH_TEST_SECRET" > "$test_work/publisher-fixture.key"
printf 'reviewed EL9 RPM fixture\n' > "$test_work/input/xe-antishell-0.1.0-24.el9.x86_64.rpm"
printf 'reviewed EL10 RPM fixture\n' > "$test_work/input/xe-antishell-0.1.0-24.el10.x86_64.rpm"

cat > "$test_work/source/build/xeas-release" <<'MOCK'
#!/usr/bin/env python3
import hashlib, json, os, pathlib, re, sys
command = sys.argv[1]
options = dict(zip(sys.argv[2::2], sys.argv[3::2]))
work = pathlib.Path(os.environ["XEAS_PUBLISH_TEST_WORK"])
with (work / "calls").open("a", encoding="utf-8") as output:
    output.write(command + "\n")
failure = os.environ.get("XEAS_PUBLISH_TEST_FAILURE")
if failure == command:
    print(os.environ["XEAS_PUBLISH_TEST_SECRET"], file=sys.stderr)
    sys.exit(1)
rpm = pathlib.Path(options["--rpm"])
if command == "prepare":
    match = re.fullmatch(r"xe-antishell-(\d+\.\d+\.\d+)-(\d+)\.el(\d+)\.(.+)\.rpm", rpm.name)
    if not match:
        sys.exit(1)
    version, release, major, arch = match.groups()
    manifest = {"schema_version": "1", "artifact_name": rpm.name,
        "package": {"name": "xe-antishell", "epoch": 0, "version": version,
            "release": release + ".el" + major, "arch": arch},
        "os_family": "rhel", "os_major": major, "size": rpm.stat().st_size,
        "sha256": hashlib.sha256(rpm.read_bytes()).hexdigest(), "published_at": "2026-11-18T00:00:00Z"}
    pathlib.Path(options["--out"]).write_text(json.dumps(manifest), encoding="utf-8")
elif command == "sign":
    key = pathlib.Path(options["--key"])
    assert key == work / "publisher-fixture.key"
    assert "public" not in key.parts
    manifest = json.loads(pathlib.Path(options["--manifest"]).read_text(encoding="utf-8"))
    signed = {"manifest": manifest, "key_id": "test-public-key", "signature": "noncryptographic-fixture"}
    pathlib.Path(options["--out"]).write_text(json.dumps(signed), encoding="utf-8")
elif command == "verify":
    signed = json.loads(pathlib.Path(options["--manifest"]).read_text(encoding="utf-8"))
    assert signed["manifest"]["sha256"] == hashlib.sha256(rpm.read_bytes()).hexdigest()
else:
    sys.exit(1)
MOCK
cat > "$test_work/tools/gh" <<'MOCK'
#!/usr/bin/env python3
import json, os, pathlib, sys
work = pathlib.Path(os.environ["XEAS_PUBLISH_TEST_WORK"])
args = sys.argv[1:]
assert args[0] == "release"
assert args[2] == "v0.1.0-r24"
assert args[args.index("--repo") + 1] == "github.com/mkjang2000/Xe-AntiShell"
assert "--clobber" not in args and "--notes" not in args and "delete" not in args
with (work / "gh-calls").open("a", encoding="utf-8") as output:
    output.write(json.dumps(args) + "\n")
if args[1] == "create":
    assert "--verify-tag" in args and "--draft" in args
    notes = pathlib.Path(args[args.index("--notes-file") + 1])
    assert notes.is_file()
    assert "PUBLIC_NOTES_FIXTURE" in notes.read_text(encoding="utf-8")
elif args[1] == "upload":
    files = args[args.index("--repo") + 2:]
    assert len(files) == 8
    for value in files:
        path = pathlib.Path(value)
        assert path.is_file() and not path.is_symlink()
        assert not path.name.endswith("unsigned.json")
        assert path.name == "SHA256SUMS" or path.name in ("LICENSE", "THIRD_PARTY_NOTICES.md", "third-party-licenses.tar.gz") or path.name.endswith((".rpm", ".rpm.manifest.json"))
        assert os.environ["XEAS_PUBLISH_TEST_SECRET"].encode() not in path.read_bytes()
elif args[1] == "edit":
    assert "--draft=false" in args
else:
    sys.exit(1)
if os.environ.get("XEAS_PUBLISH_TEST_FAILURE") == "gh-" + args[1]:
    print(os.environ["XEAS_PUBLISH_TEST_SECRET"], file=sys.stderr)
    sys.exit(1)
MOCK
chmod 0755 "$test_work/source/build/xeas-release" "$test_work/tools/gh"
printf 'PUBLIC_NOTES_FIXTURE\nA reviewed multiline release body.\n' > "$test_work/notes.md"

publish_find_tool() {
  [[ "$1" != "$test_missing_tool" ]] || return 1
  case "$1" in
    python3) printf '%s\n' "$test_python" ;;
    tar) printf '%s\n' "$test_tar" ;;
    gh) printf '%s\n' "$test_work/tools/gh" ;;
    *) return 1 ;;
  esac
}
publish_build_tool() { printf 'build\n' >> "$test_work/calls"; }
test_count=0
test_assert() { if ! "$@"; then printf 'Assertion failed: %s\n' "$*" >&2; exit 1; fi; }
test_run() {
  test_count=$((test_count+1))
  : > "$test_work/calls"
  : > "$test_work/gh-calls"
  test_status=0
  publish_main --tag v0.1.0-r24 \
    --rpm "$test_work/input/xe-antishell-0.1.0-24.el9.x86_64.rpm" \
    --rpm "$test_work/input/xe-antishell-0.1.0-24.el10.x86_64.rpm" \
    --key "$test_work/publisher-fixture.key" --notes-file "$test_work/notes.md" \
    --output-dir "$test_work/out-$test_count" "$@" > "$test_work/output" 2>&1 || test_status=$?
  if grep -q -F "$XEAS_PUBLISH_TEST_SECRET" "$test_work/output"; then
    printf 'Sensitive tool output escaped the fixed error boundary.\n' >&2; exit 1
  fi
}

# Default mode signs/verifies the complete bundle, with no gh call.
test_run
test_assert test "$test_status" -eq 0
test_assert test ! -s "$test_work/gh-calls"
test_assert test -f "$test_work/out-$test_count/SHA256SUMS"
test_assert test ! -e "$test_work/out-$test_count/publisher-fixture.key"
"$test_python" - "$test_work/out-$test_count" "$test_work/calls" <<'PYTHON'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
assert len(list(root.iterdir())) == 8
for line in (root / "SHA256SUMS").read_text().splitlines():
    digest, name = line.split("  ")
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
assert pathlib.Path(sys.argv[2]).read_text().splitlines() == ["build", "prepare", "prepare", "sign", "verify", "sign", "verify"]
PYTHON

# Explicit publication uses the fixed repository, a remote-existing tag, draft
# staging, a notes file and explicit public assets before the final publication.
test_run --publish
test_assert test "$test_status" -eq 0
"$test_python" - "$test_work/gh-calls" <<'PYTHON'
import json, pathlib, sys
assert [json.loads(line)[1] for line in pathlib.Path(sys.argv[1]).read_text().splitlines()] == ["create", "upload", "edit"]
PYTHON

# Header/tag disagreement and unsupported targets fail before signing/output.
for test_extra in '--tag v0.1.0-r25' '--tag v0.2.0-r24'; do
  read -r -a test_args <<< "$test_extra"
  test_run "${test_args[@]}"
  test_assert test "$test_status" -ne 0
  test_assert test ! -e "$test_work/out-$test_count"
  test_assert test ! -s "$test_work/gh-calls"
  test_assert test "$(grep -c '^sign$' "$test_work/calls" || true)" = 0
done
test_run --rpm "$test_work/input/xe-antishell-0.1.0-24.el9.x86_64.rpm"
test_assert test "$test_status" -ne 0
test_assert test ! -s "$test_work/calls"

# Missing gh is a deterministic preflight error, without touching a key/tool.
test_missing_tool=gh
test_run --publish
test_assert test "$test_status" -ne 0
test_assert test ! -s "$test_work/calls"
test_assert grep -q 'GitHub CLI (gh) is required' "$test_work/output"
test_missing_tool=''

# Sign/verify failure cannot create a public output or call GitHub; raw child
# diagnostics (including an injected secret marker) are never echoed.
for test_failure in prepare sign verify; do
  XEAS_PUBLISH_TEST_FAILURE=$test_failure
  test_run --publish
  test_assert test "$test_status" -ne 0
  test_assert test ! -e "$test_work/out-$test_count"
  test_assert test ! -s "$test_work/gh-calls"
done

# Existing remote release/create error and partial upload never publish or
# overwrite anything. Local checked assets remain available for investigation.
for test_failure in gh-create gh-upload gh-edit; do
  XEAS_PUBLISH_TEST_FAILURE=$test_failure
  test_run --publish
  test_assert test "$test_status" -ne 0
  test_assert test -f "$test_work/out-$test_count/SHA256SUMS"
  "$test_python" - "$test_work/gh-calls" "$test_failure" <<'PYTHON'
import json, pathlib, sys
stages = [json.loads(line)[1] for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
assert stages == {"gh-create": ["create"], "gh-upload": ["create", "upload"], "gh-edit": ["create", "upload", "edit"]}[sys.argv[2]]
PYTHON
done
XEAS_PUBLISH_TEST_FAILURE=''

# Existing output, input symlinks and unintended license payloads are rejected.
test_run --output-dir "$test_work/out-1"
test_assert test "$test_status" -ne 0
test_assert test ! -s "$test_work/calls"
mv "$test_work/input/xe-antishell-0.1.0-24.el9.x86_64.rpm" "$test_work/input/real.rpm"
ln -s real.rpm "$test_work/input/xe-antishell-0.1.0-24.el9.x86_64.rpm"
test_run
test_assert test "$test_status" -ne 0
test_assert test ! -e "$test_work/out-$test_count"
rm "$test_work/input/xe-antishell-0.1.0-24.el9.x86_64.rpm"
mv "$test_work/input/real.rpm" "$test_work/input/xe-antishell-0.1.0-24.el9.x86_64.rpm"
printf 'not a public license\n' > "$test_work/source/third_party/licenses/unexpected.pem"
test_run --publish
test_assert test "$test_status" -ne 0
test_assert test ! -e "$test_work/out-$test_count"
test_assert test ! -s "$test_work/gh-calls"

printf 'Publisher orchestration tests passed (%s scenarios).\n' "$test_count"

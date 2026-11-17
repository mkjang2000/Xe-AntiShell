#!/usr/bin/env bash
# Prepare a public release bundle; publish only with the explicit --publish flag.
set -euo pipefail
PATH=/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
XEAS_PUBLISH_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)

publish_usage() {
  cat <<'USAGE'
Usage: scripts/publish-release.sh --tag vVERSION-rRELEASE --rpm AGENT.rpm [--rpm AGENT.rpm ...]
       [--key FILE] [--output-dir NEW_DIR] [--notes-file PUBLIC_NOTES.md] [--publish]

Prepare, sign and verify reviewed EL9/EL10 x86_64 RPMs, matching their actual
headers to the tag. Default: create a new local public bundle only.
--publish additionally creates a draft, uploads the explicit assets, then
publishes it in mkjang2000/Xe-AntiShell. The remote tag must already exist.
Existing releases/assets are never overwritten. A failed upload leaves a draft.

Default key: /root/.local/share/xe-antishell-release/publisher-key.pem
Default output: dist/publish/TAG (must not exist)
Requires the installed Go SDK, Python 3, tar and, with --publish, GitHub CLI (gh).
Private key contents are read only by xeas-release and never copied into assets.
USAGE
}

publish_fail() { printf 'publish-release.sh: %s\n' "$*" >&2; return 1; }
publish_find_tool() { type -P "$1"; }
publish_build_tool() { "$XEAS_PUBLISH_ROOT/scripts/build-release-tool.sh"; }

publish_main() (
  local tag='' key=/root/.local/share/xe-antishell-release/publisher-key.pem output_dir=''
  local notes_file='' publish=false option rpm name unsigned manifest work='' python_tool tar_tool gh_tool=''
  local release_tool="$XEAS_PUBLISH_ROOT/build/xeas-release" repository=github.com/mkjang2000/Xe-AntiShell
  local -a rpms=() staged_rpms=() unsigned_files=() assets=()
  while (( $# )); do
    option=$1
    case "$option" in
      -h|--help) publish_usage; return 0 ;;
      --publish) publish=true; shift ;;
      --tag|--key|--output-dir|--notes-file|--rpm)
        (( $# >= 2 )) && [[ -n "$2" && "$2" != --* ]] || { publish_fail 'Missing option value.'; return 1; }
        case "$option" in
          --tag) tag=$2 ;; --key) key=$2 ;; --output-dir) output_dir=$2 ;;
          --notes-file) notes_file=$2 ;; --rpm) rpms+=("$2") ;;
        esac
        shift 2 ;;
      *) publish_fail 'Unknown option. See --help.'; return 1 ;;
    esac
  done
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-r[1-9][0-9]*$ && ${#rpms[@]} -ge 1 && ${#rpms[@]} -le 2 ]] || {
    publish_fail 'Supply a version/release tag and one or two reviewed EL9/EL10 RPMs.'; return 1
  }
  [[ -n "$output_dir" ]] || output_dir="$XEAS_PUBLISH_ROOT/dist/publish/$tag"
  [[ ! -e "$output_dir" && ! -L "$output_dir" ]] || { publish_fail 'Output directory must be new.'; return 1; }
  python_tool=$(publish_find_tool python3) || { publish_fail 'Python 3 is required.'; return 1; }
  tar_tool=$(publish_find_tool tar) || { publish_fail 'tar is required.'; return 1; }
  if [[ "$publish" == true ]]; then
    gh_tool=$(publish_find_tool gh) || { publish_fail 'GitHub CLI (gh) is required for --publish; install it and authenticate separately.'; return 1; }
  fi
  [[ -z "$notes_file" || ( -f "$notes_file" && ! -L "$notes_file" ) ]] || { publish_fail 'Public notes must be a regular file.'; return 1; }
  umask 077
  work=$(mktemp -d "${TMPDIR:-/tmp}/xeas-publish.XXXXXX") || return 1
  trap 'rm -rf -- "$work"' EXIT
  mkdir "$work/payloads" "$work/metadata" "$work/public" || return 1
  publish_build_tool >/dev/null 2>&1 || { publish_fail 'Cannot build xeas-release; check the installed Go SDK and reviewed source.'; return 1; }
  # Copy inputs into a private workspace before inspecting them. Only RPMs that
  # pass the header/tag/signature checks enter the public output directory.
  for rpm in "${rpms[@]}"; do
    name=${rpm##*/}
    [[ "$name" =~ ^xe-antishell-[A-Za-z0-9._+~^-]+\.rpm$ ]] || { publish_fail 'Invalid agent RPM asset name.'; return 1; }
    [[ ! -e "$work/payloads/$name" ]] || { publish_fail 'Duplicate RPM asset name.'; return 1; }
    "$python_tool" - "$rpm" "$work/payloads/$name" <<'PYTHON' || { publish_fail 'Cannot stage a bounded regular RPM.'; return 1; }
import os, stat, sys
try:
    path, destination = sys.argv[1:]
    original = os.lstat(path)
    if not stat.S_ISREG(original.st_mode) or not 1 <= original.st_size <= 64 * 1024 * 1024:
        raise ValueError()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source, open(destination, "xb") as target:
        if not os.path.samestat(original, os.fstat(source.fileno())):
            raise ValueError()
        count = 0
        while True:
            chunk = source.read(min(1024 * 1024, 64 * 1024 * 1024 + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            if count > 64 * 1024 * 1024:
                raise ValueError()
            target.write(chunk)
        if count != original.st_size:
            raise ValueError()
except (OSError, ValueError):
    sys.exit(1)
PYTHON
    unsigned="$work/metadata/$name.unsigned.json"
    "$release_tool" prepare --rpm "$work/payloads/$name" --out "$unsigned" >/dev/null 2>&1 || {
      publish_fail 'RPM metadata preparation failed.'; return 1
    }
    staged_rpms+=("$work/payloads/$name")
    unsigned_files+=("$unsigned")
  done
  "$python_tool" - "$tag" "${unsigned_files[@]}" <<'PYTHON' || { publish_fail 'Tag, RPM headers or release targets do not agree.'; return 1; }
import json, re, sys
try:
    tag = re.fullmatch(r"v([0-9]+\.[0-9]+\.[0-9]+)-r([1-9][0-9]*)", sys.argv[1])
    majors, epochs = set(), set()
    for path in sys.argv[2:]:
        with open(path, encoding="utf-8") as source:
            manifest = json.load(source)
        package = manifest["package"]
        major = manifest["os_major"]
        if (not tag or manifest["os_family"] != "rhel" or major not in ("9", "10")
                or major in majors or package["name"] != "xe-antishell"
                or package["arch"] != "x86_64" or package["version"] != tag[1]
                or package["release"] != tag[2] + ".el" + major
                or manifest["artifact_name"] != "xe-antishell-" + tag[1] + "-" + package["release"] + ".x86_64.rpm"):
            raise ValueError()
        majors.add(major)
        epochs.add(package["epoch"])
    if len(epochs) != 1:
        raise ValueError()
except (OSError, ValueError, KeyError, TypeError):
    sys.exit(1)
PYTHON
  for rpm in "${staged_rpms[@]}"; do
    name=${rpm##*/}
    unsigned="$work/metadata/$name.unsigned.json"
    manifest="$work/public/$name.manifest.json"
    "$release_tool" sign --rpm "$rpm" --manifest "$unsigned" --key "$key" --out "$manifest" >/dev/null 2>&1 || {
      publish_fail 'Publisher signing failed; inspect key ownership/permissions and reviewed RPM metadata locally.'; return 1
    }
    "$release_tool" verify --manifest "$manifest" --rpm "$rpm" >/dev/null 2>&1 || {
      publish_fail 'Publisher signature or RPM verification failed; nothing was published.'; return 1
    }
    cp -- "$rpm" "$work/public/$name" || return 1
    assets+=("$name" "$name.manifest.json")
  done
  [[ -f "$XEAS_PUBLISH_ROOT/LICENSE" && ! -L "$XEAS_PUBLISH_ROOT/LICENSE" &&
     -f "$XEAS_PUBLISH_ROOT/THIRD_PARTY_NOTICES.md" && ! -L "$XEAS_PUBLISH_ROOT/THIRD_PARTY_NOTICES.md" &&
     -d "$XEAS_PUBLISH_ROOT/third_party/licenses" && ! -L "$XEAS_PUBLISH_ROOT/third_party/licenses" ]] || {
    publish_fail 'Reviewed project and upstream license notices are required.'; return 1
  }
  # Reject symlinks and non-text additions rather than archiving an arbitrary
  # runtime directory beside the maintained upstream license files.
  "$python_tool" - "$XEAS_PUBLISH_ROOT/third_party/licenses" "$work/license-paths" <<'PYTHON' || { publish_fail 'Invalid upstream license directory.'; return 1; }
import os, pathlib, sys
try:
    root = pathlib.Path(sys.argv[1])
    paths = []
    for directory, folders, files in os.walk(root):
        for name in folders + files:
            path = pathlib.Path(directory, name)
            if path.is_symlink():
                raise ValueError()
        for name in files:
            path = pathlib.Path(directory, name)
            if not path.is_file() or path.suffix not in (".txt", ".md"):
                raise ValueError()
            paths.append("third_party/licenses/" + path.relative_to(root).as_posix())
    if not paths:
        raise ValueError()
    pathlib.Path(sys.argv[2]).write_bytes(b"".join(os.fsencode(path) + b"\0" for path in sorted(paths)))
except (OSError, ValueError):
    sys.exit(1)
PYTHON
  cp -- "$XEAS_PUBLISH_ROOT/LICENSE" "$XEAS_PUBLISH_ROOT/THIRD_PARTY_NOTICES.md" "$work/public/" || return 1
  "$tar_tool" -C "$XEAS_PUBLISH_ROOT" --null --verbatim-files-from --no-recursion \
    -czf "$work/public/third-party-licenses.tar.gz" -T "$work/license-paths" || return 1
  assets+=(LICENSE THIRD_PARTY_NOTICES.md third-party-licenses.tar.gz)
  "$python_tool" - "$work/public" "${assets[@]}" <<'PYTHON' || return 1
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
with (root / "SHA256SUMS").open("x", encoding="ascii") as output:
    for name in sorted(sys.argv[2:]):
        output.write(hashlib.sha256((root / name).read_bytes()).hexdigest() + "  " + name + "\n")
PYTHON
  assets+=(SHA256SUMS)
  # Notes are outside the asset directory and are passed through a file, never
  # interpolated into a shell command or automatically uploaded as an asset.
  printf 'Xe-AntiShell %s\n\nPublisher-signed EL agent RPMs. Verify each signed manifest before installation.\n' "$tag" > "$work/notes.md"
  if [[ -n "$notes_file" ]]; then
    "$python_tool" - "$notes_file" "$work/notes.md" <<'PYTHON' || { publish_fail 'Public release notes must be bounded UTF-8 text.'; return 1; }
import pathlib, sys
try:
    path = pathlib.Path(sys.argv[1])
    if path.stat().st_size > 65536:
        raise ValueError()
    text = path.read_text(encoding="utf-8")
    if "\0" in text or "PRIVATE KEY" in text:
        raise ValueError()
    with open(sys.argv[2], "a", encoding="utf-8") as output:
        output.write("\n" + text + "\n")
except (OSError, UnicodeError, ValueError):
    sys.exit(1)
PYTHON
  fi
  mkdir -p -- "$(dirname -- "$output_dir")" || return 1
  mkdir -- "$output_dir" || { publish_fail 'Cannot create new output directory.'; return 1; }
  output_dir=$(cd -- "$output_dir" && pwd -P) || return 1
  for name in "${assets[@]}"; do
    cp -- "$work/public/$name" "$output_dir/$name" || return 1
    chmod 0644 "$output_dir/$name" || return 1
  done
  printf 'Verified public bundle: %s\n' "$output_dir"
  [[ "$publish" == true ]] || return 0
  # gh create fails for an existing release and --verify-tag avoids creating a
  # tag on an unintended commit. No --clobber, delete or automatic retry occurs.
  "$gh_tool" release create "$tag" --repo "$repository" --verify-tag --draft \
    --title "Xe-AntiShell $tag" --notes-file "$work/notes.md" >/dev/null 2>&1 || {
    publish_fail 'Cannot create draft release; check gh authentication, existing release and remote tag. Public bundle was preserved.'; return 1
  }
  local -a upload_paths=()
  for name in "${assets[@]}"; do upload_paths+=("$output_dir/$name"); done
  "$gh_tool" release upload "$tag" --repo "$repository" "${upload_paths[@]}" >/dev/null 2>&1 || {
    publish_fail 'Asset upload failed. The release remains a draft; inspect it manually before retrying. Public bundle was preserved.'; return 1
  }
  "$gh_tool" release edit "$tag" --repo "$repository" --draft=false >/dev/null 2>&1 || {
    publish_fail 'Assets were uploaded but publication failed. Inspect the draft manually. Public bundle was preserved.'; return 1
  }
  printf 'Published: https://%s/releases/tag/%s\n' "$repository" "$tag"
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then publish_main "$@"; fi

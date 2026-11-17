# 릴리즈 빌드·개발자 서명·중앙 배포 승인

## 목적과 신뢰 경계

개발자가 검토한 에이전트 RPM에 별도 publisher 서명을 붙이고, 중앙과
에이전트가 이를 각각 검증한다. 중앙 관리자의 배포 승인은 대상 서버·등록 세대·
업데이트 revision·설치 lease를 묶는 별도 서명이다. 중앙 배포 승인만으로 임의의
RPM을 설치할 수 없으며, publisher 서명만으로 서버에 설치가 시작되지도 않는다.

```text
검토한 소스 → unsigned RPM 빌드 → 개발자 RPM 검토 → publisher 서명·재검증
→ GitHub Releases 또는 RPM+서명 manifest 수동 업로드
→ 중앙 publisher 검증 → 운영자 대상 선택·미리보기·배포 승인
→ 에이전트 publisher/중앙 서명·대상·시간·현재 설치 상태 재검증
→ 독립 updater의 root RPM 설치 → 재시작·실행 버전·수집 확인 보고
```

현재 개발 호스트와 중앙 서비스 호스트는 같은 장비를 사용할 수 있다.
이는 **파일 소유권과 실행 계정에 의한 권한 분리**다. 물리적 분리나 root 침해에
대한 보호를 뜻하지 않는다. 중앙 웹 로그인 관리자와 publisher 키 사용자는
서로 다른 권한이며, 중앙 서비스 계정에는 키 디렉터리·파일의 읽기 권한,
sudo 경로, 키 읽기용 API를 부여하지 않는다. 같은 호스트의 root를 침해하면
이 경계도 무너지므로, 더 강한 분리가 필요하면 별도 서명 호스트나 하드웨어
키로 이전해야 한다.

publisher 개인키 기본 경로는
`/root/.local/share/xe-antishell-release/publisher-key.pem`이다. 개인 디렉터리는
root 전용 `0700`, 개인키는 root 소유 `0600`으로 유지한다. 서명 CLI가 소유권·
모드·일반 파일 여부를 검사한다. 이 경로는 RPM payload, 공개 소스, GitHub
artifact, 중앙 업로드, 릴리즈 자산에 포함하지 않는다. 개인키 내용이나 인증
토큰을 화면·로그·릴리즈 본문에 출력하지 않는다.

공개 신뢰 앵커는 shared protocol의 내장 publisher 공개키다. 중앙 UI에서
publisher 키를 등록·교체하지 않는다. 현재 승인된 키를 새로 생성한 키로 바꾸면
기존 중앙·에이전트가 거부하므로, 키 교체는 공개 앵커와 배포 순서를 별도로
검토해야 한다. `keygen`은 일반 릴리즈 단계가 아니다.

## GitHub Actions: unsigned 후보만 생성

[release-build.yml](../../.github/workflows/release-build.yml)은 수동 실행 또는
`v*-r*` 태그 push 시 EL9·EL10 / Linux amd64 두 작업을 실행한다.

- GitHub 권한은 `contents: read`이며 checkout에 Git 인증정보를 저장하지 않는다.
- 소스 개인정보 검사를 먼저 실행한 후, 해당 commit의 Git archive만 컨테이너에
  전달한다. 호스트의 `.git`, HOME, 개인키, 중앙 설정·DB·인증정보를 마운트하지 않는다.
- Rocky Linux 프로젝트 이미지와 호스트에서 준비한 read-only Go SDK를 사용한다.
  컨테이너에는 공개 소스 read-only와 전용 결과 디렉터리만 전달한다.
- 컨테이너 내부 root로 의존성 설치·빌드·메타데이터 준비를 실행한다. privileged,
  host network/PID, Docker 소켓, 호스트 서비스·커널 장치 마운트를 사용하지 않고
  CPU 2개·메모리 4GiB·PID 256개·작업 30분으로 제한한다.
- 같은 작업에서 가져온 이미지 ID로 빌드하고, RepoDigest·Go 버전·소스 commit·
  실제 OS 버전·RPM requires/scriptlets/files를 함께 보존한다. 이미지 태그와
  stable Go 선택은 바뀔 수 있으므로, 이것만으로 bit-for-bit 재현 빌드를 주장하지 않는다.
- 실제 RPM 헤더의 OS major와 x86_64를 검사한다. 태그 실행이면 version/release가
  태그와 일치해야 하며, CLI `prepare`로 unsigned 메타데이터를 생성한다.
- 7일 보관 artifact `unsigned-agent-el9-amd64` / `unsigned-agent-el10-amd64`에는
  RPM, `*.rpm.unsigned.json`, 검토용 빌드 기록과 라이선스가 들어간다.

이 workflow에는 publisher 개인키, Actions signing secret, keygen/sign 명령,
GitHub Release 게시 권한이 없다. 비밀값을 CI에 자동 등록·전송하지 않는다.
unsigned JSON은 검토 보조 자료이며 중앙에 업로드하는 서명 manifest가 아니다.
최종 서명 단계는 검토한 RPM을 다시 query·hash하고 별도 unsigned 메타데이터를
만들어 서명한다.

초기 matrix는 검증 대상인 EL9·EL10 x86_64만 포함한다. EL8, ARM, 실제 Rocky
커널의 eBPF·SELinux·systemd 동작을 이 컨테이너 빌드로 검증했다고 표시하지 않는다.
컨테이너는 호스트 커널을 공유한다.
[Rocky 이미지 소스](https://github.com/rocky-linux/sig-cloud-instance-images),
[userspace 검증 범위](../plans/rocky10-package-validation.md) 참고.

## 검토한 RPM을 로컬 공개 번들로 준비

먼저 artifact의 source commit·image digest와 실제 RPM의 패키지 정보, 파일 목록,
의존성, 설치 scriptlet, 주어진 OS의 독립 테스트 결과를 검토한다. RPM 설치는
root scriptlet을 실행하므로, 해시 일치만으로 신뢰할 수 있는 릴리즈가 되지는 않는다.
검토한 소스에서 도구를 빌드하고, 승인된 publisher 키를 가진 계정에서만 서명한다.

```bash
scripts/publish-release.sh \
  --tag v0.1.0-r24 \
  --rpm /reviewed/xe-antishell-0.1.0-24.el9.x86_64.rpm \
  --rpm /reviewed/xe-antishell-0.1.0-24.el10.x86_64.rpm \
  --output-dir /reviewed/public-v0.1.0-r24
```

이 명령의 기본 동작은 로컬 번들 생성이다. `gh`나 GitHub 접근 없이 서명·검증까지
실행한다. 예시 경로에는 실제 검토한 파일을 지정한다. 출력 디렉터리는 새 경로여야
하며 기존 파일을 덮어쓰지 않는다. 한 OS만 준비할 수도 있으나, 동일 OS 중복이나
서로 다른 epoch·version·release 조합은 거부한다.

태그 `v0.1.0-r24`는 실제 RPM 헤더가 다음과 같아야 한다.

| 항목 | 허용 값 |
| --- | --- |
| Name | `xe-antishell` |
| Version | `0.1.0` |
| Release | `24.el9` 또는 `24.el10` |
| Arch | `x86_64` |
| OS family / major | `rhel` / 해당 `9` 또는 `10` |
| Epoch | 두 RPM이 같아야 함; 서명 metadata에 보존 |

파일명도 실제 헤더의 version·release·arch와 일치해야 한다. 태그나 파일명만 바꿔서
다른 RPM을 게시할 수 없다. 입력 파일은 symlink가 아닌 1바이트~64MiB 일반 파일만
허용하고, 개인 작업 디렉터리에 복사하여 검사한다. 모든 RPM의 태그·헤더 검사가
끝난 다음 서명한다. 내장 공개키로 서명과 RPM 해시를 재검증한 파일만 공개 번들에
넣는다. 개인키는 CLI의 `--key FILE` 인자로 경로만 전달하며 복사하지 않는다.

완성 번들의 GitHub 업로드 목록은 다음으로 제한한다.

- 검증된 `xe-antishell-*.rpm`과 각 `*.rpm.manifest.json`
- 위 파일과 라이선스 자산을 포함하는 `SHA256SUMS`
- `LICENSE`, `THIRD_PARTY_NOTICES.md`, `third-party-licenses.tar.gz`

unsigned JSON, 도구 실행파일, 키 파일, 원본 작업 디렉터리, 호스트 설정·DB·
검토 로그는 업로드하지 않는다. upstream 라이선스 디렉터리도 symlink나 예상 외
파일이 있으면 거부한다. SHA256SUMS는 전송 확인용이며 publisher 서명을 대신하지
않는다. manifest는 패키지 메타데이터, OS, 크기·SHA256, artifact 이름·발행 시각을
묶고 `release-manifest` 도메인으로 서명한다.

직접 CLI를 실행하는 절차가 필요하면 [sign-release.sh](../../scripts/sign-release.sh)를
사용한다. 이 도구도 실제 RPM을 준비·서명·검증하지만 GitHub 게시나 RPM 설치는
실행하지 않는다. 중앙 수동 업로드에는 RPM과 **서명된** `*.rpm.manifest.json`
두 파일을 선택한다. 중앙은 서명 검증 후에도 artifact hash·크기·실제 RPM 헤더를
확인한다. GitHub 가져오기도 동일 검증을 통과해야 한다.

## 명시적으로 GitHub Release 게시

검토 후 권한 있는 개발자가 고정 저장소 `mkjang2000/Xe-AntiShell`에 일치하는
소스 태그를 미리 만들고 push한다. 스크립트가 태그나 commit을 대신 만들지 않는다.
GitHub CLI 설치·인증은 별도 준비하며 publisher 개인키를 GitHub secret으로 넣지 않는다.
`gh`가 없으면 서명 전에 고정된 설치·인증 안내를 표시하고 종료한다.

```bash
scripts/publish-release.sh \
  --tag v0.1.0-r24 \
  --rpm /reviewed/xe-antishell-0.1.0-24.el9.x86_64.rpm \
  --rpm /reviewed/xe-antishell-0.1.0-24.el10.x86_64.rpm \
  --output-dir /reviewed/published-v0.1.0-r24 \
  --notes-file /reviewed/release-notes.md \
  --publish
```

이 단계는 다시 서명·검증하고 새 공개 번들을 보존한 후 다음을 실행한다.

1. `gh release create --verify-tag --draft --notes-file ...`
2. `gh release upload`에 명시적인 공개 자산 경로만 전달
3. 업로드 성공 시에만 `gh release edit --draft=false`

릴리즈 본문은 임시 파일로 전달하여 셸 보간이나 긴 인자 처리를 피한다. 본문
파일은 공개해도 되는 UTF-8 텍스트만 지정하고 개인키나 토큰을 넣지 않는다.
본문 파일과 unsigned 메타데이터는 자산 목록에 포함하지 않는다.

기존 릴리즈가 있으면 생성 단계에서 실패한다. `--clobber`, 자산 삭제, 자동
덮어쓰기·재시도는 하지 않는다. 업로드 또는 공개 전환 실패 시 이미 만든
draft와 로컬 공개 번들을 남기므로, 관리자가 원격 상태를 확인해야 한다.
실패 원인 원문에 인증정보가 섞이지 않도록 `gh`의 출력은 재출력하지 않으며
고정된 단계별 오류 안내만 표시한다. 이들 API 호출은 하나의 원자적 트랜잭션이
아니다. [gh release create](https://cli.github.com/manual/gh_release_create),
[gh release upload](https://cli.github.com/manual/gh_release_upload) 참고.

## 운영 검증과 완료 판정

게시 완료는 에이전트 업데이트 완료와 다르다. 중앙에 릴리즈를 가져온 다음
publisher 검증 표시·키 ID와 대상 OS·arch를 확인하고, 한 대부터 미리보기와
배포 승인을 진행한다. 이전 에이전트는 초기 한 번 수동 업데이트가 필요할 수 있다.
에이전트가 재시작 후 실제 실행 버전·설치된 RPM·수집 점검 결과를 보고해야 완료로
판정한다. 설치 지시, 다운로드, staging, lease 발급만으로 성공 처리하지 않는다.
결과 미확인과 늦은 보고는 실패 상태를 임의로 성공으로 바꾸지 않는다.

개발 회귀는 `bash scripts/publish_release_test.sh`로 검사한다. 실제 개인키나
GitHub 요청 없이 mock CLI·mock gh·사용 불가능한 키 fixture로 태그 불일치,
서명·검증 실패, 자산 allowlist, 비밀 출력 억제, upload 실패 후 공개 금지를
검증한다. 실제 암호 검증·키 파일 권한은 `internal/releasepublish`와 shared
protocol 테스트에서 다룬다. workflow YAML/내장 셸 검사는 로컬에서 가능하지만,
최초 Actions 빌드와 실제 GitHub 게시, 중앙 import 및 서버 업데이트는 각각
별도의 실제 결과를 확인해야 한다.

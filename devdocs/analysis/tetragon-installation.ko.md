# Tetragon 설치와 수집 확인

명령 예시는 Rocky Linux 10 x86_64 기준입니다. 배포판 이름만으로 커널 후크
지원이나 아래 확장 정책의 실측 검증이 완료되었다고 판단하지 않습니다.
에이전트와 중앙 등록이 완료된 서버에
프로세스 수집기를 추가합니다. 중앙 등록 토큰이나 복구 파일을 다시 입력하지
않습니다. 자동 차단은 켜지지 않습니다.

## 설치 스크립트 사용

최신 설치 스크립트와 `packaging/` 디렉터리를 함께 받은 위치에서 실행합니다.
이미 설치된 에이전트 RPM을 다시 받을 필요는 없습니다.

```bash
sudo ./install.sh --tetragon-only
```

고정된 공식 v1.8.0 배포본(약90MB)을 다운로드해 SHA256을 확인하고,
Tetragon 서비스와 기존 에이전트의 수집기 설정을 연결합니다. 필요한 경우
Python3/PyYAML 패키지를 dnf로 설치합니다. 서비스 상태, 무해한 실제 실행
이벤트, 에이전트 수신을 확인한 뒤 성공으로 표시합니다. 실패하면 기존
에이전트 수집기 설정과 서비스 상태를 복구합니다.

미리 받은 공식 아카이브를 사용할 수도 있습니다.

```bash
sudo ./install.sh --tetragon-only \
  --tetragon-archive /root/tetragon-v1.8.0-amd64.tar.gz
```

새 서버의 인자 없는 설치 마법사는 Tetragon 설치 여부를 묻습니다.
자동 설치에서는 명시적으로 선택합니다.

```bash
sudo ./install.sh --rpm ./agent.rpm --with-tetragon
```

기존에 별도로 관리하던 Tetragon 서비스나 다른 에이전트 설정 경로가 있으면
자동 덮어쓰기를 중단합니다. 해당 경우 아래 수동 절차를 참고해 기존 구성에
통합해야 합니다. DB, 중앙 인증서, 등록 키, 복구 파일은 설치 대상이 아닙니다.

## 선택적 인라인·파일 쓰기·TCP 시작 관측

기본 설치는 프로세스 exec/exit 수집을 연결합니다. 아래 확장은 별도 선택이며,
관측 기능을 지원하는 새 에이전트와 최신 전체 `packaging/` 디렉터리가 필요합니다.
먼저 도움말과 적용 범위를 검토합니다.

```bash
python3 packaging/tetragon/observations.py --help
```

인자 없이 실행하거나 `--apply`를 빼면 사용법만 출력하고 변경하지 않습니다.
검토한 대상 호스트에서 명시적으로 적용할 때만 다음을 실행합니다.

```bash
sudo python3 packaging/tetragon/observations.py --apply
```

전제는 root, Python 3.9+/PyYAML, x86_64, 읽을 수 있는 커널 BTF와 실행 중인
설치기 소유 Tetragon v1.8.0·sentineld입니다. 설치기가 관리하는 정확한 unit,
실행파일과 기본 에이전트 설정을 확인합니다. 아래 수동 설치 예제나 별도 관리
Tetragon, 사용자 정의 unit/drop-in, 같은 이름의 비소유 정책, 변경된 소유 파일은
자동 통합 대상이 아닙니다. 사전 확인에서 중단되면 기존 파일을 덮어쓰지 말고
수동 통합 범위를 검토합니다. 이 명령은 에이전트 RPM을 갱신하거나 중앙 정책,
확장 탐지 옵션, 자동 종료를 켜지 않습니다.

| 관측 | 실제 범위와 해석 |
| --- | --- |
| 인라인 옵션 | Python `-c`, Node `-e`/`--eval`/`-p`/`--print`, PHP `-r`, Perl `-e`/`-E`, Ruby `-e`. argv[0] 다음 위치 0–2의 정확한 옵션과 앞선 허용 switch만 검사합니다. Tetragon v1.8 내부 맵 한도 때문에 선행 switch는 최대 2개입니다. 스크립트 뒤의 `-c` 등을 인라인으로 판정하지 않습니다. 옵션 관측은 유효한 코드나 실행 성공의 증거가 아닙니다. |
| 파일 쓰기 | 고정 실행파일 이름과 선택한 경로 접두사에 속하는 일반 파일의 `vfs_write`. 반환값 양수는 쓴 바이트 수, 0은 기록 없음, 음수는 실패, 반환값 없음은 미상입니다. 디스크 영속성까지 보장하지 않습니다. |
| TCP 연결 | 고정 실행파일 집합의 `tcp_v4_connect`/`tcp_v6_connect`. 반환값 0은 연결 시작(`initiated`), 음수는 실패, 없음은 미상입니다. 연결 수립·전달 성공·HTTP 통신 성공을 뜻하지 않습니다. |

커널 필터의 실행파일 집합은 알려진 웹 worker, Python/Node/PHP/Perl/Ruby,
Java/.NET, 셸과 `curl`/`wget`/`nc`/`ncat`/`netcat`/`socat` 등으로 제한합니다.
root가 신뢰하는 설치 경로의 정규 버전 이름과 alternatives 대상도 확인합니다.
커널의 실행파일 선택은 `/python3` 같은 이름 접미사 기준이며, 실행파일의
전체 디렉터리나 digest를 고정해 검증하는 정책은 아닙니다.
임의 이름으로 바꾼 바이너리와 사용자 정의 실행파일까지 포괄하지 않습니다.
파일 기본 경로는 `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/var/www/`, `/srv/`입니다.
다음처럼 `--file-prefix`를 반복하면 기본 집합을 **대체**합니다. 검증용 `/tmp/`는
필수이며 루트 `/` 전체 관측은 허용하지 않습니다.

```bash
sudo python3 packaging/tetragon/observations.py --apply \
  --file-prefix /tmp/ --file-prefix /srv/app/
```

이미 적용한 소유 정책의 경로 범위 변경은 자동 덮어쓰지 않고 수동 검토를 요구합니다.
모든 writev/mmap/io_uring 쓰기, UDP, 파일 내용이나 패킷 본문은 수집하지 않습니다.
커널의 실행파일·경로 선택 뒤 에이전트가 설정된 웹 출처를 다시 확인해 보존합니다.
셸 후보 필터만으로 행위 이벤트를 선택하지 않으며, 파일/연결 관측 자체로 악성
finding을 만들거나 코드의 원인을 확정하지 않습니다. 샘플링은 적용하지 않으므로
이 제한된 범위도 호스트의 처리량에 따라 부하가 달라집니다.

### 적용 확인과 복구 범위

도우미는 소유 정책을 monitor-only로 추가하고 모든 후크의 로드를 확인합니다.
설치된 런타임별 무해한 인라인 양성/스크립트 우선 음성 실행, private `/tmp` 파일의
1바이트 쓰기, loopback TCP 연결 시작을 PID와 exec ID가 같은 실제 이벤트로
확인합니다. 외부 주소에 연결하지 않습니다. argv·환경변수를 제외하는 구독으로
에이전트 설정이 바뀌면 sentineld를 재시작하며, 기존 Tetragon 본체는 재시작하지
않습니다. 마지막으로 에이전트의 실제 이벤트 수신과 상태를 확인합니다.

```bash
sudo sentinel status
sudo sentinel capabilities
```

런타임이 미설치이거나 IPv6 후크·소켓·이벤트를 확인하지 못하면 해당 범위는
미검증으로 남습니다. 가능한 IPv4 관측은 유지할 수 있으므로 성공 메시지가
모든 런타임/IPv6 지원을 뜻하지 않습니다. 정책 파일은
`/opt/xe-antishell/tetragon/policies/`에, 소유권·해시·확인 시각·
`verified_runtime_policies`·`verified_network_families`는 root 전용
`/opt/xe-antishell/tetragon/observations.json`에 기록합니다. 이 메타데이터나
기존 exec 수신만으로 파일/네트워크/인라인 기능을 `ACTIVE`로 올리지 않습니다.
에이전트가 각 유형의 유효한 관측을 실제로 받아야 합니다.

실패·일반 종료 신호 시 새로 추가한 소유 정책을 제거하고 이전 파일·manifest·
에이전트 설정과 실행 상태의 복구를 시도합니다. 일부 복구 실패는 별도로 알리며,
진단 백업은 root 전용 `/var/lib/xe-antishell/tetragon-install-backups/`에 남습니다.
강제 종료나 전원 차단까지 자동 복구를 보장하지는 않습니다. 검증된 동일 범위의
재실행은 불필요한 정책 추가·에이전트 재시작을 피합니다. 전용 제거 옵션은 없으므로
완료 후 제거·범위 변경은 소유 정책과 백업을 확인한 수동 작업입니다.

EL9 커널 `5.14.0-687.66.1.el9_8.x86_64`의 격리 인스턴스에서 정책 11개 로드,
설치된 Python·Node·PHP·Perl의 인라인 양성/음성, 실제 1바이트 쓰기와 IPv4/IPv6
loopback 연결 시작을 확인했습니다. Ruby는 미설치로 미검증입니다. 기존 서비스는
유지했고 임시 BPF 자원은 제거했습니다. **다른 대상 커널과 지속 운영 부하는
별도 검증이 필요합니다.** 후크 지원, 이벤트 누락, CPU/메모리·DB/전송량과
정상 작업을 확인해야 하며 이 실측을 모든 I/O 경로의 지원으로 일반화하지 않습니다.

### 코드·인자 보존의 개인정보 경계

신규 인라인 관측은 런타임·고정 옵션·증거 방식만 보존하며 코드 본문이나 그
해시를 저장하지 않습니다. 알려진 다섯 인터프리터의 argv와 raw payload는
분류하지 못한 호출도 에이전트 큐 전에 제거합니다. 새 행위 이벤트의 raw payload와
ancestor argv도 제거합니다. 확장 구독은 Tetragon 서버에서도 process/parent/
ancestors의 arguments·environment_variables를 제외합니다. 단, upstream
Tetragon 내부의 일시적 옵션 선택용 인자 캐시를 제거하는 기능은 아닙니다.

기존 셸 `-c`의 본문까지 일괄 제거하는 변경은 포함하지 않습니다. 해당 경로는 기존
민감 인자 이름 redaction 정책을 따르므로 임의 셸 코드가 모두 지워진다고 가정하면
안 됩니다. 일반 raw 수집은 기본 비활성 상태를 유지합니다. 기존 DB와 outbox를
재작성하지 않으며, 구버전 원본을 같은 ID로 새 정규화 경로에 재입력하면 개인정보
정규화 차이로 충돌할 수 있습니다. 자세한 경계는
[호출 증거·개인정보 설계](../plans/execution-evidence-detection.md)를 참고합니다.

Phase 3인 기존 프로세스 내부 코드 실행은
[상세 설계만 완료](../plans/in-process-code-observation.md)했습니다.
PHP/JVM/Python/Node의 compile/eval, USDT/uprobe, 언어 agent 센서는 아직 구현하지
않았으며 파일 쓰기·연결 시작을 내부 코드 실행 증거로 표시하지 않습니다.

[고정 v1.8.0 근거와 범위](../research/tetragon-observations.md),
[공통 관측 계약](../plans/execution-and-io-observations.md)도 함께 검토합니다.

## 수동 설치

아래 절차는 Tetragon을 처음 설치하는 호스트 기준입니다. 기존 Tetragon
서비스·설정이 있는 호스트에는 그대로 덮어쓰지 않습니다. 각 명령이 성공한
것을 확인하고 다음 단계로 진행합니다.

### 1. 배포본 다운로드와 검증

```bash
sudo dnf -y install curl tar gzip
sudo -i
umask 077
XEAS_TETRA_WORK=$(mktemp -d /root/xeas-tetragon-manual.XXXXXX)
cd "$XEAS_TETRA_WORK"
test -r /sys/kernel/btf/vmlinux
test "$(uname -m)" = x86_64
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output tetragon-v1.8.0-amd64.tar.gz \
  https://github.com/cilium/tetragon/releases/download/v1.8.0/tetragon-v1.8.0-amd64.tar.gz
printf '%s  %s\n' \
  e88691c5f05a2a61aba58974a080603050b924c7f13ecc06f3d05172feb05f59 \
  tetragon-v1.8.0-amd64.tar.gz | sha256sum --check -
tar -xzf tetragon-v1.8.0-amd64.tar.gz
```

공식 아카이브 안의 `install.sh`는 즉시 서비스를 시작하므로 이 절차에서는
다음 단계에서 필요한 파일과 서비스를 직접 설치합니다.

### 2. 파일과 관찰용 서비스 설치

```bash
install -d -m 0755 /opt/xe-antishell/tetragon/manual-v1.8.0/bpf
install -m 0755 tetragon-v1.8.0-amd64/usr/local/bin/tetragon \
  /opt/xe-antishell/tetragon/manual-v1.8.0/tetragon
install -m 0755 tetragon-v1.8.0-amd64/usr/local/bin/tetra \
  /opt/xe-antishell/tetragon/manual-v1.8.0/tetra
cp -R tetragon-v1.8.0-amd64/usr/local/lib/tetragon/bpf/. \
  /opt/xe-antishell/tetragon/manual-v1.8.0/bpf/
chmod -R go-w /opt/xe-antishell/tetragon/manual-v1.8.0
install -d -m 0700 /var/lib/xe-antishell/tetragon-empty-policies
```

빈 정책 디렉터리에 다른 정책을 넣지 않습니다. 다음 파일을
`/etc/systemd/system/tetragon.service`에 root 소유·0644로 저장합니다.

```ini
[Unit]
Description=Tetragon process observation for Xe-AntiShell
After=local-fs.target

[Service]
Type=simple
WorkingDirectory=/
ExecStart=/opt/xe-antishell/tetragon/manual-v1.8.0/tetragon --bpf-lib=/opt/xe-antishell/tetragon/manual-v1.8.0/bpf --server-address=unix:///run/tetragon/tetragon.sock --export-filename= --health-server-address=127.0.0.1:6789 --metrics-server=127.0.0.1:2112 --enable-k8s-api=false --k8s-kubeconfig-path= --enable-process-cred=true --enable-process-environment-variables=false --enable-ancestors=base --process-cache-size=32768 --tracing-policy-dir=/var/lib/xe-antishell/tetragon-empty-policies --tracing-policy= --persist-grpc-policies=false
RuntimeDirectory=tetragon
RuntimeDirectoryMode=0700
UMask=0077
LimitMEMLOCK=infinity
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

API는 root만 접근할 수 있는 Unix 소켓을 사용합니다. 6789(gRPC health)와
2112(metrics)는 localhost에만 열며 외부 방화벽 개방은 필요하지 않습니다.
SELinux를 비활성화하지 않습니다. 시작 실패 시 실제 journal 원인을 확인합니다.

```bash
systemctl daemon-reload
systemctl enable --now tetragon.service
/opt/xe-antishell/tetragon/manual-v1.8.0/tetra \
  --server-address unix:///run/tetragon/tetragon.sock \
  --timeout 5s --retries 0 status </dev/null
```

`Health Status: running`인지 확인합니다. `initializing`은 아직 준비 완료가
아닙니다. 기존 `/etc/tetragon`과 전역 Tetragon 설정도 별도로 검토해야 합니다.

### 3. 기존 에이전트 설정 연결

```bash
cp -p /etc/xe-antishell/sentineld.yaml "$XEAS_TETRA_WORK/sentineld-before.yaml"
chmod 0600 "$XEAS_TETRA_WORK/sentineld-before.yaml"
sudoedit /etc/xe-antishell/sentineld.yaml
```

기존 파일의 다음 값만 변경합니다. 나머지 agent/DB 경로, 수집 필터,
privacy/detection/response 등은 유지합니다.

```yaml
collector:
  mode: tetragon
  tetragon:
    command: /opt/xe-antishell/tetragon/manual-v1.8.0/tetra
    args:
      - --server-address
      - unix:///run/tetragon/tetragon.sock
      - getevents
      - -o
      - json
```

위 블록으로 기존 `collector` 전체를 지우면 audit 설정과 필터가 소실될 수
있습니다. 해당 필드만 수정하세요. `response.allow_terminate`를 켜지 않습니다.

`/etc/systemd/system/sentineld.service.d/tetragon.conf`에는 다음을 저장합니다.

```bash
install -d -m 0755 /etc/systemd/system/sentineld.service.d
sudoedit /etc/systemd/system/sentineld.service.d/tetragon.conf
```

```ini
[Unit]
Wants=tetragon.service
After=tetragon.service
```

```bash
systemctl daemon-reload
systemctl restart sentineld.service
sentinel status
sentinel capabilities
```

### 4. 실제 이벤트 확인

다른 터미널에서 `/usr/bin/true`를 몇 차례 실행한 후 아래를 확인합니다.

```bash
/usr/bin/true
sentinel status
sentinel capabilities
sentinel managed status
```

`collector`가 `tetragon-json`이고 `collector_health.running`이 true이며,
`events_received`와 실행 관찰의 최근 확인 시각이 갱신되어야 합니다.
중앙 패널에서도 다음 상태 보고 후 수집 상태가 바뀌는지 확인합니다.
이 검증은 프로세스 수집 연결 확인입니다. 웹쉘 탐지 정확도는 별도의
정상/의심 시나리오로 검증합니다.

수동 변경을 되돌릴 때는 저장한 설정을 복원하고 추가한 에이전트 drop-in을
제거한 뒤 `systemctl daemon-reload`, `systemctl restart sentineld`를 실행합니다.
이번에 새로 설치한 Tetragon은 `systemctl disable --now tetragon`으로 중지할 수
있습니다. 기존에 사용하던 Tetragon에는 이 중지 명령을 적용하지 않습니다.

## 참고

- [공식 패키지 설치](https://tetragon.io/docs/installation/package/)
- [공식 v1.8.0 배포본](https://github.com/cilium/tetragon/releases/tag/v1.8.0)
- [기존 Tetragon 적용 설계](../plans/tetragon-runtime-rollout.md)

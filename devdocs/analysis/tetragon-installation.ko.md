# Tetragon 설치와 수집 확인

대상은 Rocky Linux 10 x86_64입니다. 에이전트와 중앙 등록이 완료된 서버에
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

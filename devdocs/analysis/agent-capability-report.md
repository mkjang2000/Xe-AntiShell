# Xe-AntiShell Agent 실제 탐지·관측 기능 분석

## 개발본 · 서비스별 파일 및 TCP 경보

내장 규칙은 16개다. 적용 중인 웹 서비스 목록과 호스트의 `service_observations` 범위가 일치하면 보호 파일에 대한 양수 쓰기와 허용 주소·포트 목록 밖으로 시작된 TCP 연결을 각각 탐지한다. 예외 경로의 정상 쓰기, 실패한 쓰기·연결, 결과 미상은 관측으로 남는다. 원본 이벤트를 경보 근거로 묶고 자동 대응은 수행하지 않는다. [서비스별 규칙](../plans/service-observation-rules.md)

RPM 32–33의 운영 하트비트를 확인한 2026-11-18 18:40 KST에는 Tetragon 호스트 네 대 중 한 대에서 파일 및 TCP 이벤트 수신 시각이 확인됐다. 다른 세 대는 두 센서 모두 `unverified`였다. 이 시점의 측정은 개발본 규칙 배포 전 상태다.

## 배포 에이전트 · RPM 32–33

RPM 32부터 일반 관측은 기본 60분 동안 최소 정보로 보존한다. 경보의 점수·규칙·근거와 미전송 이벤트는 보호한다. 네 호스트에서 최소 저장 정책이 적용된 것을 확인했다. 에이전트는 이미 저장용으로 줄인 관측을 전송에도 사용한다. 센트럴 RPM 17의 수신 영수증 변경은 에이전트에 추가 압축·해시 연산을 요구하지 않는다. [최소 관측 이력](../plans/minimal-observation-history.md)

RPM 33은 SELinux Enforcing 호스트의 RPM scriptlet 도메인 전환을 지원하도록 업데이터 유닛을 변경했다. 해당 호스트의 RPM 33 설치는 확인했고, 다음 에이전트 패치의 중앙 자동 설치는 검증 대기 중이다. [업데이터 전환과 검증](../plans/managed-agent-updates.md#selinux-rpm-scriptlet-transition)

## 탐지 기능 및 배포 당시 측정 · RPM 31

2026-11-18 14:14 KST 배포 검증 기록을 기준으로 정리했다. 에이전트는 공유 프로토콜 `v0.3.1`을 사용한다. 이 개정에서 운영 수치를 새로 조회하지 않았으므로 아래 수치는 배포 당시의 관측값이다. [운영 업데이트 기록](../plans/operator-rules-observations-capacity.md#운영-업데이트-결과)

### 탐지·관측·운영 기능

| 기능 | RPM 31에서 확인할 수 있는 범위 | 근거 |
| --- | --- | --- |
| 웹 출처 실행 탐지 | 기본 프로필은 셸·관리자 권한 셸을 탐지한다. 확장 프로필은 일부 도구, 임시 실행 파일·스크립트, 인터프리터 인라인 호출을 다루며 탐지 전용으로 동작한다. | [탐지 엔진](../../internal/detection/engine.go) · [확장 규칙](../../internal/detection/extended.go) |
| 전역 권한 관측·탐지 | 선택형 권한 프로필이 root 실행과 변경 전후 자격 증명을 평가한다. root 실행은 기본 모드인 `suspicious`에서 문맥 점수가 기준을 넘을 때 경보를 내며 `all`에서 범위를 넓힐 수 있다. root 복귀·호스트 root 획득·범위 미확인 root 신원 변경·Capability 증가와 활성화를 구분하며 모두 탐지 전용이다. | [root 실행](../../internal/detection/privilege.go) · [자격 증명 규칙](../../internal/detection/privilege_credentials.go) |
| 규칙 현황·비교 | `sentinel rules`와 패널에서 내장 규칙 14개의 버전, 적용 정책 및 리비전, 정책 활성 여부, 필수 근거와 센서 수신 상태를 본다. 경보 이력은 같은 한글 제목으로 검색된다. `sentinel rules compare`는 동일 호스트·부팅의 정규화 JSONL 표본으로 두 로컬 YAML의 경보 추가·감소·변경을 비교한다. | [규칙 카탈로그](../../internal/detection/catalog.go) · [오프라인 비교](../../internal/agent/rule_comparison.go) |
| 파일·TCP 표본 | `sentinel observations`와 패널에서 관측 당시의 서비스, 파일 쓰기 반환값, TCP 연결 시작·실패·결과 미상을 조회한다. 서비스의 보호 경로에 양수 바이트를 쓴 표본을 검토 후보로 표시하고 허용 경로를 제외할 수 있다. 현재는 관측 및 검토 단계이며 파일·TCP 자동 경보는 미구현이다. | [표본 조회](../../internal/storage/observation_samples.go) · [경로 판정](../../internal/model/observation_samples.go) |
| 수집 스트림 복구 | Tetragon 구독이 종료되면 지수 백오프로 다시 연결한다. 새 구독에서 고유 이벤트가 SQLite에 커밋된 시점을 복구로 기록하고 중단 구간을 상태에 표시한다. 실커널 구독 장애 주입은 후속 검증 범위다. | [수집 복구 설계와 검증](../plans/collector-recovery.md) |
| 저장·전송 측정 | `sentinel capacity`, 패널 및 중앙 heartbeat에서 UTC 일일 저장량, DB·WAL·가용 공간, 큐 수위·드롭 원인, 전송 대기량과 손실을 확인한다. 단절 후 첫 진행 ACK와 대기열 소진을 각각 기록하며 마지막 구간은 데몬이 재시작돼도 보존된다. | [저장 측정](../../internal/storage/capacity.go) · [전송 측정](../../internal/storage/delivery_capacity.go) |

TCP 센서는 연결 시도의 반환값을 보고한다. 연결 성립과 전송 내용, 파일 내용 분석, 기존 프로세스 내부의 코드 실행 탐지는 여전히 검증·구현 범위에 제한이 있다. 운영에서 권한 변경 센서 수신은 두 호스트에서 확인됐고, RPM 27의 통제된 EL9 실험에서 기존 root 자격 복귀 경보가 중앙까지 전달됐다. 독립적인 Capability 증가 경보의 운영 검증은 남아 있다. [실커널 권한 검증](../research/credential-sensor-live-proof.md)

### 운영 배포 결과

| 대상 | 설치·실행 버전 | 정책 리비전 | 중앙 설치 및 수집 | 재시작 뒤 관찰 |
| --- | --- | --- | --- | --- |
| Rocky 10 호스트 | `0.1.0-31.el10.x86_64` | 4 | `succeeded` · `verified` | 실행·권한 변경 수신, 이벤트 저장 증가 |
| Rocky 9 호스트 | `0.1.0-31.el9.x86_64` | 5 | `succeeded` · `verified` | 실행·권한 변경 수신, 이벤트 저장 증가 |

최종 배포 후 각 호스트를 70초 동안 관찰했다. 입력 드롭, 파싱 오류, 중앙 전송 손실은 각 0건이었다. EL9에서 파일·TCP 센서 수신도 확인했다. EL10의 파일·TCP 센서는 이 관찰에서 새 수신을 확인하지 못했다. 장시간 부하와 센서별 탐지율은 별도 검증 범위다. [운영 검증 기록](../plans/operator-rules-observations-capacity.md#운영-업데이트-결과)

EL9의 RPM 29에서는 프로세스 이력 정리 중 큐 시간 초과로 입력 드롭 169건을 기록했다. RPM 30은 프로세스 정리를 제한된 페이지로 나눴으나 로컬 API가 약 65초 후 준비돼 업데이터의 60초 점검 기한을 넘겼다. RPM 31은 시퀀스 복원에 기존 인덱스를 사용하도록 수정했고, 같은 호스트에서 데몬 초기화부터 API 준비까지 약 46ms가 걸렸다. 최종 확인에서 EL9의 에이전트 DB는 32.2 GiB이고 해당 파일시스템의 가용 공간은 4.8 GiB였다. [대용량 DB 기동과 검증](../plans/operator-rules-observations-capacity.md#대용량-기존-db에서의-기동)

RPM 31 소스의 Go race·vet와 EL9·EL10 패키지 기반 CLI·데몬 검증을 통과했다. 파일·TCP 표본 3건을 넣어 검토 후보 1건, 경보 0건, 저장 3건을 확인했다. 중앙 단절 시험은 별도의 루프백 환경에서 두 에이전트가 각각 65건을 쌓은 뒤 약 2초 만에 전량 ACK를 받았고 양쪽 전송 손실은 0건이었다. [시험 범위와 측정값](../plans/operator-rules-observations-capacity.md#구현-결과와-격리-시험)

## 과거 분석 · RPM 24

아래의 상태표, 테스트 식별자와 실서버 수치는 최초 분석 시점에 해당한다. RPM 25 이후 탐지 기능과 보존 정책은 위의 RPM 31 및 RPM 32–33 절에 정리했다.

- 분석일: 2026-11-18, Asia/Seoul.
- Agent 소스: `7533d0efad79cbe272bf2d7d89e806e047b21916`, protocol `v0.2.0`.
- 운영 확인: Rocky Linux 9.8 / x86_64 / 커널 `5.14.0-687.66.1.el9_8.x86_64`, Agent RPM24.
- 범위: 소스·수집 정책 생성 코드·테스트 본문을 확인했다. 구현 코드는 수정하지 않았다. 운영 API는 상태만 읽었으며, 공격 실행·차단 활성화·정책 변경·업데이트 재실행은 하지 않았다.


> 후속 변경: RPM25 (`30c87396b806c9aea155d062f47a7e7d646fb076`)에서 SQLite를 단일 연결로 직렬화하고, 증거 저장의 BEGIN 예약 실패만 제한 재시도하며, 실제 저장 성공 시 해당 오류만 복구하도록 수정했다. 시작 background 작업 분산과 retention 유예도 추가했다. 아래 본문은 명시한 RPM24 분석 기준을 보존한다. 특히 pool4·저장 오류 상태 잔류·미저장 실패 미계수 설명은 RPM24의 동작이며, RPM25 변경·검증 근거는 [안정성 설계/검증](../plans/sqlite-startup-stability.md)에 별도 기록했다. 탐지 규칙·관측 범위·차단 정책은 이 패치에서 확장하지 않았다.

### 1. 판단 기준과 요약

이 보고서의 상태는 배타적인 한 단계가 아니라 다음 다섯 가지 근거를 구분한 것이다.

| 상태 | 의미 |
| --- | --- |
| **구현** | 실제 실행 경로와 처리 코드가 존재함. 설정·외부 수집기 등의 조건은 별도임 |
| **테스트 통과** | 이번 분석에서 해당 테스트 패키지/도우미를 실제 실행해 통과함. 합성 입력과 mock은 실서버 공격 검증으로 승격하지 않음 |
| **실서버 검증** | 날짜가 있는 기존 운영 검증 기록 또는 이번 운영 읽기에서 실제 동작을 확인함. 확인한 OS·후크·시나리오에만 적용 |
| **미검증** | 구현은 있으나 해당 환경·공격·전체 연결 경로의 실제 검증 근거가 없음. 확인 불가도 여기에 명시 |
| **미구현** | 실행 가능한 해당 수집/탐지/대응 경로가 없음. 계획·UI 입력·환경 검사만으로 구현이라 판단하지 않음 |

현재 제품은 **웹 출처의 프로세스 실행을 중심으로 하는 행위 탐지기**다. 웹셸 파일의 내용·시그니처를 검사하는 스캐너, 모든 RCE를 탐지하는 런타임 센서, 실행 전 차단 엔진은 아니다.

주요 결론은 다음과 같다.

1. 기본 탐지는 웹 출처의 셸·root 셸이다. 명시적으로 활성화하는 확장 프로필은 특정 외부 도구, 임시 실행 파일, 일부 인터프리터 실행 옵션까지 탐지한다.
2. 파일은 **제한된 프로그램·경로의 `vfs_write`**, 네트워크는 **제한된 프로그램의 TCP connect 시작**을 관측한다. 파일 읽기·삭제·모든 변경이나 전체 소켓 활동을 수집하지 않는다.
3. `file.write`·`network.connect`는 저장·전송되는 관측 이벤트다. **현재 탐지 엔진에는 이 두 이벤트 자체를 경보·점수로 바꾸는 규칙이 없다.**
4. UID/EUID 스냅샷은 있으나 자격 증명 변경 추적과 일반적인 신규 root 프로세스 탐지는 없다.
5. 확장 프로필의 모든 finding은 `DetectionOnly=true`다. 높은 점수나 중앙 enforce 정책으로도 이 finding을 종료 대상으로 바꿀 수 없다.
6. 중앙 업데이트는 실제 구현돼 있고, 현재 Rocky 9 서버 한 대의 23→24 배포가 검증됐다. 이것이 Rocky 10 커널 관측이나 다른 서버의 차단 검증을 뜻하지는 않는다.

### 2. 확인한 실행 경로

```text
Tetragon JSON / audit dispatcher / replay
→ 정규화·인자 비식별화·크기 제한
→ 유한 큐
→ 계보 또는 operation context 갱신
→ 출처·실행 파일 보존 필터
→ Engine.Evaluate
→ 이벤트·계보·finding·중앙 outbox 원자 저장
→ 별도 조건을 만족하는 경우에만 pidfd SIGTERM
```

근거: [service.go](../../internal/agent/service.go)의 `Submit`, `processEvent`, `selectCollector`, [event_normalization.go](../../internal/agent/event_normalization.go)의 `normalizeEvent`, `sanitizeEventPrivacy`, [managed.go](../../internal/storage/managed.go)의 `PersistObservation`.

중요하게도 **커널에서 관측됨 → 에이전트에서 수신됨 → DB에 보존됨 → finding 생성됨 → 종료됨**은 서로 다른 단계다. 기능 가용성 `active`는 마지막 두 단계까지의 보장이 아니다.

### 3. 이벤트 수집 범위

#### 3.1 기능별 상태표

테스트 식별자 T1~T8과 실서버 근거 L1~L3는 뒤의 검증 절에 정의한다.

| 기능 | 구현 상태·정확한 범위 | 테스트 | 실서버 및 미검증 범위 | 코드·함수 |
| --- | --- | --- | --- | --- |
| 프로세스 실행 | **구현**: Tetragon `process_exec`, audit `EXECVE` 조합, replay | **테스트 통과** T1/T2 | **실서버 검증** L1/L2의 Tetragon. 전체 audit 운영 경로는 **미검증** | `collector/tetragon.go:NormalizeTetragonJSON`; `collector/audit.go:AuditAssembler.normalize` |
| 프로세스 종료 | **구현**: Tetragon `process_exit`. audit 종료 스트림은 **미구현** | **테스트 통과** `TestNormalizeTetragonProcessExit` | 종료 어댑터는 테스트됨. 이번 상태 API에는 종료 수신의 독립 증명이 없어 현재 실제 종료 경로는 **확인 불가** | `NormalizeTetragonJSON`, `lineage.Tracker.ExitObserved` |
| 계보 | **구현**: ExecID/ParentExecID, PPID 추론, procfs 시작 스냅샷, source ancestors | **테스트 통과** T1~T3 | **실서버 검증** L1/L2. 모든 조상·짧은 프로세스 보장은 **미검증** | `lineage/tracker.go:Observe, ObserveContext, Ancestors`; `agent/tetragon_context.go:observeTetragonAncestors` |
| UID/EUID/GID/EGID | **구현**: 실행·관측 시점의 값. Tetragon top-level UID는 EUID로 처리, real UID 등은 credentials 객체가 있어야 채움 | **테스트 통과** `TestTetragonUsesEffectiveUIDForRootShell`, `TestTetragonProcessCredentialsPreserveRealAndEffectiveIDs` | 해당 네 필드의 모든 실제 입력 조합은 **미검증** | `tetragonToProcess`, `auditCredential`, `procfs.readCredentials` |
| setuid/setgid·Capability 변경 | **미구현**: 지속 변경 이벤트·전후 비교·capset 규칙 없음 | 자격 증명 변경 수집 테스트 없음 | **미구현**, UI도 planned/inactive | `capability/probe.go:Probe`; `agent/runtime_capabilities.go:applyRuntimeCapabilities`의 `observation.credential_change` |
| 일반 신규 root 프로세스 경보 | **미구현**: EUID=0만으로 finding을 만들지 않음 | **테스트 통과** `TestExtendedOrdinaryProcessesDoNotAlert`에서 root 단독 비발동 | 웹 출처 root 셸 또는 이미 일치한 확장 행위의 root 가중치만 **구현** | `detection/engine.go:Evaluate`; `extended.go:evaluateExtended` |
| 셸 실행 | **구현**: 설정한 셸 basename + 웹 출처. 셸 내부 built-in 명령별 이벤트는 없음 | **테스트 통과** T1/T2 | 통제된 replay/기존 운영 기록과 L1의 실행 관측. 실제 공격 웹셸 탐지율은 **미검증** | `Engine.Evaluate`, `classify` |
| 셸 없는 외부 명령 | **구현**: exec 자체 관측. 자동 finding은 아래 고정 분류만 | **테스트 통과** T1/T2 | Tetragon 실행 스트림 **실서버 검증**. 임의 외부 명령을 모두 악성 판정하는 기능은 **미구현** | `classifiers.go:classify`, `extendedRule` |
| 인터프리터 실행 | **구현**: 일반 exec + 일부 inline/script invocation 사실. 코드 의미·실행 완료 판정 없음 | **테스트 통과** T1/T2/T6 | L1/L2에서 interpreter 관측 **실서버 검증**. Ruby 실제 실행 등 개별 런타임 전 범위는 **미검증** | `execution.go:exactExecution, executionEvidence`; `normalizeTetragonObservation` |
| 파일 쓰기 | **구현**: 선택된 basename·디렉터리 prefix·regular file의 `vfs_write`, 반환값 포함 | **테스트 통과** T1/T2/T6 | L1/L2에서 실제 유형 수신 **실서버 검증**. 전체 쓰기·모든 앱은 **미검증/범위 밖** | `observation_policies.py:policies`; `normalizeFileObservation` |
| 파일 읽기·삭제·rename·chmod/chown·내용 무결성 | **미구현**: 해당 후크·어댑터·탐지 규칙 없음 | 해당 기능 테스트 없음 | **미구현**. 쓰기를 모든 파일 변경이라고 표시하면 안 됨 | `policies`, `isOperationEvent`, `Engine.Evaluate`의 수용 유형 확인 |
| 네트워크 연결 | **구현**: TCP IPv4/선택적 IPv6의 목적지 주소·포트와 connect 반환값 | **테스트 통과** T1/T2/T6 | L1/L2에서 유형 수신 **실서버 검증**. IPv6 등 개별 경로의 현재 재검증은 하지 않음 | `normalizeNetworkObservation`, `policies` |
| 기타 소켓 활동 | UDP·accept/listen/bind·send/recv·연결 종료·DNS/HTTP 본문·TLS 내용은 **미구현** | 해당 기능 테스트 없음 | **미구현** | 네트워크 정책은 `tcp_v4_connect`/`tcp_v6_connect`만 생성 |
| 컨테이너 프로세스 | **부분 구현**: 호스트에서 수신한 process와 procfs cgroup scope를 일반 경로로 처리 | **테스트 통과** `TestOriginServicePrefersLeafContainerScope` | Docker 컨테이너를 실제 띄운 전용 E2E는 이번에 없고 보유 기록으로도 **확인 불가** | `procfs/snapshot.go:OriginService, isContainerScope` |

`collector`, `agent`, `detection` 등의 축약 경로는 모두 `internal/` 아래다. Linux Capability 비트와 화면의 “기능 가용성(capabilities)”은 서로 다르다. 전자의 변경 센서는 없고 후자는 제품 기능 상태다.

독립적인 fork/clone 이벤트 어댑터도 **미구현**이다. exec 없는 자식이 초기 procfs 또는 다른 관측 문맥에 나타날 수는 있으나, 모든 fork를 연속 수집한다고 주장할 수 없다. 실제 모델의 process.exec은 OS exec 관측이지 반드시 새 PID 생성이라는 뜻도 아니다.

#### 3.2 Tetragon 인터프리터 정책의 실제 제약

[observation_policies.py](../../packaging/tetragon/observation_policies.py)의 `inline_policy`는 `sched:sched_process_exec` **raw tracepoint**에 고정된 basename 및 `matchCmdArgs`를 건다. 어댑터는 [tetragon_observations.go](../../internal/collector/tetragon_observations.go)의 `normalizeTetragonObservation`에서 정책 이름·후크·action·실행 파일 패턴을 함께 확인한다.

| 런타임 | 고정 정책이 관측하는 옵션 |
| --- | --- |
| Python | `-c` |
| Node / nodejs | `-e`, `--eval`, `-p`, `--print` |
| PHP CLI | `-r` |
| Perl | `-e`, `-E` |
| Ruby | `-e` |

- `INLINE_OPTION_POSITIONS=3`: 코드 옵션 앞에 허용된 독립 스위치가 최대 2개인 경우를 다룬다. 더 뒤의 옵션이나 값 소비 옵션 조합은 일반적인 CLI 파서처럼 모두 해석하지 않는다.
- 이 제한은 v1.8.0 string-map 슬롯 제한을 고려한 실제 정책 구현이다. 옵션 위치를 무한 확장하지 않는다.
- `runtime_names`, `discover_runtime_names`, `RUNTIME_PATTERN`에 정의된 이름/버전과 신뢰 경로를 쓴다. 임의로 이름을 바꾼 인터프리터를 모두 인식하지 않는다.
- 정책 매치는 **해당 invocation 옵션을 관측했다는 사실**이다. 코드가 정상 파싱됐는지, 성공 실행됐는지, 악성인지까지 증명하지 않는다.
- Tetragon flattened `arguments`는 정확한 argv로 재구성하지 않는다. `tetragonToProcess`가 보존하는 기본 argv는 실행 파일이고, 정확한 인자 증거가 아니면 `process.argv_exact` 누락으로 취급한다.
- `ExecutionObservation`의 정책 이름은 암호학적 출처 인증이 아니다. 외부 root 수집기와 그 입력 스트림을 신뢰하는 경계 안에서 유효성 검사한다.

#### 3.3 audit 인터프리터 분석은 별도 경로

[execution.go](../../internal/detection/execution.go)의 `exactExecution`, `scriptExecution`, `interpreterOptionSet`은 검증된 **정확한 argv**에서 옵션을 해석한다. 단순 문자열 검색이 아니다. Python/Node/PHP/Perl/Ruby별 제한된 switch·값 옵션·script 경계만 처리하며 알 수 없는 조합은 증거로 승격하지 않는다.

임시 스크립트는 절대 경로 또는 신뢰 가능한 CWD로 해석한 상대 경로가 `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/memfd:...`, 숫자 descriptor의 `/dev/fd/`, `/proc/self/fd/`, `/proc/thread-self/fd/`인 경우다. 일반 `/srv/app/job.py` 실행 자체는 이 규칙의 경보가 아니다.

`audit_argv.go`의 `auditArgv.normalized`는 argc·위치·중복·분할 인자 불확실성을 검사한다. 레코드 누락·EOE 부재·잘림으로 exact argv를 증명할 수 없으면 inline/script 증거로 쓰지 않는다. 정확한 함수명은 `normalized`; audit 타입은 비공개 `auditArgv`다.

#### 3.4 파일·네트워크의 커널 범위와 보존 범위

파일 기본 prefix는 `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/var/www/`, `/srv/`다. 일반 파일만 대상이며 `observation_binaries`의 셸·웹서버·언어 런타임·일부 도구 basename 목록도 일치해야 한다. 디렉터리를 추가해도 해당 후크가 모든 쓰기 API를 포괄하는 것은 아니다.

`vfs_write` 양수 반환은 쓴 바이트 수, 0은 `no_data`, 음수는 `failed`, 반환값 부재는 `unknown`이다. `writev`, mmap dirty page, io_uring 등 다른 경로의 완전한 커버리지는 없다. 파일 내용·변경 전후 hash·쓰기 버퍼는 수집하지 않는다.

네트워크도 같은 선택적 basename 집합을 사용한다. 반환값 0은 **`initiated`이지 `established`가 아니다**. 음수는 실패, 부재는 unknown이다. IPv4/IPv6와 주소 family를 대조하고 목적지 포트는 1~65535만 수용한다. 본문·로컬 소켓 전체 정보·전송량을 이 이벤트로 얻지 않는다.

추가로 `Service.retainTetragonEventWithDetector`는 operation 이벤트 세 종류를 **항상 웹 출처 일치 시에만 DB 보존**한다. 일반 exec의 `only_detection_origins=false` 설정이 operation 전체 보존을 열어 주지는 않는다. `recordRuntimeEvent`는 이 보존 필터보다 앞에서 호출되므로 기능 화면이 active여도 해당 유형의 모든 이벤트가 이력에 보이는 것은 아니다.

#### 3.5 Docker 등 컨테이너

`OriginService`는 cgroup 경로를 뒤에서부터 검색해 가장 안쪽 `.service` 또는 `docker-`, `libpod-`, `cri-containerd-`로 시작하는 `.scope`를 찾는다. 정확한 scope를 정책의 웹 서비스로 지정할 수 있다. 하지만 다음은 별도 구현을 확인하지 못했다.

- Docker/CRI API 연동과 이미지·컨테이너 이름·Pod/namespace enrichment.
- 컨테이너 내부 PID와 호스트 PID의 독립 매핑 모델 및 namespace별 보장.
- 컨테이너별 모든 파일 prefix의 의미를 자동 해석하는 로직.
- 실제 Docker RCE 시나리오 E2E 검증.

따라서 “호스트에서 전달되는 컨테이너 프로세스도 일반 처리 가능”과 “Docker 보안 전용 기능 완성”은 다르다. Tetragon 기본 설치 unit은 Kubernetes API 연동을 끈다.

#### 3.6 자원·프로세스 목록 모니터링

별도로 `internal/hostmetrics/metrics.go:Sampler.Sample`, `internal/agent/resources.go:Resources`, `managed_worker.go:managedResources`에 CPU 사용률/load, RAM/swap, filesystem 용량/inode, disk byte rate/IOPS/busy, 인터페이스 RX/TX/rate/error/drop, 프로세스 PID/PPID·실행 파일·UID·RSS·CPU·서비스 샘플링이 **구현**돼 있다. 이번 `go test -count=1 ./internal/hostmetrics`는 **테스트 통과**했다. 자원 API를 실제 업무 부하에서 검증하거나 프로세스별 네트워크 트래픽과 대조하는 실서버 검증은 이번에는 하지 않아 **미검증**이다.

기본 프로세스 표시 제한은200, 최대2000이고 cache는5초다. 같은 boot의 호환되는 두 샘플이 있어야 rate를 계산하며 처음 값은 unknown일 수 있다. argv·environ을 읽지 않는 경로이며, 이 프로세스 목록은 샘플 사이에 종료된 프로세스를 빠짐없이 기록하는 보안 이벤트 스트림을 대체하지 않는다. 인터페이스 사용량 통계와 TCP connect 보안 관측도 서로 다른 기능이다. 자원 모니터링을 끄는 정책이 보안 탐지 엔진 전체를 끄는 것과 같지는 않다.

### 4. 탐지 엔진: 모든 규칙과 점수

#### 4.1 공통 발동 전제

근거: [engine.go](../../internal/detection/engine.go)의 `Evaluate`, `MatchWebOrigin`, [classifiers.go](../../internal/detection/classifiers.go)의 `classify`, [extended.go](../../internal/detection/extended.go)의 `evaluateExtended`.

- `detection.enabled=true`여야 실제 pipeline에서 평가한다.
- 기본 프로필은 `process.exec`만, 확장 프로필은 추가로 `process.exec_observation`을 평가한다.
- 웹 출처 일치가 필수다. `process.exit`, `file.write`, `network.connect`는 finding 생성 대상이 아니다.
- 확장은 `extended_process_rules=true`로 명시 opt-in한다. 기본값은 false다. 로컬/중앙 정책 검증은 확장 활성화 시 audit/Tetragon executable 필터가 비어 있어야 한다고 강제한다. 웹 출처 필터는 유지 가능하다.
- 확장 분류에는 유효한 `process.exe`가 필요하다. 누락·잘림·비식별화된 관련 필드를 가중치 증거로 쓰지 않는다.

#### 4.2 기본 프로필: 규칙 버전 0.1.0

| 규칙 ID | 정확한 조건 | 심각도 | 점수·테스트 상태 |
| --- | --- | --- | --- |
| `web-descendant-shell` | 웹 출처 + 설정한 셸 basename + `origin:shell` 예외 없음 + EUID가 0 아님 | high | Engine 자체 RiskScore는 0. Agent `applyResponseDecisions`가 85 부여. **구현·테스트 통과** T1/T2 |
| `web-descendant-root-shell` | 위 조건 + EUID=0 | critical | Agent가 95 부여. **구현·테스트 통과** T1/T2 |

이는 UID가 non-root에서 root로 바뀌었다는 탐지가 아니라 **root 신원의 셸 실행 관측**이다. UnknownCredentialID는 -1이다.

#### 4.3 확장 프로필: 규칙 버전 0.3.0

아래 순서는 `extendedRule`의 **우선순위**다. 하나의 이벤트에 여러 신호가 있어도 주 규칙은 하나이며, 같은 이벤트에서 나온 보조 신호들은 점수에 합산한다.

| 순위·규칙 ID | 발동 신호 | 비root 기본 점수 | 상태·검증 |
| --- | --- | --- | --- |
| 1 `web-descendant-root-shell` | 허용 예외가 아닌 설정 셸 + 사용 가능한 EUID=0 | 해당 없음, 통상 95 | **구현·테스트 통과** T1/T2. 실공격 종료 E2E **미검증** |
| 2 `web-descendant-shell` | 허용 예외가 아닌 설정 셸 | 85 | **구현·테스트 통과** T1/T2 |
| 3 `web-descendant-temporary-executable` | 정규화된 실행 경로가 `/tmp/`, `/var/tmp/`, `/dev/shm/` 아래 또는 비어 있지 않은 `/memfd:` | 65 | **구현·테스트 통과** T1/T2 |
| 4 `web-descendant-connection-tool` | basename 정확히 `nc`, `ncat`, `socat` | 70 | **구현·테스트 통과** T1/T2. 실제 연결 증명 아님 |
| 5 `web-descendant-inline-interpreter` | 검증된 ExecutionObservation mode=inline | 70 | **구현·테스트 통과** T1/T2/T6, 관측 유형은 L1/L2 **실서버 검증** |
| 6 `web-descendant-temporary-script` | exact argv로 얻은 ExecutionObservation mode=script, location=temporary/memory/fd | 60 | **구현·테스트 통과** T1/T2. Tetragon flattened argv만으로는 미발동; 실제 audit script 경로 **미검증** |
| 7 `web-descendant-download-tool` | basename 정확히 `curl`, `wget` | 60 | **구현·테스트 통과** T1/T2. 다운로드 성공 증명 아님 |
| 8 `web-descendant-recon-tool` | basename 정확히 `id`, `whoami`, `uname`, `hostname`, `ps` | 45 | **구현·테스트 통과** T1/T2 |

모든 확장 규칙은 **`DetectionOnly=true`**다. 표의 실서버 미표기는 미검증으로 해석해야 하며, 패키지 테스트나 수집 유형 활성만으로 규칙별 실공격 검증을 주장하지 않는다. `TestExtendedProcessCategoriesAndRisk`와 `TestExtendedProcessDetectionScenarioMatrix`는 범주별 합성 검증이다.

확장 가중치는 `extendedRisk`에서 다음 순서로 부여한다.

| 기여 항목 | 점수 |
| --- | ---: |
| web_origin | 25 |
| shell_execution | 60 |
| download_tool | 35 |
| recon_tool | 20 |
| connection_tool | 45 |
| inline_interpreter | 45 |
| temporary_script | 35 |
| temporary_executable | 40 |
| root_identity: 사용 가능한 EUID=0 | 10 |
| temporary_working_directory: 사용 가능한 CWD가 임시 디렉터리 | 5 |

`len(factors)<8`일 때 순서대로 추가하며 총점은 `min(100, 실제 보존한 factor 점수 합)`이다. 웹 출처·root·CWD만으로는 finding을 만들지 않는다. 예: 웹 출처 `/usr/bin/id`=45, root curl=70, `/tmp/curl` root=100. 확장 심각도는 기본 medium, 셸이거나 점수≥70이면 high, root 셸이면 critical이다.

기본·확장 confidence는 계보 verified=0.95 / inferred=0.75 / 기타=0.55다. **위험 점수와 confidence는 별개**이며 악성 확률·통계적 정확도가 아니다. 기본 프로필의 심각도→점수 후처리는 high85/critical95/medium60/기타30이며, 확장에 factor가 있으면 이 대체 점수를 쓰지 않는다.

#### 4.4 출처·계보의 판단

1. 현재 프로세스 `OriginService`를 설정한 서비스 목록과 대소문자 무시 **정확 일치** 비교한다.
2. 아니면 최대 64단계 조상에서 service 또는 executable basename을 비교한다. 직접 현재 프로세스의 executable만 웹 실행 파일과 같다고 조상으로 간주하지는 않는다.
3. ParentKey가 없고 조상도 없을 때에만 현재 PPID 및 그 조상을 fallback한다. 명시적 부모 identity가 있는데 PID가 재사용됐다고 대체하지 않는다.
4. 서비스 alias에는 호환성을 위해 `web_executables`도 합쳐진다. 일반 Python/Node 서비스는 실제 service를 `web_services`에 넣거나 웹 조상 조건을 만족해야 한다.
5. 부팅 ID와 source ExecID 또는 시작 시각 기반 키, 초기 procfs, source ancestors, 제한된 메모리 그래프를 조합한다. procfs 성공 시 오래된 DB 계보로 덮지 않고, procfs 실패 때 durable fallback을 사용한다.

이는 HTTP 요청→취약 코드→프로세스의 인과 추적이 아니다. 웹 서비스의 정상 배포·작업 실행도 같은 출처로 판단될 수 있다.

#### 4.5 예외·오탐 억제·상관분석

- `allowed_pairs`의 `origin:shell`은 기본 프로필에서 해당 경보 전체를 제외한다. 확장에서는 **셸 신호만 제거**하며 `/tmp/sh` 같은 다른 위험 신호는 남는다. `origin:curl`을 적는다고 curl 규칙 전체가 예외가 되지 않는다.
- executable 분류는 정확한 basename이다. `curl-wrapper`·`CURL`은 curl 도구 규칙에 일치하지 않는다. 셸과 origin 비교의 소문자 정규화와는 다르다.
- `/opt/tmp/x`, `/tmp-helper`, `/var/tmp-old/x`, 상대 실행 경로는 임시 실행 신호가 아니다. `filepath.Clean`으로 `/tmp/../usr/bin/x`를 임시 경로로 보지 않는다.
- 정상 SSH 계보·미등록 일반 서비스·일반 위치의 스크립트는 기본적인 음성 테스트에 포함된다. 그러나 false positive/negative의 운영 통계, 학습형 baseline, 업무별 자동 예외 추천은 **미구현/미검증**이다.
- 이벤트 ID 기반 finding ID와 source ID는 재전송 중복을 억제한다. 서로 다른 exec의 반복 알림을 시간창으로 묶는 rate limit/cooldown은 확인하지 못했다.
- **제한적 문맥 결합은 구현**: 과거 프로세스/조상·서비스를 현재 이벤트에 연결하고 operation과 같은 프로세스 문맥을 유지한다.
- **행위 연쇄 상관 엔진은 미구현**: 파일 쓰기→실행→외부 TCP라는 시퀀스, 프로세스/호스트 간 시간창 점수 누적, IOC/도메인 평판, taint 추적, 공격 단계 판정은 없다. 현재 RiskScore는 한 이벤트의 factor 합이다.

### 5. 수집기·모드·환경

#### 5.1 Tetragon과 audit 비교

| 구분 | Tetragon | audit dispatcher |
| --- | --- | --- |
| 입력 | 고정 `tetra` 명령의 JSONL, Unix gRPC 이벤트 구독 | auditd plugin이 Unix API에 record 전달 |
| exec/exit | 둘 다 어댑터 존재 | exec만 조합, exit 없음 |
| 계보 | source ExecID/ParentExecID·ancestors + procfs | PPID·초기 procfs·기존 문맥 기반 inferred |
| 정확한 argv | flattened string은 exact로 취급 안 함 | 검증된 EXECVE argc/index 조합 사용 가능 |
| inline/file/TCP | 추가 고정 TracingPolicy 필요 | exact argv inline/script만; file/TCP 어댑터 없음 |
| 실제 동작 증명 | Probe는 경로 존재만, 이후 실제 exec 수신 확인 필요 | dispatcher 설정·audit rule·권한·실제 record 수신이 필요 |
| 검증 상태 | **구현·테스트 통과·현재 단일 실서버 검증** | **구현·테스트 통과**, 전체 실제 auditd 운영 경로 **미검증** |

[90-xe-antishell.rules](../../packaging/audit/90-xe-antishell.rules)는 b64/b32 `execve,execveat`, `success=1` 규칙 예시다. **`always,exit`의 exit는 syscall 완료 필터이지 process.exit 수집이 아니다.** audit assembler는 EXECVE 존재를 기준으로 event를 만든다. 개별 syscall 성공/종류 검증은 제공 규칙과 외부 audit 구성에도 의존한다.

`selectCollector(auto)`는 passive Tetragon 지원과 명령 Probe가 가능하면 우선 선택하고, 아니면 audit 후보를 degraded로 선택한다. 하지만 `runCollector`에서 Tetragon stream이 실패했을 때 **자동 audit 전환이나 해당 stream 재시작을 수행하는 코드가 없다**. 종료/실패 상태로 표시한다. 프로세스가 계속 살아 있는 상태의 collector 오류가 systemd `Restart=on-failure`를 곧바로 유발하는 것도 아니다.

#### 5.2 Basic / Advanced의 의미

**정식 Basic/Advanced 제품 모드 enum 또는 기능 패키지 전환은 확인할 수 없다.** `Collector.Mode`는 auto/tetragon/audit/replay/disabled이고, 실제 AgentMode는 active/degraded/unsupported/error 등 실행 상태다. 이를 Basic=audit, Advanced=Tetragon이라고 동일시하면 안 된다.

실제 기능 차이는 두 축이다.

- 수집기 선택: 앞 표처럼 입력·관측 범위가 달라진다.
- 탐지 프로필: `extended_process_rules=false`는 기본 셸 규칙, true는 확장 8종이다. Tetragon 선택만으로 확장이 자동 활성화되지 않는다.

추가 관측은 [observations.py](../../packaging/tetragon/observations.py) 및 `observation_workflow.py`의 별도 opt-in 설치 흐름이다. `setup.py`로 기본 collector를 설치했다고 11개 추가 정책 전체가 활성화됐다고 판단하면 안 된다. 일반 helper는 installer-owned 구성을 요구하고 변경·실제 probe·검증·rollback을 분리한다. 현재 서버의 수동 설치 이력은 그 서버에 한정된 별도 운영 사례다.

#### 5.3 OS 지원을 과장하지 않는 분류

| 대상 | 코드/패키지 상태 | 실서버·검증 상태 |
| --- | --- | --- |
| Rocky 9 x86_64 | EL9 RPM·수집·업데이트 경로 **구현** | 현재 Rocky 9.8에서 Tetragon·추가 관측·중앙 업데이트 **실서버 검증**. 다른 9.x 커널/SELinux 조합 전체는 **미검증** |
| Rocky 10 x86_64 | EL10 RPM·번들 **구현**. 기존 기록에 native EL10 userspace 빌드·설치·replay·등록 테스트 통과 | **테스트 통과(기존 기록)**. 실제 부팅된 Rocky 10 커널의 모든 관측·차단·업데이트 E2E는 이번 분석에서 **미검증/확인 불가** |
| Rocky 8 x86_64 | installer의 Python39 선택 등 호환 분기와 수동 runtime probe **구현** | 이번 릴리즈의 검증된 EL8 패키지/실커널 E2E 근거는 **확인 불가**, **미검증** |
| CentOS 7 x86_64 | OS 식별·audit fallback·RPM update metadata의 major7 수용 경로 존재 | 실제 패키지 의존성·systemd·auditd·SELinux E2E **미검증**. 커널이 코드 gate 4.19 미만이면 Tetragon passive 판정 unsupported |

근거: `capability.Prober.probeTetragon`, `probeAudit`, [install-tetragon.sh](../../packaging/install-tetragon.sh)의 `check_tetragon_preflight`, `install_tetragon`, `updates.HostPlatform`, `protocol/managed/updates.go:validUpdateMajor`, 빌드 workflow. OS major를 파싱할 수 있다는 것은 지원 인증이 아니다. EL10 컨테이너는 호스트 커널을 공유하므로 커널·부팅 systemd·SELinux 검증을 대체하지 않는다. 본 표의 커널 요건은 **이 프로젝트의 코드상 gate**이며 외부 Tetragon 버전 전체의 지원표를 주장하지 않는다.

#### 5.4 커널 기능·권한

- `probeEBPF`: `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_EVENTS`를 검사한다. 파일 접근 실패 시 limited다. 실제 프로그램 load/attach를 이 함수가 실행하지 않는다.
- `probeTetragon`: 바이너리/설정 경로, 숫자 기준 커널≥4.19, `/sys/kernel/btf/vmlinux` 존재를 검사한다. 실제 attach·정책별 verifier 성공은 별도다.
- `probeAudit`: `CONFIG_AUDIT`, `CONFIG_AUDITSYSCALL` 또는 userspace 흔적을 검사한다. dispatcher 소유권·충돌·모든 rule coverage 보장은 아니다.
- `probeCgroup`: v2 controllers 또는 v1/hybrid 흔적을 검사한다. v1을 완전 미지원으로 일괄 처리하지 않는다.
- Tetragon 설치 unit은 root, `LimitMEMLOCK=infinity`, process credentials/ancestors 활성화, env/K8s 연동 비활성화다. **최소 Linux Capability 세트를 분리해 배포하는 구현은 없다.** CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN 등의 최소 조합을 이 소스만으로 인증할 수 없다. 실제 root 실행과 커널 보안 설정의 허용을 전제로 한다.
- agent unit은 User를 지정하지 않아 기본 root, `NoNewPrivileges`, `ProtectSystem=strict`, 제한된 쓰기 경로를 사용한다. updater는 별도 root unit, local web은 별도 비특권 계정이다.
- `response.Capability`는 자기 자신에 `pidfd_open`만 시도한다. `pidfd_send_signal` 권한과 대상 동일성까지 사전 보증하지 않는다. 숫자 커널 버전 대신 실제 syscall 결과를 사용한다.
- IMA/TPM은 환경 파일·장치 존재 검사만 있다. 프로세스 바이너리 무결성 판정·TPM quote/원격 attestation은 **미구현**이다.

#### 5.5 손실·누락·불확실성 처리

| 지점 | 실제 처리와 한계 |
| --- | --- |
| Tetragon JSON | 한 줄 최대4MiB, 연속 malformed16회면 stream 종료. 미지원 유형은 skipped 증가. source의 BPF ring buffer 손실을 복구하거나 모든 누락을 계수하는 프로토콜은 없음 |
| Agent 큐 | 기본256개, enqueue 최대1초 대기 후 drop 카운터 증가. 기본 이벤트256KiB, argv128개·인자4096바이트 등 제한. Submit이 drop 후 nil을 반환할 수 있으므로 upstream emitted 수와 durable 저장 수는 다를 수 있음 |
| audit 조립 | 기본4096 pending, 그룹64 records/256KiB, timeout2초. 초과·만료 그룹을 partial로 내보내며 EOE/records/argv_exact 누락 표시. 이미 누락된 원래 내용을 복원하지 않음 |
| 계보 | 기본50,000개 및 탐색64단계 제한. PID 재사용·모순 부모·종료 상태를 보수적으로 처리. 누락 조상·퇴출된 문맥은 탐지 누락으로 이어질 수 있음 |
| 품질 표시 | missing/truncated/redacted 필드를 보존. 미확인 credential은 -1. 확장 분류는 관련 불가 필드로 점수를 추가하지 않음. partial 전체를 무조건 폐기하는 방식은 아님 |
| DB/중앙 | 이벤트·finding·outbox를 한 transaction으로 저장. 저장 오류는 health error. 중앙 outbox 기본256MiB, 초과/과대 레코드는 lost_records 증가로 중앙 전송 손실을 기록할 수 있음. 무한 보관·무손실 보장은 없음 |
| 상태 표시 | passive state와 implementation/runtime_state/verified_at을 분리. 유형별 실제 수신 이후 active. stream 오류/중단은 error/unverified로 내림. 실제 attach·전체 저장·전체 탐지 커버리지의 인증은 아님 |

### 6. 보안·대응·신뢰 경계

#### 6.1 탐지 전용·차단 예측·실제 종료

[managed_policy.go](../../internal/agent/managed_policy.go)의 `applyResponseDecisions`와 [managed_response.go](../../internal/agent/managed_response.go)의 `executeResponses`가 담당한다.

| 모드 | 구현 동작 | 상태 |
| --- | --- | --- |
| 로컬/observe | finding 보존, 신호 전송 없음 | **구현·테스트 통과·현재 실서버 검증** |
| would_block | 만료·점수·confidence·필수 기능 조건을 적용해 가상 결정 기록, 신호 없음 | **구현·테스트 통과**. 실제 운영 정책 전체 E2E는 **미검증** |
| enforce + terminate | 유효한 중앙 정책 + 로컬 `allow_terminate=true` + runtime 기능 + 실제 Tetragon source 등 모두 만족한 기본 finding만 종료 시도 | **구현·테스트 통과**, 실제 공격 서비스 차단 E2E **미검증/실험적** |
| 확장 finding | 모드·점수와 무관하게 `detection_only`, 실행 경로에서 다시 제외 | **구현·테스트 통과** `TestExtendedDetectionCannotBecomeAnEnforcementTarget` |

필수 조건에는 점수≥RiskThreshold, confidence≥MinConfidence, 정책 미만료, 지정 필수 기능의 implemented/active/VerifiedAt이 있다. enforce는 추가로 process_exec/process_lineage/response.terminate를 요구한다. 탐지 전에 사용한 immutable 정책과 실행 직전 현재 정책 revision을 다시 대조한다. 정책이 만료되면 탐지는 유지하고 응답을 observe/none으로 내린다.

#### 6.2 종료 시점·보호 조건

[terminate_linux.go](../../internal/response/terminate_linux.go)의 `Terminate`, `preconditions`, `liveIdentity`:

- **실행 후** 이벤트를 처리·증거 저장한 뒤 `pidfd_open`→live procfs 동일성 2회 확인→`pidfd_send_signal(SIGTERM)`이다.
- 기본 허용 나이3초, 1초를 초과하는 미래 이벤트 거절. boot ID, PID>1, 자기 자신/자기 조상 제외, 시작 시각·실행 파일·UID/EUID·서비스의 정확 일치를 요구한다.
- `(deleted)` 실행 파일, 불완전 신원, 종료된 프로세스, 동일 시작 시각을 증명할 수 없는 source timestamp 정밀도 차이는 거절할 수 있다.
- DB의 `ClaimResponse`가 신호 전 durable intent를 기록하고 동일 finding 재시작/재시도에 재신호하지 않는다.
- SIGTERM 수신·종료는 보장하지 않는다. SIGKILL fallback, 숫자 PID kill fallback, 커널 deny/LSM exec 차단, syscall 결과 변경은 없다.
- pidfd는 프로세스를 고정하지만 concurrent exec 세대까지 고정하지 않는다. 최종 확인과 신호 사이 exec race는 소스 주석에도 남아 있다.

**실서버 검증 구분:** 이번 `response` 테스트는 테스트가 직접 생성한 sleep을 종료하는 제한된 actuator 검증이다. 운영 웹 서비스·공격 프로세스를 enforce 정책으로 차단한 검증으로 표시하지 않는다. 현재 운영 종료 opt-in은 꺼져 있다.

#### 6.3 Agent / Central 권한과 정책 통제

- Agent는 호스트 root 관찰자이며 커널·root 수집기의 입력을 신뢰한다. 수집 JSON 형식 검증은 root 공격자의 위조 방어와 동일하지 않다.
- Unix API의 일반 조회와 root-only 관리 작업이 구분된다. `localapi/management.go:unixPeerContext, handleManagement`는 kernel Unix peer UID로 root를 확인한다. HTTP 헤더로 root를 선언하는 방식이 아니다.
- 독립 Central의 unit은 `xe-antishell-central` 계정이다. console의 `accounts_auth.go:allowsAPI`가 admin/operator/viewer 작업을 서버에서 제한한다. Agent local web은 모니터링 중심이다.
- `managedclient.New`는 pinned CA, TLS≥1.3, mTLS, redirect 거절을 사용한다. 최초 등록은 CSR·토큰과 사전에 신뢰한 bootstrap 정보가 필요하다. `ValidateEnrollment`가 돌아온 인증서·신원·키를 확인하며 network peer가 임의의 CA로 교체하게 하지 않는다.
- `VerifyPolicy`는 Ed25519, key ID/domain, 대상 agent/enrollment, revision·유효기간을 검증한다. `applyManagedPolicy`/`SavePolicy`가 checkpoint를 보존하고 원자적인 detector snapshot을 교체한다.
- 중앙 정책이 로컬 collector 인자·실제 hook·환경을 자동으로 만들어 주지는 않는다. 로컬 scope와 충돌하는 확장/셸 정책은 거절한다. 중앙 정책만으로 로컬 종료 opt-in을 켤 수 없다.
- 삭제는 `AuthorizeRemoval`, `BeginRemoval`, `VerifyRemovalGrant`의 challenge-bound 서명 grant와 별도 오프라인 recovery 검증·단일 소비를 사용한다. OTP라는 UI 이름이 일반 TOTP 양방향 공유 시계 검증과 같다는 근거는 없다.
- required audit queue가 가득 차는 등 의무 기록 실패 시 관리 작업을 거절하는 경로가 있다. 그러나 root가 강제로 프로세스/네트워크/디스크를 파괴하는 상황에 “삭제 로그 무조건 중앙 도착”은 보장 불가능하며 코드도 그 경계를 제거하지 않는다.

#### 6.4 이벤트 무결성·중앙 전송

`storage.PersistObservation`은 evidence·finding·outbox 원자성을 제공한다. `managedDeliveryLoop`는 실패 시 최대1분 backoff로 재시도하고 `Acknowledge`는 spool/sequence 범위를 검증한 뒤 ACK된 outbox만 제거한다.

Central의 `internal/central/server.go:withAgent`는 client certificate의 agent/enrollment와 현재 등록 상태를 인증한다. `internal/central/ingest.go:Store.Ingest`는 연속 sequence, payload hash와 같은 sequence 재전송의 kind/ID/body 일치를 transaction 안에서 검증한다.

이것은 전송·중복·일관성 보호다. **이벤트별 publisher 서명, TPM 서명, WORM 저장, 외부 anchored hash-chain은 구현되지 않았다.** EventID의 hash와 Central payload hash는 root/DB 관리자에 대한 암호학적 변조 불가 증명이 아니다. 정책·삭제 grant·업데이트에는 서명이 있지만 일반 이벤트와 ACK가 동일한 서명 계약인 것은 아니다.

#### 6.5 업데이트의 실제 범위

근거: `internal/agent/managed_update.go`, [stage.go](../../internal/updates/stage.go)의 `Once`, `stage`, `download`, [apply.go](../../internal/updates/apply.go)의 `Apply`, `Reconcile`, [collection.go](../../internal/updates/collection.go)의 `verifyOutcome`, protocol `VerifyUpdatePlan`, `VerifyUpdateAuthorization`, `VerifyReleaseManifest`.

**구현·테스트 통과·현재 한 대 실서버 검증:**

```text
GitHub 고정 저장소 릴리즈 또는 RPM+서명 manifest 업로드
→ Central publisher 서명·hash·크기·실제 RPM header 검증 및 보관
→ 대상/그룹 미리보기 및 배포
→ agent가 별도 publisher 공개키와 중앙 배포 서명을 재검증
→ mTLS 같은 origin에서 RPM 수신 및 bounded staging
→ ready 보고 ACK 후 단기 install authorization
→ 별도 root updater가 신원·설정·서명·hash·현재패키지 재확인
→ rpm transaction test / upgrade / daemon restart
→ 실제 설치·실행 버전·새 수집 증거 확인 / durable 결과 보고
```

- update wire v2, 에이전트/enrollment/별도 revision·expected installed NEVRA·target RPM·expiry를 바인딩한다. publisher key와 중앙 정책/배포 key는 별도다. publisher 공개키는 내장 신뢰 anchor이며 서버가 임의로 바꿀 수 없다.
- 현재 개발·빌드 서버의 publisher 개인키는 root 전용 별도 보관이고 Central 서비스 계정에는 접근을 허용하지 않는다. Agent RPM에는 signer 개인키/개발 signer CLI를 넣지 않는다. 이 권한 분리가 host root 탈취까지 방어하지는 않는다.
- 최대 RPM64MiB, root 전용 journal·lock·동일 report 재시도·ACK가 있다. 일반 원격 셸 명령 실행이나 임의 URL 실행 API가 아니다.
- 기본 순차 배포, 실패/결과 불명 시 미시작 대상 중지 처리. 설치 권한을 받은 installing 작업을 강제로 되돌리는 취소가 아니다.
- 현재 패키지와 daemon build identity(포함 epoch)를 따로 본다. 이전에 수집기가 가동 중이었다면 새 daemon 시작 이후 같은 source의 실제 exec 수신을 성공 조건으로 요구한다. 선택적 모든 hook의 probe나 웹셸 탐지 테스트를 매 업데이트마다 수행하지는 않는다.
- 중단 작업은 실제 설치/실행 결과로 reconcile하고 무조건 재설치하지 않는다. 자동 rollback, 무중단 업데이트, package dependency 자동 설치는 없다.
- 구버전은 최초1회 updater-capable RPM bootstrap이 필요하다. source/dev 빌드·비표준 경로·helper 부재·로컬 opt-out 등은 새 설치를 거절한다. 수동 install.sh의 로컬 RPM 설치가 자동으로 publisher manifest까지 검증하는 것은 아니다.
- OS metadata parser는 major7/8/9/10을 수용하지만 현재 공개·검증한 RPM24 자산은 EL9/EL10 x86_64다. parser 범위를 완전 지원표로 해석하지 않는다.

### 7. 탐지 가능한 공격과 어려운 공격

| 상황 | 현재 가능한 결과 | 불가능/미검증 부분 |
| --- | --- | --- |
| 웹 서비스가 `/bin/sh` 실행 | 출처·셸 일치 시 기본/확장 finding | 웹 요청과의 직접 인과·악성 확정 없음 |
| 웹 서비스가 셸 없이 id/curl/nc 실행 | 확장 opt-in이면 고정 도구 경보 | 임의 바이너리의 모든 악성 사용 탐지 없음 |
| 웹 출처 임시 바이너리 실행 | 임시 경로 규칙 | 정상 경로로 복사·파일명 변경 후 사용하면 같은 규칙으로 보장 못 함 |
| 새 Python `-c` / Node `-e` / PHP CLI `-r` | exact argv 또는 제한된 Tetragon 정책으로 invocation 탐지 | 전체 옵션 조합·다른 런타임·코드 의미/성공 판정 없음 |
| PHP-FPM 요청 안의 eval, 기존 Node/Python 서비스 내부 eval | 새 exec 없이도 제한된 file/TCP 후크는 관측 가능 | eval/compile/deserialize 자체 탐지는 **미구현** |
| 기존 웹 프로세스가 파일을 씀 | basename·prefix·vfs_write·web attribution 만족 시 `file.write` | 자동 웹셸 파일 판정·내용 분석·변경 연쇄 경보 없음 |
| 기존 프로세스가 외부 TCP 접속 | basename·hook·web attribution 만족 시 목적지 메타데이터 | established·유출 내용·UDP·기존 연결 재사용 탐지 없음 |
| 프로세스 생성 없는 순수 계산·메모리 공격 | 일반 자원 변화가 보일 수 있으나 공격 센서가 아님 | runtime USDT/uprobe, compile/eval hook, memory scanner, taint/ROP/JIT 센서 **미구현** |
| rootkit·BPF/수집기/DB 조작 | 일부 health 이상을 보일 수 있음 | 신뢰한 호스트 root/커널에 대한 신뢰성 보장·원격 attestation 없음 |

프로세스 생성 없는 RCE에 대한 현재 결론은 **부수적인 제한된 파일 쓰기/TCP 시도를 관측할 수 있으나 RCE 발생 자체는 알 수 없다**는 것이다. [in-process-code-observation.md](../plans/in-process-code-observation.md)는 후속 설계이며 현재 실행 가능한 센서의 증거로 사용하지 않았다.

### 8. 실제 검증 결과와 근거

#### 8.1 이번 실행한 테스트

2026-11-18 분석 중 `-count=1`로 재실행했다. 기존 구현이나 테스트를 변경하지 않았다.

| 식별자 | 실행 및 결과 | 대표 근거 |
| --- | --- | --- |
| T1 | `go test -count=1 ./internal/detection ./internal/collector` **통과** | `TestExtendedProcessCategoriesAndRisk`, `TestExtendedOrdinaryProcessesDoNotAlert`, `TestTemporaryScriptInvocationsUseExactOperandBoundaries`, `TestTetragonInlinePoliciesYieldCodeFreeIndependentObservations`, `TestTetragonFileWriteUsesActualReturnValue`, `TestTetragonNetworkConnectUsesRequestedSockaddr`, audit argv 테스트 |
| T2 | `go test -count=1 ./internal/agent` **통과**(localhost 허용 환경 재실행) | `TestExtendedProcessDetectionScenarioMatrix`, `TestExtendedDetectionCannotBecomeAnEnforcementTarget`, `TestOperationObservationPipelinePersistsTypedEvidenceAndOutbox`, `TestOperationRuntimeCapabilitiesNeedTheirOwnValidatedEvidence`, `TestColdOperationContextKeepsDurableExitAndNewerPIDOwner` |
| T3 | `go test -count=1 ./internal/lineage ./internal/capability ./internal/procfs` **통과** | 타임스탬프·PID 재사용·현대/legacy 합성 fixture·container scope 테스트 |
| T4 | `go test -count=1 ./internal/response` **통과** | `TestTerminateOnlyOwnedVerifiedProcess`, `TestTerminateRefusesUncertainIdentityWithoutSignaling`: 테스트 소유 프로세스 대상 |
| T5 | `go test -count=1 ./internal/updates ./internal/storage ./internal/managedclient` **통과** | publisher 독립 신뢰·마지막 설치 gate·재시도/중단/epoch·원자 저장·잘못된 ACK·TLS/전송 관련 테스트 |
| T6 | `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s packaging/tetragon -p 'test_*.py'` **68개 통과** | 정책 생성·옵션 위치·mock probe·receipt·rollback·upstream archive 검사. 테스트 주석대로 실제 host BPF attach를 하지 않음 |
| T7 | `cd protocol && go test -count=1 ./...` **두 패키지 통과** | `TestPolicySignatureRejectsChangesTargetsAndRollback`, `TestCentralAuthorizationCannotForgePublisherRelease`, `TestUpdateInstallAuthorizationBindsExactPlanAndShortValidity`, legacy wire 호환 |
| T8 | 중앙 다중 에이전트 전용 통합 테스트 | `TestIndependentCentralWithMultipleAgents`는 `XEAS_CENTRAL_TEST_BINARY` 미지정 시 skip. 이번 실행에서 외부 중앙 binary를 지정하지 않았으므로 **미검증**. 패키지 PASS를 이 테스트 실행의 증거로 쓰지 않음 |

첫 agent 테스트는 샌드박스의 임시 IPv6 localhost listen 금지로 panic했다. 같은 코드의 localhost 허용 재실행은 통과했다. 이를 제품 버그나 실패한 테스트 삭제로 처리하지 않았다. 이번 전체 `make verify`, race/vet·모든 installer wizard, EL10 재빌드, Central 전체 테스트는 새로 실행하지 않았다. 과거 기록과 이번 실행을 섞어 전부 재검증했다고 주장하지 않는다.

#### 8.2 실서버 근거

- **L1 — 이번 직접 읽기, 2026-11-18 01:01:30 KST:** 로컬 `GET /v1/status` HTTP200. version=`0.1.0-24.el9.x86_64`, mode=active, health=healthy, collector=tetragon-json/running. parse_errors=0, events_skipped=0, 마지막 source 이벤트는 조회 약0.03초 전. process_exec·process_lineage·interpreter_exec·file·network가 implemented/active이며 실제 VerifiedAt 보유. credential_change=planned/inactive, response.terminate=available/VerifiedAt 없음. 조회 시 이벤트 payload·정책·인증정보를 수집하지 않았다.
- **L2 — 기존 로컬 운영 검증 기록:** `devdocs/analysis/central-agent-updates-validation.md`(Git 제외 운영 기록)의 2026-11-18 약00:56 KST 한 대23→24 중앙 배포. 설치·실행24/new start/fresh receipt/collection_check=verified, reports4/ACK4/pending0. 독립 확인에서 observe/none·allow_terminate=false·등록 지문·policy revision 유지 및 선택 관측 새 수신 확인. 이는 본 대화의 실제 실행 결과와도 일치한다.
- **L3 — EL10 검증 범위 기록:** `devdocs/plans/rocky10-package-validation.md`와 위 운영 기록은 userspace 패키지·replay·등록 검증을 구분한다. 실제 Rocky10 커널·SELinux·기능별 공격 E2E를 확인했다는 증거로 쓰지 않았다.

L1의 counters는 현재 daemon lifetime 관측이며 커널 upstream에서 한 번도 손실이 없었다는 인증이 아니다. `verified_at` 하나는 각 기능의 적어도 한 번 수신 근거다. 모든 정책 파일의 attach 상태나 런타임별 정확도를 독립적으로 증명하지 않는다. 이번에는 실제 침해 샘플·공격 트래픽을 생성하지 않았다.

### 9. 알려진 제한·버그 판단·성능

#### 9.1 코드에서 확정할 수 있는 제한

| 항목 | 근거와 영향 | 판단 |
| --- | --- | --- |
| 실행 후 대응 | event→DB→SIGTERM, max event age3초 | 짧은 공격은 종료 시도 전에 완료 가능. 실행 전 차단 **미구현** |
| 종료 신원 정밀도 | procfs 시작 tick과 source timestamp 정확 일치 | 정상 대상에도 보수적 거절 가능. 운영 차단 성공률 **미검증** |
| 활성 상태 신선도 | `runtime_capabilities.go`가 daemon lifetime 수신 시간을 보유하며 정해진 TTL로 만료시키지 않음 | 조용히 멈춘 채 Running=true인 스트림을 일정 시간 뒤 반드시 비활성화하는 watchdog은 확인되지 않음 |
| parse 오류 복구 | `TetragonJSON.consume`는 오류 시 LastError를 쓰고 성공 수신 때 명시적으로 비우지 않음 | 한 번의 malformed 뒤 계속 수신돼도 runtimeSnapshot이 error를 유지할 수 있음. 실패 주입 운영 재현은 하지 않았으므로 **코드상 잔류 진단 동작**, 새 확정 장애로 과장하지 않음 |
| 수집/저장 카운터 차이 | Submit drop 시 nil, source health와 agent drop 카운터 분리 | emitted만으로 DB 무손실을 판단하면 안 됨 |
| 신뢰한 source 위조 | 고정 policy tuple·ID/hash 검사는 root source 진위 서명이 아님 | root/커널 침해 후 텔레메트리 신뢰성 보장 없음 |
| 개인정보 범위 | 런타임 argv/원본·조상 argv는 제거, 일반 인자는 이름 기반 redaction | legacy shell `-c` 본문 전체 제거 보장은 없음. 파일 경로/IP도 운영 정보. upstream stderr 진단은 별도 경계 |
| full stream 비용 | 프로세스 문맥 갱신 뒤 candidate 보존 필터 적용 | 저장량 감소가 커널 이벤트량·JSON parse·계보 비용 제거를 뜻하지 않음 |
| procfs/DB 비용 | 출처 조회, 응답 신원 검사시 전체 procfs snapshot; enqueue에서 outbox payload 길이 합 query | 프로세스/적체 증가 시 비용 증가 가능. 정량 throughput·p99·최대 CPU/RAM 부하는 **미검증** |
| 제한/보관 | queue·그래프·스풀 유한, 기본 evidence retention7일 | 무제한 forensic history·무손실·장기 격리 전송 보장 없음 |
| 이름/경로/서비스 의존 | 고정 basename·옵션·prefix·출처 매칭 | 이름 변경, 정책 밖 서비스, 지원 밖 API는 우회/미탐 가능 |

#### 9.2 확정되지 않은 항목

이번 테스트에서 구현 오류로 확정한 새 실패는 없다. localhost 차단 실패는 환경 제한이었고 재실행으로 분리했다. 과거 wizard PTY timeout, hostmetrics 외부 환경 reader 간섭은 기존 검증 기록의 제한이지 이번에 재현한 제품 결함으로 분류하지 않는다.

실제 웹셸 데이터셋의 precision/recall, 오탐률·미탐률, CPU 1코어 VPS 포화 조건, 대규모 컨테이너 밀도, 다수 에이전트 순차/그룹 업데이트의 운영 규모 한계, 모든 SELinux·커널 조합은 **미검증/확인 불가**다. 단위 테스트 통과 수로 이를 대신하지 않는다.

### 10. 미구현·실험적 항목과 후속 검증 우선순위

| 분류 | 항목 |
| --- | --- |
| **미구현** | credential/capability 변경 센서·일반 신규 root 규칙, 파일 읽기/삭제/rename/내용 무결성, 일반 소켓/UDP/패킷 내용, file/network 자동 경보, 다중 이벤트 공격 상관분석, runtime eval/compile/역직렬화 센서, TPM/IMA 무결성 검증, 실행 전 차단, 자동 package rollback |
| **실험적/제한 구현** | pidfd SIGTERM 응답(보수적 거절 및 exec race), opt-in 확장 탐지(강제 detection-only), 고정 scope의 추가 Tetragon 정책 |
| **미검증** | 실제 auditd dispatcher 전체 수집, 컨테이너 내부 RCE E2E, Rocky8/CentOS7 설치·운영, Rocky10 실커널·SELinux 기능별 동작, 운영 enforce 차단, 장시간 부하와 탐지 정확도 |
| **확인된 구현·검증** | 현재 Rocky9 단일 호스트의 exec/계보 및 선택 관측 수신, 기본/확장 규칙의 합성 회귀 테스트, 현재 호스트 중앙 RPM23→24 업데이트 및 실제 수집 복구 |

후속 검증은 정상 업무 baseline과 실제 관측 범위부터 확보하는 것이 적절하다. 규칙별 안전한 양성/음성 시나리오를 웹 서비스 출처에서 수행하고, audit·Docker·실제 Rocky10 커널로 플랫폼을 넓힌 뒤, 종료 정책을 별도의 통제된 프로세스에서 검증해야 한다. 프로세스 없는 RCE는 현재 센서의 과장된 확대 해석이 아니라 별도 runtime별 센서 설계·구현 과제다. 이 절은 권고이며 구현 완료 항목에 포함하지 않는다.

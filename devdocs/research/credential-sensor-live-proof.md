# Credential sensor 실커널 검증 기록

## 결과와 범위

2026-11-18, Rocky Linux 9.8의 단일 disposable child에서 credential 센서의
실제 커널 관측 → 새 collector 정규화 → 새 탐지 엔진 평가를 1회 검증했다.
동일 task의 EUID `0 → 65534 → 0`을 직접 읽은 before/after와 return0으로
확인했고, 마지막 복귀에서 `privilege-root-restored`가 발생했다.

이 양성 사례는 **이미 보유한 root 자격으로의 복귀**이다. child의 real UID와
saved UID는 계속0이었으므로 비인가 권한 상승이나 취약점 악용 검증이 아니다.
실제 설치된 에이전트 전체 흐름, Central 정책 배포·이력 수신, 패키지 업데이트까지
검증한 결과로 확대해서 해석하지 않는다. 실행한 helper는 현재 workspace의
collector와 detection 패키지를 직접 import해 빌드했다.

## 환경과 고정 정책

| 항목 | 확인 값 |
| --- | --- |
| 운영체제 | Rocky Linux 9.8 (Blue Onyx), x86_64 |
| 커널 | `5.14.0-687.66.1.el9_8.x86_64` |
| Tetragon 서버 | `v1.8.0`, 실제 Unix API의 버전 조회 |
| 정책 | `xeas-credential-change-v1`, `commit_creds`, monitor 전용 |
| 고정 정책 SHA-256 | `503a2ee8012f70d6ae363d19fc5eeefbfc24545b13ea8733a198d35ff0443581` |
| 기존 정책 | 실행 전11개, 실행 후11개; 종료 후 모두 enabled/monitor |

정책 원본은 `internal/privileges/credential-policy.yaml`이다. 검증용 사본에는
단일 child의 정확한 host PID에 대한 `matchPIDs`만 추가했다.
`isNamespacePID:false`, `followForks:false`로 설정했으며 hook, argument, data,
return, monitor 옵션과 Post 동작은 원본 그대로 유지했다.

## 안전 경계와 절차

1. 같은 이름의 기존 정책과 production controller의 소유 표시가 없는지 확인했다.
2. 부모와 별도인 single-thread C child를 하나 만들고, pipe 명령 전에는 대기시켰다.
3. child PID에 한정한 monitor 정책을 추가하고 enabled/monitor/hook loaded 상태를 확인했다.
4. 그 정책만 구독했다. argv/environment를 서버 측에서 제외하고 이벤트를 메모리
   파이프로만 전달했다. raw 이벤트·명령행·환경변수는 파일에 쓰거나 출력하지 않았다.
5. child의 EUID만65534로 내린 뒤 실제 정규화 이벤트를 확인하고, 그 다음0으로 복귀시켰다.
6. 소유한 동일 policy ID/name/domain만 삭제한 뒤 정책 부재를 확인했다.
   child와 subscriber를 종료·회수하고 부모의 UID/EUID 불변을 확인했다.

기존 Tetragon 서비스, 다른 정책, Central, 에이전트의 설정·정책·등록 정보는
변경하지 않았다. child에는 parent-death 종료와 제한 시간을 적용했다.
실행 실패를 반복하는 방식은 사용하지 않았다.

## 관측된 정규화 결과

서버 이름·에이전트 등록 정보·일회성 PID 및 exec ID는 이 문서에 포함하지 않는다.
두 관측에서 PID=TGID=TID가 같았고 kernel task start 값과 exec generation도
같았다. 각 snapshot은 UID/GID 8종, Capability 3개 집합 및 user namespace를
포함했으며 `Outcome=applied`, `ReturnValue=0`이었다.

| 항목 | EUID 하향 | EUID 복귀 |
| --- | --- | --- |
| 같은 hook에서 읽은 Before.EUID | 0 | 65534 |
| argument0에서 읽은 After.EUID | 65534 | 0 |
| Before/After real UID | 0 / 0 | 0 / 0 |
| Before/After saved UID | 0 / 0 | 0 / 0 |
| Before/After user namespace | 같은 inode, level0, `is_host:true` | 같은 inode, level0, `is_host:true` |
| Effective Capability 수 | 41 → 0 | 0 → 41 |
| Permitted Capability 수 | 41 → 41 | 41 → 41 |
| cached exec EUID | 0 | 0 |
| 탐지 결과 | 없음 | `privilege-root-restored`, 점수40, `DetectionOnly:true` |

복귀 시 cached exec EUID는0이었지만 직접 읽은 Before.EUID는65534였다.
따라서 과거 exec snapshot을 before로 대체하면 실제 전이를 잃는다는 점과,
이번 센서가 그 캐시를 사용하지 않고 같은 hook의 before를 읽는다는 점을
실제 이벤트로 확인했다. parser에서 제외된 typed shape는 없었다.

## 근거 코드

- `internal/privileges/credential-policy.yaml`: argument0/new cred,
  current_task.cred/old cred, TID, task start, TGID와 return을 수집한다.
- `internal/collector/privilege_observation.go:normalizeTetragonCredential`:
  고정 tuple, task identity, snapshot completeness, return과 outcome을 검증한다.
- `internal/collector/privilege_credentials.go:normalizedTetragonCredentials`:
  ID0의 존재, capability 집합과 user namespace를 보존·검증한다.
- `internal/detection/privilege_credentials.go:evaluateCredentials`:
  real/saved UID0 보유에 따른 복귀를 새로운 root 자격 획득과 구분한다.
- `internal/detection/engine.go:Evaluate`: 같은 workspace의 실제 탐지 진입점을 사용했다.

준비 단계에서 PID selector 외 정책 불변, 단일 host PID 제한,
reject 진단의 개인정보 제거, 정책 ID 소유 구분에 대한 helper 테스트와
C/Go 빌드를 통과했다. 이 실증을 위해 sensor/schema를 수정할 필요는 없었다.

## 아직 실서버에서 검증하지 않은 범위

- real/saved UID가 모두 nonroot인 프로세스의 성공한 EUID0 획득과 악용 경로.
- UID 변경과 독립적인 Capability gain/activation rule의 개별 양성 사례.
  위 Capability 변화는 EUID 변경의 결과이며 root-restored 규칙으로 평가됐다.
- 여러 thread, fork 후 exec하지 않은 child, PID 재사용·늦은 이벤트, 컨테이너 및
  non-host/unknown user namespace의 실제 서버 사례.
- Rocky Linux 8 또는 CentOS 7의 이 센서 attach·이벤트 모양.
  Rocky10 후속 배포 검증은 아래와 같이 별도로 수행했다.
- 전역 unrestricted 정책의 sustained event rate, 부하, 손실 및 장시간 운영 안정성.
- 최초 격리 proof 자체에는 설치된 controller/DB/outbox/Central 경로가 없었다.
  후속 RPM27에서 수행한 통합 검증을 아래에 구분한다.

위 항목은 코드·단위 테스트 근거와 실서버 검증을 분리해서 보고해야 한다.
이 결과만으로 완전한 credential 관측, 손실 없는 수집, 컨테이너 탈출 탐지,
커널 변조 방어 또는 차단 기능이 검증됐다고 주장하지 않는다.

## 후속 실서버 통합 검증: Agent RPM27

같은 날짜의 후속 작업에서 publisher 서명된 RPM27을 중앙의 대상별 preview와
승인된 업데이트 경로로 Rocky9.8/5.14 및 Rocky10.2/6.12 서버에 순서대로
배포했다. 두 작업 모두 설치 성공과 재시작 후 실제 exec 수집 검증을 보고했다.
기존 등록과 웹 탐지 정책을 보존하고 새 프로필만 observe로 활성화했다.
두 서버 모두 고정 monitor 정책이 loaded 상태였고, 실제 완전한 paired
credential 이벤트를 받아 `observation.credential_change`가 active가 됐다.
엔진 제공 여부와 실제 이벤트 수신은 별개의 값으로 확인했다.

Rocky9 서버에서는 같은 disposable C child를 사용해 실제 설치 daemon의
queue/DB/탐지/outbox와 중앙의 committed event bundle까지 대조했다.
EUID0→65534→0의 동일 task와 직접 Before65534를 확인했고,
`privilege-root-restored`,40점,`DetectionOnly:true`,
`response_decision:detection_only`를 확인했다. 중앙의 두 event ID,
credential DTO 및 finding ID/규칙/점수도 로컬 결과와 일치했다.
이 검증은30초 예산 안에 완료됐고 child 회수, 부모 UID/EUID 불변,
등록·정책·수집기 generation·loaded policy ID 불변 및 관측된 손실·parse
카운터 증가 없음을 확인했다. 검증 helper는 정책이나 서비스를 변경하지 않았다.

최초 RPM26 배포에서는 정상적인 빈 Tetragon 정책 목록이 `{}`라는 점과
고정64건/초 중앙 전송 상한 때문에 문제가 드러났다. 원본 upstream 생성
타입의 MarshalJSON으로 빈 객체를 재현했고, RPM27에서 canonical 빈 객체
허용과 엄격한 모호 JSON 거부를 추가했다. 전송은 ACK 완료 batch를8회 또는
250ms까지 처리한 뒤50ms 양보하도록 바꿨고, 기존 idle/backoff/취소/순서를
유지했다. 임시 opt-out 동안 쌓인 기록은 유실 없이 배출됐으며 수정본 배포
뒤 프로필을 다시 활성화했다. 기존 RPM26 공개 설명에도 수정 버전을 안내했다.

추가40초/3표본 관찰에서 두 서버의 에이전트 drop/parse 및 source parse는0,
credential runtime은 active였다. busy 서버의 전송 대기는0~14건 범위에서
처리됐고 lost_records는0이었다. 이 짧은 관찰은 장시간 용량 보증이나 커널
계층의 이벤트 손실 부재 증명이 아니다. 독립 Capability 양성/비인가 root
획득/모든 container·thread/fork 사례는 위 미검증 범위에 남는다.
중앙의 대규모 이력 조회 성능과 UI는 이 센서 증명과 별도로 검증한다.

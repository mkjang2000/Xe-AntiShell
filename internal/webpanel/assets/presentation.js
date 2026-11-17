"use strict";

// Operator-facing terms remain separate from the machine values in evidence.
function operatorLabel(kind, value) {
  if (kind === "response" && (value == null || value === "" || value === "unknown")) return "대응 기록 없음";
  const labels = {
    severity: {critical: "매우 높음", high: "높음", medium: "보통", low: "낮음"},
    state: {open: "검토 대상", closed: "종료", resolved: "확인 완료", acknowledged: "확인됨"},
    event: {"process.exec": "프로그램 실행", "process.exit": "프로그램 종료", "process.exec_observation": "실행 옵션 관측", "file.write": "파일 쓰기 관측", "network.connect": "TCP 연결 요청 관측"},
    completeness: {complete: "정보 확인", partial: "일부 정보", incomplete: "정보 부족"},
    lineage: {verified: "경로 확인", inferred: "일부 추정", unknown: "경로 미확인"},
    response: {observe: "탐지 전용", detection_only: "확장 탐지 전용", would_block: "모의 대응 대상", below_threshold: "대응 기준 미달", insufficient_capability: "대응 요건 부족", terminate_pending: "종료 요청 준비", sigterm_sent: "종료 신호 전송", refused: "안전 조건 미충족", not_repeated: "재실행 생략"},
    health: {healthy: "정상", starting: "확인 중", degraded: "일부 확인 필요", error: "오류"},
    collector: {"tetragon-json": "실시간 실행 수집", "audit-dispatcher": "기본 실행 수집", "replay-jsonl": "점검 자료 재생", replay: "점검 자료 재생"},
    policy: {applied: "적용됨", rejected: "적용 확인 필요", stale: "갱신 필요", local: "서버 설정 사용"},
  };
  const group = Object.prototype.hasOwnProperty.call(labels, kind) ? labels[kind] : null;
  return group && Object.prototype.hasOwnProperty.call(group, value) ? group[value] : kind === "severity" ? "미분류" : "미확인";
}

function serviceLabel(value) {
  if (!value || value === "unknown") return "출처 미확인";
  if (value === "xeas-detection-selftest.service") return "탐지 기능 점검";
  if (value === "pm2-root.service") return "PM2 애플리케이션";
  if (value === "nginx.service") return "웹 서버 (nginx)";
  if (value === "haproxy.service") return "트래픽 중계 (HAProxy)";
  const container = /^docker-([a-f0-9]{12})[a-f0-9]*\.scope$/.exec(value);
  return container ? `컨테이너 ${container[1]}` : value;
}

function isSelfTestFinding(finding) {
  const origin = finding.origin_service;
  if (origin && origin !== "unknown") return origin === "xeas-detection-selftest.service";
  return String(finding.summary || "").includes("xeas-detection-selftest.service");
}

function findingTitle(finding) {
  return findingRuleText(finding).title;
}

function findingRuleText(finding) {
  const rules = {
    "web-descendant-root-shell": {title: "웹 서비스에서 관리자 권한 셸 실행", description: "서비스가 운영체제 명령을 실행했습니다. 정상 배포 작업인지 확인하세요."},
    "web-descendant-shell": {title: "웹 서비스에서 셸 실행", description: "서비스가 운영체제 명령을 실행했습니다. 정상 배포 작업인지 확인하세요."},
    "web-descendant-download-tool": {title: "웹 서비스에서 다운로드 도구 실행", description: "다운로드 기능이 있는 도구가 실행됐습니다. 실제 다운로드 여부와 정상 운영 작업인지는 추가 확인이 필요합니다."},
    "web-descendant-recon-tool": {title: "웹 서비스에서 정보 확인 도구 실행", description: "시스템·계정·네트워크 정보 확인용 도구가 실행됐습니다. 정상 운영 작업인지 확인하세요."},
    "web-descendant-connection-tool": {title: "웹 서비스에서 연결 도구 실행", description: "연결 기능이 있는 도구가 실행됐습니다. 실제 연결 여부와 실행 목적은 추가 확인이 필요합니다."},
    "web-descendant-inline-interpreter": {title: "웹 서비스에서 직접 코드 실행 요청", description: "직접 코드 실행 옵션을 지정한 인터프리터가 실행됐습니다. 코드 내용과 실행 성공 여부는 이 기록으로 확인할 수 없습니다."},
    "web-descendant-temporary-executable": {title: "웹 서비스에서 임시 경로의 실행 파일 실행", description: "임시 또는 메모리 파일 경로의 프로그램이 실행됐습니다. 파일의 출처와 정상 운영 작업인지는 추가 확인이 필요합니다."},
    "web-descendant-temporary-script": {title: "웹 서비스에서 임시 경로의 스크립트 실행 요청", description: "인터프리터에 임시·메모리·파일 디스크립터 경로의 스크립트가 지정됐습니다. 파일 내용과 실행 성공 여부는 이 기록으로 확인할 수 없습니다."},
  };
  return Object.prototype.hasOwnProperty.call(rules, finding.rule_id) ? rules[finding.rule_id] : {title: "의심 행위 탐지", description: "탐지 조건에 해당하는 실행 기록입니다. 상세 기록을 확인하세요."};
}

function findingRiskFactorText(factor) {
  const reasons = {
    web_origin: "웹 서비스와 연결된 실행 경로가 관찰됐습니다.",
    shell_execution: "셸 프로그램 실행이 관찰됐습니다.",
    download_tool: "다운로드 기능이 있는 도구 실행이 관찰됐습니다. 다운로드 성공 여부는 확인되지 않았습니다.",
    recon_tool: "시스템·계정·네트워크 정보 확인용 도구 실행이 관찰됐습니다.",
    connection_tool: "연결 기능이 있는 도구 실행이 관찰됐습니다. 실제 연결 여부는 확인되지 않았습니다.",
    inline_interpreter: "직접 코드 실행 옵션을 지정한 인터프리터 호출이 관찰됐습니다. 코드 내용은 분석하지 않았습니다.",
    temporary_executable: "임시 또는 메모리 파일 경로의 실행 파일 실행이 관찰됐습니다.",
    temporary_script: "인터프리터에 임시·메모리·파일 디스크립터 경로의 스크립트 실행 인자가 지정됐습니다. 실행 성공 여부는 확인되지 않았습니다.",
    root_identity: "관리자 권한(실행 권한 사용자 번호 0)으로 실행됐습니다.",
    temporary_working_directory: "프로세스의 작업 경로가 임시 경로로 확인됐습니다.",
  };
  return factor && Object.prototype.hasOwnProperty.call(reasons, factor.id) ? reasons[factor.id] : "추가 관찰 근거";
}

// Typed metadata explains the observation boundary; code and arbitrary probe
// fields are never promoted into operator-facing evidence.
function eventObservation(event) {
  const object = (value) => value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const label = (labels, value) => Object.hasOwn(labels, value) ? labels[value] : "미확인";
  const returned = (value) => value === null || value === undefined ? "미수집" : Number.isSafeInteger(value) ? String(value) : "정확한 값 미확인";
  const fields = [];
  let summary = "";
  if (["process.exec", "process.exec_observation"].includes(event.event_type) && event.execution) {
    const value = object(event.execution);
    summary = value.mode === "inline" ? "인터프리터의 직접 코드 실행 옵션을 관측했습니다. 코드 내용과 실행 성공 여부는 확인하지 않습니다." : value.mode === "script" ? "임시·메모리·파일 디스크립터 경로의 스크립트 실행 인자를 관측했습니다. 파일 내용과 실행 성공 여부는 확인하지 않습니다." : "인터프리터 실행 근거가 보고됐습니다. 관측 범위는 상세 정보를 확인하세요.";
    const option = ["-c","-e","-E","-p","--eval","--print","-r","-f"].includes(value.option) ? value.option : value.mode === "script" && !value.option ? "위치 인자 (옵션 없음)" : "미확인";
    fields.push(["인터프리터", label({python:"Python",node:"Node.js",php:"PHP",perl:"Perl",ruby:"Ruby"}, value.runtime)], ["실행 방식", label({inline:"직접 코드 실행 옵션",script:"스크립트 파일 인자"}, value.mode)], ["관측 근거", label({exact_argv:"분리된 실행 인자의 정확한 옵션·위치",tetragon_policy:"전용 수집 정책의 실행 옵션 조건"}, value.evidence)], ["확인한 옵션", option], ["스크립트 경로 종류", value.mode === "inline" ? "해당 없음" : label({temporary:"임시 경로",memory:"메모리 파일 경로",fd:"파일 디스크립터 경로"}, value.script_location)], ["수집 정책", value.policy_name]);
  } else if (event.event_type === "file.write") {
    const value = object(event.file);
    summary = label({written:"파일 쓰기 호출에서 쓴 바이트 수가 보고됐습니다. 디스크 반영과 파일 내용은 확인하지 않습니다.",no_data:"파일 쓰기 호출이 0을 반환했습니다. 이 호출에서 쓴 데이터는 없습니다.",failed:"파일 쓰기 호출이 실패로 보고됐습니다.",unknown:"파일 쓰기 호출을 관측했습니다. 반환 결과는 확인되지 않았습니다."}, value.outcome);
    if (summary === "미확인") summary = "파일 쓰기 관측의 결과를 확인할 수 없습니다.";
    fields.push(["파일 경로",value.path], ["쓰기 결과",label({written:"쓰기 바이트 수 보고",no_data:"쓴 데이터 없음",failed:"실패",unknown:"결과 미확인"},value.outcome)], ["원래 반환값",returned(value.return_value)], ["반환값 의미","양수: 쓴 바이트 수 · 0: 쓴 데이터 없음 · 음수: 커널 오류. 디스크 반영 여부는 별도 확인이 필요합니다."], ["관측 함수",value.function], ["수집 정책",value.policy_name]);
  } else if (event.event_type === "network.connect") {
    const value = object(event.network);
    summary = label({initiated:"TCP 연결 요청이 커널에서 받아들여졌습니다. 연결 완료나 데이터 전송을 뜻하지 않습니다.",failed:"TCP 연결 요청이 실패로 보고됐습니다. 연결 완료 여부는 별도 관측이 필요합니다.",unknown:"TCP 연결 요청을 관측했습니다. 결과와 연결 완료 여부는 확인되지 않았습니다."},value.outcome);
    if (summary === "미확인") summary = "TCP 연결 요청의 결과를 확인할 수 없습니다.";
    fields.push(["대상 주소",value.destination_address], ["대상 포트",Number.isInteger(value.destination_port) && value.destination_port > 0 && value.destination_port <= 65535 ? value.destination_port : "미확인"], ["프로토콜",label({tcp:"TCP"},value.protocol)], ["주소 종류",label({ipv4:"IPv4",ipv6:"IPv6",AF_INET:"IPv4",AF_INET6:"IPv6"},value.family)], ["요청 결과",label({initiated:"연결 요청 시작",failed:"요청 실패",unknown:"결과 미확인"},value.outcome)], ["원래 반환값",returned(value.return_value)], ["반환값 의미","0: 커널 연결 요청 시작 · 음수: 커널 오류. 연결 완료·상대 응답·통신 내용은 확인하지 않습니다."], ["관측 함수",value.function], ["수집 정책",value.policy_name]);
  }
  return {summary, fields};
}

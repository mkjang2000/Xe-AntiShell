"use strict";

// Operator-facing terms remain separate from the machine values in evidence.
function operatorLabel(kind, value) {
  if (kind === "response" && (value == null || value === "" || value === "unknown")) return "대응 기록 없음";
  const labels = {
    severity: {critical: "매우 높음", high: "높음", medium: "보통", low: "낮음"},
    state: {open: "검토 대상", closed: "종료", resolved: "확인 완료", acknowledged: "확인됨"},
    event: {"process.exec": "프로그램 실행", "process.exit": "프로그램 종료"},
    completeness: {complete: "정보 확인", partial: "일부 정보", incomplete: "정보 부족"},
    lineage: {verified: "경로 확인", inferred: "일부 추정", unknown: "경로 미확인"},
    response: {observe: "탐지 전용", would_block: "모의 대응 대상", below_threshold: "대응 기준 미달", insufficient_capability: "대응 요건 부족", terminate_pending: "종료 요청 준비", sigterm_sent: "종료 신호 전송", refused: "안전 조건 미충족", not_repeated: "재실행 생략"},
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
  if (finding.rule_id === "web-descendant-root-shell") return "웹 서비스에서 관리자 권한 셸 실행";
  if (finding.rule_id === "web-descendant-shell") return "웹 서비스에서 셸 실행";
  return "의심 행위 탐지";
}

"use strict";
const recentReviewButtons = new Map();

function operationalCount(value) {
  return Number.isFinite(value) && value >= 0 ? value.toLocaleString("ko-KR") : "미확인";
}
function operationalQuantity(value) {return Number.isFinite(value) && value >= 0 ? `${operationalCount(value)}건` : "미확인";}

function effectiveResponse(summary) {
  const result=effectiveWebResponse(summary);
  if(summary?.detection_enabled&&summary?.privilege_rules)result.note+=` ${privilegeProfileNote(summary)}`;
  return result;
}
function effectiveWebResponse(summary) {
  if (!summary) return {label: "미확인", note: "대응 설정을 확인할 수 없습니다."};
  if (!summary.detection_enabled) return {label: "탐지 중지", note: "탐지 정책이 꺼져 있습니다."};
  if (summary.extended_process_rules === true) return {label: "확장 탐지 전용", note: "웹 서비스의 셸과 도구 실행을 확장 탐지하며 자동 종료하지 않습니다."};
  if (summary.response_mode === "observe") return {label: "탐지 전용", note: "기본 셸 탐지 · 기록을 확인한 뒤 수동으로 대응합니다."};
  if (summary.response_mode === "would_block") return {label: "모의 대응", note: "기본 셸 탐지 · 대응 조건만 확인하며 프로세스를 종료하지 않습니다."};
  if (summary.response_mode === "enforce" && summary.response_action === "terminate") return {label: "조건부 자동 종료", note: "기본 셸 탐지 · 정책과 안전 조건을 충족할 때 종료를 시도합니다."};
  return {label: "확인 필요", note: "적용된 대응 설정을 확인하세요."};
}

function renderOperatorOverview(data) {
  const status = data.status || {}, summary = data.summary, managed = data.managed;
  const response = effectiveResponse(summary);
  text("healthValue", operatorLabel("health", status.health));
  text("modeValue", operatorLabel("collector", status.collector));
  text("findingCount", operationalCount(summary?.open_findings));
  text("criticalCount", summary ? `매우 높음 ${operationalCount(summary.critical_open)} · 높음 ${operationalCount(summary.high_open)}` : "전체 보존 이력 집계 확인 필요");
  text("todayFindingCount", operationalCount(summary?.findings_24h));
  text("selfTestCount", summary ? `기능 점검 ${operationalQuantity(summary.self_test_findings)} 별도 보관` : "기능 점검 이력 별도 표시");
  text("responseValue", response.label);text("responseNote", response.note);
  text("lastEventValue", relative(data.events?.[0]?.event_time || status.last_event_at));
  text("collectorValue", summary ? `${operationalQuantity(summary.total_events)} 보존` : "보존 이력 집계 미확인");
  text("lossValue", operationalCount(status.dropped));
  const parseErrors = (status.parse_errors || 0) + (status.collector_health?.parse_errors || 0);
  text("parseValue", operationalQuantity(parseErrors));
  const badge = byId("overallBadge");
  badge.className = `status-badge ${status.health === "healthy" ? "ok" : status.health === "error" ? "bad" : "warn"}`;
  text("overallLabel", status.health === "healthy" ? "수집 정상" : status.health === "starting" ? "수집 확인 중" : "수집 상태 확인");
  text("eventTotal", summary ? `최근 24시간 ${operationalQuantity(summary.events_24h)}` : "집계 미확인");
  const recent = summary?.recent_findings || (data.findings || []).filter(finding => !isSelfTestFinding(finding)).slice(0, 5);
  renderRecentFindings(recent);
  renderOperationalAttention(status, summary, managed);
}

function renderRecentFindings(findings) {
  let focusedFinding = "";
  for (const [id, button] of recentReviewButtons) if (document.activeElement === button) focusedFinding = id;
  recentReviewButtons.clear();
  const rows = findings.map(finding => {
    const row = document.createElement("article");row.className = "review-row";
    const time = document.createElement("time");time.className = "review-time";time.textContent = fmtTime(finding.created_at);
    const description = document.createElement("button");description.type = "button";description.className = "review-description review-open";
    recentReviewButtons.set(finding.finding_id, description);
    description.addEventListener("click", () => openFindingService(finding.origin_service || ""));
    const title = document.createElement("strong");title.textContent = findingTitle(finding);
    const process = recordsFindingProcess(finding);
    const origin = document.createElement("span");origin.textContent = [serviceLabel(finding.origin_service), process.exe, process.pid ? `PID ${process.pid}` : ""].filter(Boolean).join(" · ");
    const hint = document.createElement("span");hint.className = "visually-hidden";hint.textContent = "해당 서비스 탐지 보기";
    description.append(title, origin, hint);
    const status = document.createElement("div");status.className = "review-state";
    status.append(tag(operatorLabel("severity", finding.severity), ["critical", "high", "medium", "low"].includes(finding.severity) ? finding.severity : "inactive"));
    const response = document.createElement("span");response.textContent = findingResponseLabel(finding);
    status.append(response);row.append(time, description, status);return row;
  });
  byId("recentFindings").replaceChildren(...rows);
  if (focusedFinding && recentReviewButtons.has(focusedFinding)) recentReviewButtons.get(focusedFinding).focus({preventScroll:true});
  byId("recentFindingsEmpty").classList.toggle("hidden", rows.length > 0);
}

function renderOperationalAttention(status, summary, managed) {
  const entries = [];
  if (status.health === "starting") entries.push(["unverified", "동작 확인 중", "수집 연결을 시작했습니다. 실행 정보 수신을 확인하고 있습니다.", "system"]);
  else if (!["healthy", "degraded", "error"].includes(status.health)) entries.push(["unverified", "수집 상태 미확인", "최신 수집 상태를 확인할 수 없습니다. 수집 상태를 다시 확인하세요.", "system"]);
  if (status.health === "error") entries.push(["error", "수집 오류", "실행 정보 수집에 오류가 있습니다. 수집 상태와 로그를 확인하세요.", "system"]);
  else if (status.health === "degraded") entries.push(["limited", "수집 상태 확인", "일부 수집 조건을 확인해야 합니다. 기능별 상태를 확인하세요.", "system"]);
  if ((status.dropped || 0) > 0 || (status.parse_errors || 0) + (status.collector_health?.parse_errors || 0) > 0) entries.push(["limited", "이력 처리 확인", "수집 누락 또는 처리 오류가 기록됐습니다. 수집 상태를 확인하세요.", "system"]);
  if (!summary) entries.push(["unverified", "집계 확인 필요", "탐지 건수를 집계하지 못했습니다. 새로고침 후 다시 확인하세요.", "refresh"]);
  else if (!summary.detection_enabled) entries.push(["error", "탐지 중지", "탐지 정책이 꺼져 있습니다. 적용 정책을 확인하세요.", "system"]);
  if (managed?.enrolled && (managed.last_error || managed.delivery?.lost_records > 0)) entries.push(["limited", "중앙 전송 확인", `전송 대기 ${operationalQuantity(managed.delivery?.pending)}입니다. 중앙 연결과 전송 상태를 확인하세요.`, "managed"]);
  if (managed?.policy?.result === "rejected" || managed?.policy?.result === "stale") entries.push(["limited", "정책 확인 필요", managed.policy.result === "stale" ? "정책 유효기간이 끝났습니다. 마지막 탐지 설정으로 운영 중입니다." : "새 정책이 적용되지 않았습니다. 중앙 관리 상태를 확인하세요.", "managed"]);
  if (summary?.open_findings > 0) entries.push(["limited", `탐지 검토 ${operationalQuantity(summary.open_findings)}`, "정상 배포·관리 작업인지 실행 기록을 확인하세요. 침해가 확정된 건수는 아닙니다.", "findings"]);
  const issues = entries.length;
  text("attentionHeading", issues ? `확인할 항목 ${issues}개` : "운영 점검");
  if (!issues) entries.push(["active", "수집 운영 상태 정상", "등록된 수집·전송 오류가 없습니다. 탐지 검토 대상은 아래에서 확인하세요.", "findings"]);
  const rows = entries.map(([tone, title, description, destination]) => {
    const row = document.createElement("div");row.className = "attention-item";
    row.append(tag(title, tone));
    const content = document.createElement("span");content.className = "attention-content";content.textContent = description;
    const action = document.createElement("button");action.type = "button";action.className = "ghost attention-link";action.textContent = destination === "system" ? "수집 상태" : destination === "managed" ? "연결·정책" : destination === "refresh" ? "다시 조회" : "탐지 검토";
    action.addEventListener("click", () => {
      if (destination === "refresh") {loadOverview();return;}
      if (destination === "managed") {activateView("overview", true);const section = byId("managedOverview");section.tabIndex = -1;section.scrollIntoView({block:"center"});section.focus({preventScroll:true});return;}
      activateView(destination, true);
    });row.append(content, action);return row;
  });
  byId("attentionList").replaceChildren(...rows);
}

function renderServiceOverview() {
  const services = state.services.filter(service => service.name !== "xeas-detection-selftest.service" && service.finding_count > 0);
  const rows = services.slice(0, 6).map(service => {
    const row = document.createElement("tr");
    const identity = document.createElement("th");identity.setAttribute("scope", "row");identity.textContent = serviceLabel(service.name);
    const findings = document.createElement("td");findings.textContent = operationalCount(service.finding_count);
    const events = document.createElement("td");events.textContent = operationalCount(service.event_count);
    const actionCell = document.createElement("td");const action = document.createElement("button");action.type = "button";action.className = "table-button";action.textContent = "보기";action.setAttribute("aria-label", `${serviceLabel(service.name)} 탐지 이력 보기`);
    action.addEventListener("click", () => openFindingService(service.name));
    actionCell.append(action);row.append(identity, findings, events, actionCell);return row;
  });
  byId("serviceOverview").replaceChildren(...rows);
  text("serviceOverviewDescription", `탐지 이력이 있는 서비스 ${services.length}개 · 기능 점검 제외 · 보존 기간 누적`);
  text("servicesEmpty", "아직 탐지 이력이 있는 서비스가 없습니다.");byId("servicesEmpty").classList.toggle("hidden", rows.length > 0);
}

function renderManagedStatus(managed) {
  const available = managed && typeof managed.enrolled === "boolean";
  byId("managedOverview").classList.toggle("hidden", !available);if (!available) return;
  byId("managedCards").classList.toggle("hidden", !managed.enrolled);
  const badge = byId("managedBadge");badge.className = "tag inactive";
  byId("managedWarnings").classList.add("hidden");
  if (!managed.enrolled) {badge.textContent = "단독 운영";text("managedIdentity", "이 서버의 설정으로 운영하고 있습니다.");byId("managedTechnical").replaceChildren();return;}
  const delivery = managed.delivery || {}, policy = managed.policy || {};
  const contact = managed.last_contact_at ? new Date(managed.last_contact_at).getTime() : NaN;
  const recent = Number.isFinite(contact) && Date.now() - contact < 90000;
  badge.textContent = managed.last_error ? "전송 확인 필요" : delivery.lost_records > 0 ? "이력 손실 있음" : recent ? "연결 정상" : "연결 확인 필요";
  badge.className = `tag ${managed.last_error || delivery.lost_records > 0 ? "error" : recent ? "active" : "limited"}`;
  text("managedIdentity", "중앙 정책으로 운영 중");
  byId("managedCards").replaceChildren(
    resourceCard("최근 연결", fmtTime(managed.last_contact_at), managed.last_contact_at ? relative(managed.last_contact_at) : "아직 연결이 확인되지 않았습니다."),
    resourceCard("전송 대기", operationalQuantity(delivery.pending), `전송 손실 ${operationalQuantity(delivery.lost_records)}`),
    resourceCard("적용 정책", policy.active_revision > 0 ? `${policy.active_revision}번` : "대기 중", operatorLabel("policy", policy.result)),
  );
  const warnings = [];
  if (managed.last_error) warnings.push("중앙 연결 또는 전송 상태를 확인하세요.");
  if (policy.error) warnings.push(policy.result === "stale" ? "정책 갱신이 필요합니다. 마지막 탐지 설정을 유지하고 있습니다." : "요청한 정책을 적용하지 못했습니다. 기술 정보에서 원인을 확인하세요.");
  text("managedWarnings", warnings.join(" "));byId("managedWarnings").classList.toggle("hidden", warnings.length === 0);
  const previous = byId("managedTechnical").children[0];
  const expanded = previous?.open || false, focused = previous && document.activeElement === previous.children[0];
  const details = recordDetails([["서버 식별자", managed.agent_id], ["중앙 서버", managed.central_url], ["정책 요청 버전", policy.desired_revision], ["전송 오류 원문", managed.last_error], ["정책 오류 원문", policy.error]]);
  details.className = "operation-technical";details.children[0].textContent = "기술 정보";details.open = expanded;byId("managedTechnical").replaceChildren(details);
  if (focused) details.children[0].focus({preventScroll:true});
}

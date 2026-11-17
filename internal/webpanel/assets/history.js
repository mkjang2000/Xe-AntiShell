"use strict";

// History pagination and service expansion are separate from overview polling.
class HistoryView {
  constructor(kind) {
    this.kind = kind;
    this.cursor = "";
    this.previousCursors = [];
    this.nextCursor = "";
    this.openGroups = new Set();
    this.requestID = 0;
    this.loaded = false;
    this.displayedItems = 0;
    this.lastError = "";
    this.busy = false;
    this.searchID = kind === "findings" ? "findingSearch" : "eventSearch";
    byId(`${kind}Filters`).addEventListener("submit", (event) => {
      event.preventDefault();
      this.reset();
      this.load();
    });
    byId(`${kind}Service`).addEventListener("change", () => {
      if (kind === "findings" && byId("findingsService").value === "xeas-detection-selftest.service") byId("includeSelfTests").checked = true;
      this.reset();
      this.load();
    });
    if (kind === "findings") {
      for (const control of ["severityFilter", "includeSelfTests"]) byId(control).addEventListener("change", () => {
        this.reset();
        this.load();
      });
    }
    if(kind==="events")byId("eventTypeFilter").addEventListener("change",()=>{this.reset();this.load();});
    byId(`${kind}Previous`).addEventListener("click", () => this.previous());
    byId(`${kind}Next`).addEventListener("click", () => this.next());
  }

  reset() {
    this.cursor = "";
    this.previousCursors = [];
    this.nextCursor = "";
    this.loaded = false;
  }

  selectService(name) {
    const select = byId(`${this.kind}Service`);
    if (name && !Array.from(select.options).some((option) => option.value === name)) {
      const option = document.createElement("option");
      option.value = name;
      option.textContent = serviceLabel(name);
      select.append(option);
    }
    select.value = name || "";
    this.reset();
  }

  async load() {
    const requestID = ++this.requestID;
    this.setBusy(true);
    text(`${this.kind}Status`, "이력을 불러오는 중입니다.");
    const query = new URLSearchParams({kind: this.kind, limit: "10"});
    const service = byId(`${this.kind}Service`).value;
    const search = byId(this.searchID).value.trim();
    if(this.kind==="events"&&byId("eventTypeFilter").value)query.set("event_type",byId("eventTypeFilter").value);
    if (service) query.set("service", service);
    if (search) query.set("q", search);
    if (this.kind === "findings" && byId("severityFilter").value) query.set("severity", byId("severityFilter").value);
    if (this.kind === "findings" && !byId("includeSelfTests").checked) query.set("exclude_self_tests", "1");
    if (this.cursor) query.set("cursor", this.cursor);
    try {
      const response = await fetch(`/api/history?${query}`, {headers: {Accept: "application/json"}});
      if (response.status === 401) { location.href = "/login"; return; }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const page = await response.json();
      if (requestID !== this.requestID) return;
      this.lastError = "";
      this.nextCursor = page.has_more && typeof page.next_cursor === "string" ? page.next_cursor : "";
      const items = Array.isArray(page.items) ? page.items.slice(0, 10) : [];
      this.render(items);
      this.displayedItems = items.length;
      this.loaded = true;
      const pageNumber = this.previousCursors.length + 1;
      const total = Number.isFinite(page.total) ? `총 ${page.total.toLocaleString("ko-KR")}건 중 ` : "";
      text(`${this.kind}Status`, `${total}${pageNumber}페이지 ${items.length}건 · 서비스를 펼쳐 기록을 확인하세요.`);
      text(`${this.kind}Page`, `${pageNumber}페이지${page.has_more ? " · 다음 이력 있음" : " · 마지막 페이지"}`);
    } catch (error) {
      if (requestID !== this.requestID) return;
      this.lastError = String(error.message || error);
      text(`${this.kind}Status`, this.displayedItems > 0 ? "조회를 완료하지 못해 이전 결과를 표시합니다. 연결 상태를 확인한 뒤 다시 조회하세요." : "이력을 불러오지 못했습니다. 연결 상태를 확인한 뒤 검색 또는 새로고침으로 다시 시도하세요.");
      this.nextCursor = "";
    } finally {
      if (requestID === this.requestID) this.setBusy(false);
    }
  }

  setBusy(busy) {
    this.busy = busy;
    byId(`${this.kind}Groups`).setAttribute("aria-busy", String(busy));
    byId(`${this.kind}Previous`).disabled = busy || this.previousCursors.length === 0;
    byId(`${this.kind}Next`).disabled = busy || !this.nextCursor;
  }

  next() {
    if (this.busy || !this.nextCursor) return;
    this.previousCursors.push(this.cursor);
    this.cursor = this.nextCursor;
    this.load();
  }

  previous() {
    if (this.busy || !this.previousCursors.length) return;
    this.cursor = this.previousCursors.pop();
    this.load();
  }

  render(items) {
    const grouped = new Map();
    for (const item of items) {
      const name = this.kind === "findings" ? item.origin_service || "" : (item.process || {}).origin_service || "";
      if (!grouped.has(name)) grouped.set(name, []);
      grouped.get(name).push(item);
    }
    const nodes = [];
    for (const [name, entries] of grouped) {
      const group = document.createElement("details");
      group.className = "service-group";
      group.open = this.openGroups.has(name);
      const summary = document.createElement("summary");
      const label = document.createElement("span");
      label.textContent = serviceLabel(name);
      const count = document.createElement("span");
      count.className = "pill";
      count.textContent = `${entries.length}건`;
      summary.append(label, count);
      group.append(summary);
      group.addEventListener("toggle", () => group.open ? this.openGroups.add(name) : this.openGroups.delete(name));
      for (const entry of entries) group.append(this.kind === "findings" ? findingCard(entry) : eventCard(entry));
      nodes.push(group);
    }
    byId(`${this.kind}Groups`).replaceChildren(...nodes);
    byId(`${this.kind}Empty`).classList.toggle("hidden", items.length !== 0);
  }
}

function recordDetails(fields) {
  const details = document.createElement("details");
  details.className = "record-details";
  const summary = document.createElement("summary");
  summary.textContent = "상세 보기";
  const list = document.createElement("dl");
  list.className = "detail-list";
  for (const [name, value] of fields) {
    const key = document.createElement("dt"); key.textContent = name;
    const description = document.createElement("dd"); description.textContent = value === undefined || value === null || value === "" ? "없음" : String(value);
    list.append(key, description);
  }
  details.append(summary, list);
  return details;
}

function recordsBadge(kind, value) {
  const classes = ["critical", "high", "medium", "low", "open", "closed", "resolved", "complete", "partial", "incomplete"];
  return tag(operatorLabel(kind, value), classes.includes(value) ? value : "inactive");
}

function recordsLayout(time, title, description, context, badges) {
  const article = document.createElement("article"); article.className = "history-item operator-record";
  const timestamp = document.createElement("time"); timestamp.className = "record-time"; timestamp.textContent = fmtTime(time);
  if (time && !Number.isNaN(new Date(time).getTime())) timestamp.setAttribute("datetime", new Date(time).toISOString());
  const main = document.createElement("div"); main.className = "record-main";
  const heading = document.createElement("h3"); heading.textContent = title;
  const summary = document.createElement("p"); summary.className = "record-summary"; summary.textContent = description;
  const origin = document.createElement("p"); origin.className = "record-context"; origin.textContent = context;
  main.append(heading);
  if (description) main.append(summary);
  main.append(origin);
  const status = document.createElement("div"); status.className = "record-status"; status.append(...badges);
  article.append(timestamp, main, status);
  return article;
}

function recordsFindingText(finding) {
  return findingRuleText(finding);
}

function recordsFindingProcess(finding) {
  if (finding.process && typeof finding.process === "object") return finding.process;
  if (typeof state !== "undefined" && state.data && Array.isArray(state.data.events)) {
    const evidence = new Set(finding.evidence_event_ids || []);
    const event = state.data.events.find((item) => evidence.has(item.event_id));
    return event ? event.process || {} : {};
  }
  return {};
}

function recordsConfidence(value) {
  if (!Number.isFinite(value)) return "확인되지 않음";
  const description = value >= .9 ? "연결 정보가 충분함" : value >= .7 ? "일부 정보로 연결함" : "연결 정보가 부족함";
  return `${description} · 원본 값 ${value}`;
}

function recordsRiskFields(finding) {
  const factors = Array.isArray(finding.risk_factors) ? finding.risk_factors.slice(0, 8) : [];
  if (!factors.length) return [["규칙 점수", Number.isFinite(finding.risk_score) ? `${finding.risk_score}/100 · 규칙 등급을 점수로 표시한 값이며 악성 확률이 아닙니다.` : "이전 기록 · 점수 없음"]];
  const score = Number.isFinite(finding.risk_score) ? `${finding.risk_score}/100` : "점수 미확인";
  const fields = [["규칙 기여 점수 합계", `${score} · 관찰 근거별 기여 점수의 합계(최대 100점)입니다. 악성 확률이나 실제 공격 확정을 뜻하지 않습니다.`]];
  factors.forEach((factor, index) => {
    const contribution = factor && Number.isInteger(factor.score) && factor.score >= 0 && factor.score <= 100 ? `+${factor.score}점` : "점수 미확인";
    fields.push([`관찰 근거 ${index + 1}`, `${contribution} · ${findingRiskFactorText(factor)}`]);
  });
  return fields;
}

function findingCard(finding) {
  const copy = recordsFindingText(finding), process = recordsFindingProcess(finding);
  const badges = [recordsBadge("severity", finding.severity)];
  badges.push(tag(findingResponseLabel(finding), "response-result"));
  if (isSelfTestFinding(finding)) badges.push(tag("기능 점검", "selftest"));
  const origin = [serviceLabel(finding.origin_service), process.exe, process.pid ? `PID ${process.pid}` : ""].filter(Boolean).join(" · ");
  const article = recordsLayout(finding.created_at, copy.title, copy.description, origin, badges);
  article.append(recordDetails([
    ["검토 상태", operatorLabel("state", finding.state)], ["탐지 규칙", finding.rule_id], ["탐지 원문", finding.summary],
    ...recordsRiskFields(finding),
    ...(finding.detection_only === true ? [["대응 범위", `${isPrivilegeRule(finding.rule_id)?"권한 탐지 전용":"확장 탐지 전용"} · 이 탐지는 자동 종료 대상에 포함되지 않습니다.`]] : []),
    [isPrivilegeRule(finding.rule_id)?"관측 근거":"추적 근거", isPrivilegeRule(finding.rule_id)?privilegeConfidence(finding.confidence):recordsConfidence(finding.confidence)], ["증거 기록", `${(finding.evidence_event_ids || []).length}건`],
    ["탐지 식별자", finding.finding_id], ["규칙 버전", finding.rule_version], ["프로세스 식별자", finding.process_key],
    ["증거 이벤트 식별자", (finding.evidence_event_ids || []).join(" · ")], ["수집 출처", finding.source],
    ["적용 정책", finding.policy_revision ? `${finding.policy_revision}번` : "서버 자체 설정"],
  ]));
  return article;
}

function eventCard(event) {
  const process = event.process || {};
  const observation = eventObservation(event);
  const context = [serviceLabel(process.origin_service), process.pid ? `PID ${process.pid}` : "실행 번호 미확인", event.event_type==="process.credential_change" ? "별도 전·후 자격 증명 확인" : process.euid === 0 ? "관리자 권한(EUID 0) 실행 스냅샷" : process.euid >= 0 ? `실행 스냅샷 사용자 번호 ${process.euid}` : "실행 권한 미확인"].join(" · ");
  const article = recordsLayout(event.event_time, process.exe || "실행 파일 미확인", observation.summary, context, [tag(operatorLabel("event", event.event_type), "inactive")]);
  article.append(recordDetails([
    ["실행 활동", operatorLabel("event", event.event_type)], ["상위 실행 번호", process.ppid],
    ...observation.fields,
    ["실행 스냅샷 실제 사용자 번호", credentialLabel(process.uid)], ["실행 스냅샷 EUID", credentialLabel(process.euid)],
    ["정보 확인 수준", operatorLabel("completeness", event.completeness)], ["원본 정보 상태", event.completeness],
    ["이벤트 식별자", event.event_id], ["원본 이벤트 종류", event.event_type], ["수집 출처", event.source],
    ["작업 경로", process.cwd], ["기록된 실행 인자", (process.argv || []).join(" ")],
    ["추적 근거", operatorLabel("lineage", process.lineage_confidence)], ["누락된 정보", (event.missing_fields || []).join(", ")],
    ["숨김 처리한 정보", (event.redacted_fields || []).join(", ")],
  ]));
  const actions = document.createElement("div"); actions.className = "record-actions";
  const button = document.createElement("button"); button.type = "button"; button.className = "table-button";
  button.textContent = "실행 경로 보기";
  button.setAttribute("aria-label", `PID ${process.pid || "미확인"} 현재 실행 경로 보기`);
  button.disabled = !process.pid;
  button.addEventListener("click", () => showProcessTree(process.pid));
  actions.append(button); article.append(actions);
  return article;
}

function credentialLabel(value) {
  return value === undefined || value === null || value < 0 ? "미확인" : String(value);
}

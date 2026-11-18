"use strict";

const expandedRules = new Set();
const ruleSummaries = new Map();

function ruleDefinition(id) {
  const current = state.data?.rules?.rules;
  const match = Array.isArray(current) && current.find(rule => rule?.id === id && rule.title);
  return match || (typeof bundledRuleDefinitions !== "undefined" && bundledRuleDefinitions.find(rule => rule.id === id));
}

function ruleSensorText(sensor) {
  const states = {active:"관측 확인", available:"사용 가능", unverified:"관측 미확인", inactive:"비활성", error:"오류"};
  const name = Object.hasOwn(capabilityNames, sensor.name) ? capabilityNames[sensor.name] : sensor.name;
  const status = Object.hasOwn(states, sensor.state) ? states[sensor.state] : "상태 미확인";
  const timestamp = sensor.verified_at ? " · " + new Date(sensor.verified_at).toLocaleString("ko-KR", {hour12:false}) : "";
  const collector = sensor.required_collector ? " · " + sensor.required_collector : "";
  return name + collector + " · " + status + timestamp;
}

function makeRuleRow(rule) {
  const row = document.createElement("tr");
  const name = document.createElement("th");
  name.setAttribute("scope", "row");
  name.textContent = rule.title || rule.id;
  const id = document.createElement("div");
  id.className = "section-note";
  id.textContent = rule.id;
  const profiles = {base:"기본", extended:"확장", privilege:"권한", file:"파일", network:"네트워크"};
  const fields = values => Array.isArray(values) && values.length ? values.join(", ") : "미확인";
  const details = recordDetails([
    ["설명", rule.description || "미확인"],
    ["프로필", Object.hasOwn(profiles, rule.profile) ? profiles[rule.profile] : rule.profile || "미확인"],
    ["입력 이벤트", fields(rule.event_types)],
    ["필수 필드", fields(rule.required_fields)],
  ]);
  details.open = expandedRules.has(rule.id);
  const summary = details.children[0];
  summary.textContent = "규칙 상세";
  ruleSummaries.set(rule.id, summary);
  details.addEventListener("toggle", () => {
    if (ruleSummaries.get(rule.id) !== summary) return;
    if (details.open) expandedRules.add(rule.id);
    else expandedRules.delete(rule.id);
  });
  name.append(id, details);
  row.append(name);

  const responseModes = {observe:"관측 전용", would_block:"모의 대응", enforce:"안전 조건 충족 시 종료 가능", detection_only:"탐지 전용"};
  const response = Object.hasOwn(responseModes, rule.response) ? responseModes[rule.response] : "미확인";
  const sensors = Array.isArray(rule.sensors) ? rule.sensors.filter(sensor => sensor?.name).map(ruleSensorText) : [];
  const policy = rule.enabled === true ? "활성" : rule.enabled === false ? "비활성" : "미확인";
  for (const values of [[rule.version || "미확인"], [policy, rule.reason], sensors.length ? sensors : ["센서 미확인"], [rule.enabled === false ? "종료 대상 아님" : response]]) {
    const cell = document.createElement("td");
    for (const value of values.filter(Boolean)) {
      const line = document.createElement("div");
      line.textContent = value;
      cell.append(line);
    }
    row.append(cell);
  }
  return row;
}

function renderRuleCatalog() {
  const catalog = state.data?.rules;
  const available = Array.isArray(catalog?.rules);
  const query = byId("ruleSearch").value.trim().toLowerCase();
  const rules = available ? catalog.rules.filter(rule => rule?.id &&
    [rule.id, rule.title].some(value => typeof value === "string" && value.toLowerCase().includes(query))) : [];
  byId("ruleSearch").disabled = !available;
  byId("ruleTable").hidden = !rules.length;
  let focusedID;
  for (const [id, summary] of ruleSummaries) if (document.activeElement === summary) focusedID = id;
  ruleSummaries.clear();
  byId("ruleRows").replaceChildren(...rules.map(makeRuleRow));
  ruleSummaries.get(focusedID)?.focus({preventScroll:true});
  const sources = {managed:"중앙 정책", local:"서버 설정"};
  const source = available && Object.hasOwn(sources, catalog.policy_source) ? sources[catalog.policy_source] : "정책 출처 미확인";
  const scopes = available && Object.hasOwn(sources, catalog.service_observation_source) ? " · 파일·TCP 범위 " + sources[catalog.service_observation_source] : "";
  text("rulePolicy", available ? source + (catalog.policy_revision ? " · 리비전 " + catalog.policy_revision : "") + scopes : "");
  text("ruleCount", available ? `전체 ${catalog.rules.length}개 중 ${rules.length}개 표시` : "에이전트에서 규칙 현황을 가져오지 못했습니다.");
}

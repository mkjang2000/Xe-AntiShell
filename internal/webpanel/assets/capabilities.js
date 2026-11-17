"use strict";

const capabilityNames = {
  "observation.process_exec": "실행 정보 수집",
  "observation.process_lineage": "서비스 실행 경로 추적",
  "response.terminate": "의심 프로세스 종료",
  "collector.tetragon": "실시간 수집기",
  "collector.audit": "보조 수집기",
  "host.platform": "운영체제 정보",
  "integrity.ima": "파일 측정 정보",
  "integrity.tpm": "서버 보안칩",
  "kernel.btf": "실행 수집 보조 정보",
  "kernel.cgroup": "서비스 구분 정보",
  "kernel.ebpf": "실시간 수집 환경",
  "observation.file": "파일 활동 감시",
  "observation.network": "네트워크 활동 감시",
  "observation.credential_change": "권한 변경 감시",
};
const capabilityOrder = Object.keys(capabilityNames);
const capabilityDetailsOpen = new Set();
const capabilitySummaries = new Map();

function isPrerequisite(name) {
  return name.startsWith("host.") || name.startsWith("kernel.") || name.startsWith("integrity.");
}

// Confirmed implemented collection takes precedence over passive diagnostics;
// disagreements remain visible without hiding the raw technical evidence.
function capabilityPresentation(name, value) {
  const capability = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const prerequisite = isPrerequisite(name);
  const category = prerequisite ? "prerequisite" : capability.implementation === "planned" ? "planned" : "operational";
  const knownName = Object.hasOwn(capabilityNames, name);
  const result = {title: knownName ? capabilityNames[name] : "추가 진단 항목", label: "확인 필요", tone: "unverified", description: "현재 기능 상태를 판단할 정보가 충분하지 않습니다.", action: "기술 정보에서 진단 결과를 확인하세요.", active: false, category};
  const show = (label, tone, description, action = "", active = false) => Object.assign(result, {label, tone, description, action, active});
  const runtime = capability.runtime_state;
  const support = capability.state;
  const reason = typeof capability.runtime_reason === "string" ? capability.runtime_reason : "";
  const knownSupport = ["supported", "limited", "unsupported", "error"].includes(support);
  if (!knownName) return result;
  if (category === "planned") return show("개발 예정", "planned", "현재 버전에는 이 감시 기능이 포함되어 있지 않습니다.");
  if (runtime === "error") return show("오류", "error", "기능 실행 중 오류가 발생했습니다.", "수집 프로그램과 서버 로그를 확인하세요.");

  if (name === "integrity.tpm") {
    if (support === "error") return show("확인 오류", "error", "서버 보안칩이 있는지 확인하지 못했습니다.", "서버 장치 정보를 확인하세요.");
    if (support === "supported") return show("장치 있음", "inactive", "서버에 보안칩이 있습니다. 에이전트 무결성 검증은 아직 제공하지 않습니다.");
    if (support === "unsupported") return show("장치 없음", "inactive", "서버에 보안칩이 없습니다. 웹셸 탐지에 필수인 장치는 아닙니다. 무결성 검증은 아직 제공하지 않습니다.");
    return result;
  }
  if (name === "integrity.ima") {
    if (support === "error") return show("확인 오류", "error", "운영체제의 파일 측정 정보를 확인하지 못했습니다.", "서버 측정 설정을 확인하세요.");
    if (support === "supported") return show("정보 있음", "inactive", "운영체제의 파일 측정 정보를 확인했습니다. 에이전트 무결성 검증은 아직 제공하지 않습니다.");
    if (support === "unsupported") return show("제공 안 함", "inactive", "운영체제가 파일 측정 정보를 제공하지 않습니다. 웹셸 탐지에 필수인 정보는 아닙니다.");
    return result;
  }
  if (!knownSupport) return result;

  // An unused alternate collector is intentional, even if its prerequisites
  // are absent. It must not imply that the selected collection path is broken.
  if (runtime === "inactive" && name.startsWith("collector.") && reason === "not the selected process collector") {
    return show("사용 안 함", "inactive", "현재 다른 수집 방법을 사용하고 있어 이 수집기는 선택하지 않았습니다.");
  }
  if (runtime === "active" && capability.implementation === "implemented") {
    const action = support === "unsupported" || support === "error" ? "실동작과 사전 검사 결과가 다릅니다. 기술 정보에서 사전 검사 진단을 확인하세요." : "";
    if (name === "kernel.ebpf") return show("동작 확인", "active", "프로세스 실행 수집에 사용된 커널 기능의 동작을 확인했습니다.", action);
    if (name.startsWith("collector.") || name.startsWith("observation.")) {
      const audit = reason.includes("audit");
      const descriptions = {
        "collector.tetragon": "실행 정보를 실시간으로 수집하고 있습니다.",
        "collector.audit": "서버의 감사 기록에서 실행 정보를 수집하고 있습니다. 전체 수집 규칙의 적용 범위는 확인이 필요합니다.",
        "observation.process_exec": audit ? "실행을 관찰하며 탐지 대상 이력만 저장합니다. 현재 수집 방법은 프로세스 종료 정보를 제공하지 않습니다." : "실행을 관찰하며 탐지 대상 이력만 저장합니다.",
        "observation.process_lineage": audit ? "실행 기록과 현재 프로세스 정보로 서비스 실행 경로를 추정합니다. 종료 정보는 제공되지 않습니다." : "어떤 서비스에서 실행됐는지 추적합니다. 일부 상위 실행 정보가 누락될 수 있습니다.",
      };
      return show("정상 수집", "active", descriptions[name] || "실행 정보를 수집하고 있습니다.", action, true);
    }
  }
  if (support === "error") {
    if (runtime === "active") return show("확인 필요", "unverified", "실행 정보는 수신 중이지만 서버 조건 검사에서 오류가 보고됐습니다.", "기술 정보에서 사전 검사 결과를 확인하세요.");
    return show("확인 오류", "error", "서버 지원 조건을 확인하는 중 오류가 발생했습니다.", "서버 설정과 로그를 확인하세요.");
  }
  if (support === "unsupported") {
    if (runtime === "active") return show("확인 필요", "unverified", "동작 보고와 서버 지원 정보가 서로 일치하지 않습니다.", "수집 상태와 기술 정보를 확인하세요.");
    const description = name === "response.terminate" ? "이 서버에서는 안전한 프로세스 종료 기능을 사용할 수 없습니다." : prerequisite ? "현재 서버에서 이 보조 정보를 제공하지 않습니다. 다른 수집 방법의 사용 여부를 확인하세요." : "현재 서버에서는 이 기능을 사용할 수 없습니다.";
    return show("사용 불가", "unsupported", description, prerequisite ? "" : "서버 지원 조건을 확인하세요.");
  }
  if (name === "response.terminate") {
    if (runtime === "available" || runtime === "inactive") return show("자동 대응 꺼짐", "inactive", "프로세스를 자동으로 종료하지 않습니다. 종료 기능의 서버 설정이 꺼져 있습니다.");
    if (runtime === "active" && capability.implementation === "implemented") return show("조건부 사용", "unverified", "서버의 종료 설정이 허용되어 있습니다. 실제 종료는 보안 정책과 안전 조건을 모두 만족할 때만 실행됩니다.");
    return show("확인 필요", "unverified", "프로세스를 안전하게 종료할 수 있는지 아직 확인하지 못했습니다.", "자동 대응을 사용하려면 서버 설정을 확인하세요.");
  }
  if (runtime === "unverified" && (reason === "selected collector stream is not running" || reason === "source operation failed; active attachment is no longer established by this agent")) return show(prerequisite ? "확인 필요" : "수집 중단", prerequisite ? "unverified" : "error", "수집 연결이 중단되어 동작을 확인할 수 없습니다.", "수집기 연결 상태를 확인하세요.");
  if (prerequisite) {
    if (support === "limited") return show("확인 필요", "unverified", "이 보조 정보의 일부 조건은 아직 확인하지 못했습니다. 실제 수집 여부는 위 수집 기능에서 확인하세요.");
    if (support === "supported") {
      const descriptions = {
        "host.platform": "서버의 운영체제 정보를 확인했습니다.",
        "kernel.btf": "실행 정보 수집에 필요한 커널 보조 정보를 읽을 수 있습니다.",
        "kernel.cgroup": "프로세스를 서비스 단위로 구분할 수 있는 정보를 확인했습니다.",
        "kernel.ebpf": "실시간 수집에 필요한 서버 조건을 확인했습니다. 실제 동작 여부는 수집 기능에서 확인하세요.",
      };
      return show("확인 완료", "inactive", descriptions[name] || "서버의 보조 정보를 확인했습니다.");
    }
    return result;
  }
  if (capability.implementation !== "implemented") return result;
  if (runtime === "unverified") {
    return show("확인 대기", "unverified", "수집 설정은 선택되었으며 실제 실행 정보가 들어오는지 확인하고 있습니다.");
  }
  if (runtime === "available") return show("설정 대기", "unverified", "서버 조건은 확인했지만 실제 수집 동작은 아직 확인되지 않았습니다.", "사용할 기능이면 수집 설정을 확인하세요.");
  if (runtime === "inactive") return show("수집 안 함", "inactive", "현재 실행 정보를 받는 수집기가 연결되어 있지 않습니다.", "수집 설정과 연결 상태를 확인하세요.");
  return result;
}

function renderCapabilities(capabilities) {
  const operational = [], prerequisites = [], planned = [];
  let focusedName = "";
  for (const [name, summary] of capabilitySummaries) if (document.activeElement === summary) focusedName = name;
  capabilitySummaries.clear();
  let activeCount = 0;
  const entries = Object.entries(capabilities || {}).sort(([a], [b]) => {
    const order = (name) => { const index = capabilityOrder.indexOf(name); return index < 0 ? capabilityOrder.length : index; };
    return order(a) - order(b) || a.localeCompare(b);
  });
  const names = new Set(entries.map(([name]) => name));
  for (const name of capabilityDetailsOpen) if (!names.has(name)) capabilityDetailsOpen.delete(name);
  for (const [name, capability] of entries) {
    const presentation = capabilityPresentation(name, capability);
    const row = capabilityRow(name, capability, presentation);
    if (presentation.category === "prerequisite") prerequisites.push(row);
    else if (presentation.category === "planned") planned.push(row);
    else { operational.push(row); if (presentation.active) activeCount++; }
  }
  byId("capabilityList").replaceChildren(...operational);
  byId("prerequisiteCapabilityList").replaceChildren(...prerequisites);
  byId("plannedCapabilityList").replaceChildren(...planned);
  text("capabilitySummary", `정상 수집 ${activeCount}개`);
  text("plannedCapabilityCount", `${planned.length}개`);
  byId("plannedCapabilities").classList.toggle("hidden", planned.length === 0);
  if (focusedName && capabilitySummaries.has(focusedName)) capabilitySummaries.get(focusedName).focus({preventScroll: true});
}

function capabilityBadge(label, tone) {
  const badge = document.createElement("span"); badge.className = `tag ${tone}`; badge.textContent = label; return badge;
}

function capabilityRow(name, value, presentation = capabilityPresentation(name, value)) {
  const capability = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const row = document.createElement("div"); row.className = "cap-row";
  const identity = document.createElement("div"); identity.className = "cap-identity";
  const title = document.createElement("strong"); title.textContent = presentation.title; identity.append(title);
  const badges = document.createElement("div"); badges.className = "cap-badges";
  badges.append(capabilityBadge(presentation.label, presentation.tone));
  const description = document.createElement("div"); description.className = "cap-detail";
  const explanation = document.createElement("span"); explanation.textContent = presentation.description; description.append(explanation);
  if (presentation.action) { const action = document.createElement("small"); action.className = "cap-action"; action.textContent = presentation.action; description.append(action); }
  const technical = document.createElement("details"); technical.className = "cap-technical";
  technical.open = capabilityDetailsOpen.has(name);
  technical.addEventListener("toggle", () => { if (technical.open) capabilityDetailsOpen.add(name); else capabilityDetailsOpen.delete(name); });
  const summary = document.createElement("summary"); summary.textContent = "기술 정보";
  capabilitySummaries.set(name, summary);
  const values = document.createElement("dl"); values.className = "detail-list";
  const raw = (value) => typeof value === "string" && value ? value : "제공 안 함";
  for (const [label, value] of [["항목 식별자", name], ["진단 제공자", raw(capability.provider)], ["사전 검사 상태", raw(capability.state)], ["실동작 상태", raw(capability.runtime_state)], ["구현 상태", raw(capability.implementation)], ["사전 검사 원문", raw(capability.reason)], ["실동작 원문", raw(capability.runtime_reason)], ["동작 확인 시각", capability.verified_at ? fmtTime(capability.verified_at) : "제공 안 함"]]) {
    const dt = document.createElement("dt"); dt.textContent = label;
    const dd = document.createElement("dd"); dd.textContent = value; values.append(dt, dd);
  }
  technical.append(summary, values); row.append(identity, badges, description, technical); return row;
}

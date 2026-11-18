"use strict";

const capabilityNames = {
  "observation.process_exec": "실행 정보 수집",
  "observation.interpreter_exec": "인터프리터 실행 옵션 관측",
  "observation.process_lineage": "서비스 실행 경로 추적",
  "response.terminate": "의심 프로세스 종료",
  "collector.tetragon": "실시간 수집기",
  "collector.audit": "보조 수집기",
  "host.platform": "운영체제 정보",
  "integrity.agent_files": "에이전트 파일 무결성 측정",
  "integrity.ima": "파일 측정 정보",
  "integrity.tpm": "서버 보안칩",
  "kernel.btf": "실행 수집 보조 정보",
  "kernel.cgroup": "서비스 구분 정보",
  "kernel.ebpf": "실시간 수집 환경",
  "observation.file": "파일 쓰기 관측",
  "observation.network": "TCP 연결 요청 관측",
  "observation.credential_change": "권한 변경 전·후 관측",
  "detection.privilege_rules": "전역 root·권한 변경 탐지 규칙",
  "detection.service_rule_controls": "서비스별 규칙 제어와 만료 예외",
  "detection.service_observations": "서비스별 파일·TCP 중앙 정책",
};
const capabilityOrder = Object.keys(capabilityNames);
const capabilityDetailsOpen = new Set();
const capabilitySummaries = new Map();

function isPrerequisite(name) {
  return name.startsWith("host.") || name.startsWith("kernel.") || (name.startsWith("integrity.") && name !== "integrity.agent_files");
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
    if (support === "supported") return show("장치 있음", "inactive", "서버 보안칩 장치를 확인했습니다. TPM 기반 원격 증명은 별도 기능입니다.");
    if (support === "unsupported") return show("장치 없음", "inactive", "서버에 보안칩이 없습니다. 웹셸 탐지에 필수인 장치는 아닙니다. TPM 기반 원격 증명은 별도 기능입니다.");
    return result;
  }
  if (name === "integrity.ima") {
    if (support === "error") return show("확인 오류", "error", "운영체제의 파일 측정 정보를 확인하지 못했습니다.", "서버 측정 설정을 확인하세요.");
    if (support === "supported") return show("정보 있음", "inactive", "커널 IMA 측정 정보가 있습니다. 에이전트 파일의 검사 결과는 센트럴에서 확인하세요.");
    if (support === "unsupported") return show("제공 안 함", "inactive", "운영체제가 파일 측정 정보를 제공하지 않습니다. 웹셸 탐지에 필수인 정보는 아닙니다.");
    return result;
  }
  if (!knownSupport) return result;
  if (name === "integrity.agent_files") {
    if (support === "supported" && runtime === "available" && capability.details?.contract === "1") {
      return show("측정 지원", "inactive", "승인된 리비전의 에이전트 파일을 측정할 수 있습니다.", "최근 측정 시각과 파일별 비교 결과는 센트럴에서 확인하세요.");
    }
    return result;
  }
  if (name === "detection.service_rule_controls" && runtime === "available" && capability.details?.contract === "1") {
    return show("정책 지원", "inactive", "규칙별 서비스 설정과 예외 만료 시간을 적용할 수 있습니다.");
  }
  if (name === "detection.service_observations") {
    if (runtime === "available" && capability.implementation === "implemented" && capability.details?.contract === "1") return show("정책 지원", "inactive", "중앙에서 서명한 보호 경로와 허용 TCP 목적지를 적용할 수 있습니다. 센서 수신 상태는 파일 쓰기·TCP 연결 요청 관측에서 확인하세요.");
    return result;
  }
  if (name === "detection.privilege_rules") {
    if (capability.implementation !== "implemented") return result;
    if (support === "unsupported") return show("프로필 사용 불가", "unsupported", "현재 수집 입력이 전역 실행·권한 변경 근거를 누락할 수 있어 이 프로필을 활성화할 수 없습니다.", "수집 인자를 검토한 뒤 다시 확인하세요.");
    if (runtime === "active") return show("규칙 적용", "active", "전역 root 실행과 검증된 권한 변경 근거를 평가하는 규칙이 적용됐습니다. 이 규칙은 탐지 전용입니다. 실제 권한 변경 센서의 수신 여부는 ‘권한 변경 전·후 관측’에서 확인하세요.");
    if (runtime === "available" || runtime === "inactive") return show("규칙 제공", "inactive", "현재 버전이 탐지 규칙을 제공합니다. 규칙 적용과 커널 센서의 실제 동작을 의미하지 않습니다.", "적용 정책과 권한 변경 관측 상태를 함께 확인하세요.");
    return show("규칙 확인 필요", "unverified", "탐지 규칙의 적용 상태를 확인할 수 없습니다. 센서의 수집 여부와는 별도 항목입니다.");
  }


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
        "observation.interpreter_exec": "실행 옵션 관측 이벤트를 수신했습니다. 전용 수집 정책의 옵션 조건 또는 분리된 실행 인자로 직접 코드·임시 스크립트 실행 요청을 구분합니다. 기존 프로세스 내부 실행과 실행 성공·코드 내용은 확인하지 않습니다.",
        "observation.credential_change": "같은 commit_creds 호출의 전·후 자격 증명과 성공 반환을 수신했습니다. 변경이 악성이라는 뜻은 아닙니다. UID/EUID·Capability·user namespace의 관측 범위 안에서 판단합니다.",
        "observation.file": "선택한 수집 정책의 파일 쓰기 이벤트를 수신했습니다. 경로와 호출 반환값을 관측하며 파일 내용·모든 쓰기·디스크 반영을 보장하지 않습니다.",
        "observation.network": "선택한 수집 정책의 TCP 연결 요청 이벤트를 수신했습니다. 대상과 호출 반환값을 관측하며 연결 완료·모든 통신·전송 내용은 확인하지 않습니다.",
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
  if (name === "observation.credential_change") {
    if (runtime === "unverified" || runtime === "available") return show("관측 확인 대기", "unverified", "규칙 구현이나 정책 설치만으로 센서 동작을 확인할 수 없습니다. 전용 정책에서 완전한 전·후 자격 증명과 성공 반환을 수신해야 동작이 확인됩니다.", "전용 수집 정책 설치·호환성과 에이전트의 권한 관측 설정을 확인하세요.");
    if (runtime === "inactive") return show("관측 꺼짐", "inactive", "권한 변경 전·후 관측이 꺼져 있거나 해당 수집 경로가 선택되지 않았습니다. 전역 root 실행 규칙의 지원 여부와 구분하세요.");
  }
  const scopedObservation = ["observation.interpreter_exec", "observation.file", "observation.network"].includes(name);
  if (runtime === "unverified") {
    return show("확인 대기", "unverified", scopedObservation ? "수집 정책이나 설정만으로 동작을 확인할 수 없습니다. 이 기능의 실제 관측 이벤트를 기다리고 있습니다." : "수집 설정은 선택되었으며 실제 실행 정보가 들어오는지 확인하고 있습니다.");
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

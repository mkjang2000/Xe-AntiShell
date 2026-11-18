"use strict";

const state = {data: null, services: [], activeView: "overview", refreshing: false};
let historyViews;
const byId = id => document.getElementById(id);
const text = (id, value) => {byId(id).textContent = value;};

function fmtTime(value) {
  if (!value) return "없음";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "미확인" : new Intl.DateTimeFormat("ko-KR", {month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:false}).format(date);
}
function relative(value) {
  if (!value) return "이력 없음";
  const date = new Date(value).getTime();if (!Number.isFinite(date)) return "미확인";
  const seconds = Math.max(0, Math.round((Date.now() - date) / 1000));
  if (seconds < 60) return `${seconds}초 전`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}분 전`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}시간 전`;
  return `${Math.floor(seconds / 86400)}일 전`;
}
function tag(value, extra) {
  const span = document.createElement("span");span.className = `tag ${extra || "inactive"}`;span.textContent = value || "미확인";return span;
}
async function loadOverview() {
  if (state.refreshing) return;
  state.refreshing = true;text("refreshState", "갱신 중");byId("refreshButton").disabled = true;
  try {
    const response = await fetch("/api/overview", {headers:{Accept:"application/json"}});
    if (response.status === 401) {location.href = "/login";return;}
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    state.data = await response.json();render();
    byId("errorBanner").classList.add("hidden");text("refreshState", `${fmtTime(state.data.server_time)} 갱신`);
  } catch (error) {
    text("errorBanner", "최신 상태를 불러오지 못했습니다. 아래 정보는 마지막 조회 결과입니다. 연결 상태를 확인한 뒤 새로고침하세요.");
    byId("errorBanner").classList.remove("hidden");text("refreshState", "갱신 실패");
  } finally {state.refreshing = false;byId("refreshButton").disabled = false;}
}
function render() {
  const {status, capabilities} = state.data;
  const platform = capabilities.platform || {};
  text("hostSubtitle", `${platform.hostname || "서버 미확인"} · ${platform.pretty_name || "운영체제 미확인"}`);
  renderRuleCatalog();
  renderOperatorOverview(state.data);renderSystem(platform, capabilities, status);
  renderResources(state.data.resources);renderManagedStatus(state.data.managed);
}
function renderSystem(platform, capabilities, status) {
  const fields = [["서버", platform.hostname], ["운영체제", platform.pretty_name], ["수집 시작", fmtTime(status.started_at)], ["수집 방식", operatorLabel("collector", status.collector)], ["프로그램 버전", status.version]];
  const nodes = [];
  for (const [name, value] of fields) {const key = document.createElement("dt");key.textContent = name;const data = document.createElement("dd");data.textContent = value || "미확인";nodes.push(key, data);}
  byId("systemDetails").replaceChildren(...nodes);
  const previous = byId("systemTechnical").children[0];
  const expanded = previous?.open || false, focused = previous && document.activeElement === previous.children[0];
  const details = recordDetails([["CPU 아키텍처", platform.architecture], ["커널 버전", platform.kernel_release], ["부팅 식별자", platform.boot_id], ["수집기 식별자", status.collector], ["마지막 오류 원문", status.last_error]]);
  details.open = expanded;details.children[0].textContent = "기술 정보";byId("systemTechnical").replaceChildren(details);
  if (focused) details.children[0].focus({preventScroll:true});
  const {"storage.capacity": capacity, ...otherCapabilities} = capabilities.capabilities || {};
  renderCapacity(status.capability_report?.capabilities?.["storage.capacity"] || capacity, state.data?.managed?.enrolled);
  renderCapabilities(otherCapabilities);
}
async function showProcessTree(pid) {
  const dialog = byId("processDialog");text("dialogTitle", `프로세스 실행 경로 · PID ${pid}`);
  const loading = document.createElement("p");loading.className = "muted";loading.textContent = "불러오는 중…";byId("processTree").replaceChildren(loading);dialog.showModal();
  try {
    const response = await fetch(`/api/process-tree?pid=${encodeURIComponent(pid)}`);if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const processes = await response.json();
    const nodes = processes.map(process => {
      const node = document.createElement("div");node.className = "process-node";
      const title = document.createElement("strong");title.textContent = `${process.exe || "실행 파일 미확인"} · PID ${process.pid}`;
      const detail = document.createElement("span");detail.textContent = `${serviceLabel(process.origin_service)} · ${process.uid === 0 ? "관리자" : `사용자 ${process.uid}`} · ${operatorLabel("lineage", process.lineage_confidence)}`;
      node.append(title, detail);return node;
    });
    if (!nodes.length) {const empty = document.createElement("p");empty.textContent = "보존된 실행 경로가 없습니다.";nodes.push(empty);}byId("processTree").replaceChildren(...nodes);
  } catch (error) {const failure = document.createElement("p");failure.className = "error-text";failure.textContent = "실행 경로를 불러오지 못했습니다. 수집 상태를 확인한 뒤 다시 조회하세요.";byId("processTree").replaceChildren(failure);}
}
const viewNames = ["overview", "findings", "events", "system"];
function activateView(name, focusTab = false) {
  if (!viewNames.includes(name)) return;state.activeView = name;
  for (const view of viewNames) {const selected = view === name;const tab = byId(`tab-${view}`);tab.setAttribute("aria-selected", String(selected));tab.tabIndex = selected ? 0 : -1;byId(`view-${view}`).hidden = !selected;}
  if (focusTab) byId(`tab-${name}`).focus();if (historyViews[name] && !historyViews[name].loaded) historyViews[name].load();
}
function openFindingService(service) {
  historyViews.findings.selectService(service);
  byId("findingSearch").value = "";byId("severityFilter").value = "";
  byId("includeSelfTests").checked = service === "xeas-detection-selftest.service";
  if (service) historyViews.findings.openGroups.add(service);
  activateView("findings", true);
}
async function loadServices() {
  try {
    const response = await fetch("/api/services", {headers:{Accept:"application/json"}});if (response.status === 401) {location.href = "/login";return;}if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const services = await response.json();state.services = Array.isArray(services) ? services : [];updateServiceSelectors();renderServiceOverview();
  } catch (error) {text("servicesEmpty", "서비스별 이력을 불러오지 못했습니다. 새로고침 후 다시 확인하세요.");byId("servicesEmpty").classList.remove("hidden");}
}
function updateServiceSelectors() {
  byId("observationServices").replaceChildren(...state.services.filter(service => service.name).map(service => {
    const option = document.createElement("option");
    option.value = service.name;
    option.textContent = serviceLabel(service.name);
    return option;
  }));
  for (const kind of ["findings", "events"]) {
    const select = byId(`${kind}Service`), selected = select.value, all = document.createElement("option");all.value = "";all.textContent = "모든 서비스";const options = [all];
    for (const service of state.services) {if (!service.name) continue;const option = document.createElement("option");option.value = service.name;option.textContent = serviceLabel(service.name);options.push(option);}
    if (selected && !options.some(option => option.value === selected)) {const retained = document.createElement("option");retained.value = selected;retained.textContent = serviceLabel(selected);options.push(retained);}select.replaceChildren(...options);select.value = selected;
  }
}
historyViews = {findings: new HistoryView("findings"), events: new HistoryView("events")};initResources();
for (const [index, name] of viewNames.entries()) {
  const tab = byId(`tab-${name}`);tab.addEventListener("click", () => activateView(name));
  tab.addEventListener("keydown", event => {
    let next;
    if (event.key === "ArrowRight") next = viewNames[(index + 1) % viewNames.length];
    else if (event.key === "ArrowLeft") next = viewNames[(index + viewNames.length - 1) % viewNames.length];
    else if (event.key === "Home") next = viewNames[0];else if (event.key === "End") next = viewNames[viewNames.length - 1];
    if (next) {event.preventDefault();activateView(next, true);}
  });
}
initObservations();
byId("ruleSearch").addEventListener("input", renderRuleCatalog);
byId("allFindingsButton").addEventListener("click", () => openFindingService(""));
byId("refreshButton").addEventListener("click", () => {loadOverview();loadServices();if (historyViews[state.activeView]) historyViews[state.activeView].load();});
byId("dialogClose").addEventListener("click", () => byId("processDialog").close());
loadOverview();loadServices();setInterval(loadOverview, 15000);

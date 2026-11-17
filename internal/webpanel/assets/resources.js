"use strict";

const resourceState = {snapshot: null, processPage: 0};

function formatBytes(value) {
  if (!Number.isFinite(value) || value < 0) return "미확인";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatRate(value) {
  return Number.isFinite(value) && value >= 0 ? `${formatBytes(value)}/s` : "계산 중";
}

function formatPercent(value) {
  return Number.isFinite(value) && value >= 0 ? `${value.toFixed(1)}%` : "계산 중";
}

function resourceCard(title, value, description) {
  const card = document.createElement("div"); card.className = "resource-card resource-kpi";
  const label = document.createElement("span"); label.textContent = title;
  const result = document.createElement("strong"); result.textContent = value;
  card.append(label, result);
  if (description) { const detail = document.createElement("span"); detail.textContent = description; card.append(detail); }
  return card;
}

function resourceCount(value) {
  return Number.isFinite(value) && value >= 0 ? value.toLocaleString("ko-KR") : "미확인";
}

function resourceNetworkState(value) {
  const labels = {up:"연결됨",down:"연결 안 됨",dormant:"연결 대기",lowerlayerdown:"하위 연결 끊김",notpresent:"장치 없음",testing:"점검 중"};
  return Object.prototype.hasOwnProperty.call(labels, value) ? labels[value] : "상태 미확인";
}

function resourceTable(title, headings, rows) {
  const wrap = document.createElement("div"); wrap.className = "resource-table-wrap";
  wrap.setAttribute("tabindex", "0"); wrap.setAttribute("role", "region"); wrap.setAttribute("aria-label", title);
  const table = document.createElement("table"); table.className = "resource-table";
  const caption = document.createElement("caption"); caption.textContent = title;
  const head = document.createElement("thead"), header = document.createElement("tr");
  for (const label of headings) { const cell = document.createElement("th"); cell.setAttribute("scope", "col"); cell.textContent = label; header.append(cell); }
  head.append(header);
  const body = document.createElement("tbody");
  for (const values of rows) {
    const row = document.createElement("tr");
    values.forEach((value, index) => { const cell = document.createElement(index === 0 ? "th" : "td"); if (index === 0) cell.setAttribute("scope", "row"); cell.textContent = String(value); row.append(cell); });
    body.append(row);
  }
  if (!rows.length) { const row = document.createElement("tr"), cell = document.createElement("td"); cell.setAttribute("colspan", String(headings.length)); cell.textContent = "표시할 측정 정보가 없습니다."; row.append(cell); body.append(row); }
  table.append(caption, head, body); wrap.append(table);
  return wrap;
}

function resourceWarningLabel(value) {
  const known = {
    "CPU counters unavailable":"CPU 사용량을 확인할 수 없습니다.",
    "RAM counters unavailable":"메모리 사용량을 확인할 수 없습니다.",
    "RAM counters invalid":"메모리 측정값을 다시 확인해야 합니다.",
    "MemAvailable not exposed":"가용 메모리 정보를 제공하지 않는 환경입니다.",
    "filesystem inventory unavailable":"디스크 용량 정보를 확인할 수 없습니다.",
    "disk IO counters unavailable":"디스크 작업량을 확인할 수 없습니다.",
    "interface counters unavailable":"네트워크 사용량을 확인할 수 없습니다.",
    "process inventory unavailable":"실행 중인 프로세스를 확인할 수 없습니다.",
    "process sampling cancelled":"프로세스 조회가 완료되지 않았습니다.",
    "process list truncated for central transport budget":"중앙 전송 크기에 맞춰 일부 프로세스만 보냈습니다.",
  };
  return Object.prototype.hasOwnProperty.call(known, value) ? known[value] : "일부 자원 정보를 확인하지 못했습니다.";
}

function renderResourceWarnings(errors) {
  const target = byId("resourceWarnings");
  const previous = Array.from(target.children).find((child) => child.tagName === "DETAILS");
  const expanded = previous ? previous.open : false;
  const focused = previous && document.activeElement === previous.children[0];
  target.replaceChildren();
  target.classList.toggle("hidden", errors.length === 0);
  if (!errors.length) return;
  const summary = document.createElement("p"); summary.textContent = [...new Set(errors.map(resourceWarningLabel))].join(" ");
  const details = document.createElement("details"); details.className = "resource-warning-details";
  details.open = expanded;
  const label = document.createElement("summary"); label.textContent = "수집 오류 원문";
  const raw = document.createElement("p"); raw.textContent = errors.join(" · ");
  details.append(label, raw); target.append(summary, details);
  if (focused) label.focus({preventScroll:true});
}

function replaceResourceTable(id, next) {
  const target = byId(id), previous = target.children[0];
  const scroll = previous ? previous.scrollLeft || 0 : 0;
  const focused = previous && document.activeElement === previous;
  target.replaceChildren(next);
  next.scrollLeft = scroll;
  if (focused) next.focus({preventScroll:true});
}

function renderResources(resources) {
  const available = resources && resources.sampled_at;
  byId("resourceOverview").classList.toggle("hidden", !available);
  byId("resourceDetails").classList.toggle("hidden", !available);
  if (!available) return;
  resourceState.snapshot = resources;
  const cpu = resources.cpu || {}, memory = resources.memory || {};
  const root = (resources.filesystems || []).find((filesystem) => filesystem.mount === "/");
  const interfaces = resources.network || [];
  const physical = interfaces.filter((item) => /^(en|eth|wl|ib)/.test(item.name));
  const activePhysical = physical.filter((item) => item.state === "up").sort((a, b) => ((b.rx_bytes_per_second || 0) + (b.tx_bytes_per_second || 0)) - ((a.rx_bytes_per_second || 0) + (a.tx_bytes_per_second || 0)));
  const primaryInterface = activePhysical[0] || interfaces.find((item) => item.name !== "lo" && item.state === "up") || physical[0] || interfaces.find((item) => item.name !== "lo");
  const cards = [
    ["CPU", resources.cpu ? formatPercent(cpu.usage_percent) : "확인 불가", `논리 CPU ${cpu.logical_cpus || "미확인"}개`],
    ["메모리", Number.isFinite(memory.used_bytes) && memory.total_bytes > 0 ? formatPercent(memory.used_bytes / memory.total_bytes * 100) : "미확인", `${formatBytes(memory.used_bytes)} / ${formatBytes(memory.total_bytes)}`],
    ["시스템 디스크", root && root.total_bytes ? formatPercent(root.used_bytes / root.total_bytes * 100) : "미확인", root ? `${formatBytes(root.used_bytes)} / ${formatBytes(root.total_bytes)}` : "시스템 디스크 정보 없음"],
  ];
  if (primaryInterface) cards.push([`네트워크 · ${primaryInterface.name}`, `수신 ${formatRate(primaryInterface.rx_bytes_per_second)}`, `송신 ${formatRate(primaryInterface.tx_bytes_per_second)}`]);
  else cards.push(["네트워크", "미확인", "장치 정보를 확인할 수 없습니다."]);
  for (const id of ["resourceCards", "systemResourceCards"]) byId(id).replaceChildren(...cards.map(values => resourceCard(...values)));
  text("resourceSampleTime", `${fmtTime(resources.sampled_at)} 측정`);
  text("resourceSampleNote", resources.interval_seconds > 0 ? `${resources.interval_seconds.toFixed(1)}초 간격으로 측정한 사용량입니다.` : "사용량을 계산하기 위한 다음 측정을 기다리고 있습니다. 미확인 값은 0으로 표시하지 않습니다.");
  const errors = resources.errors || [];
  renderResourceWarnings(errors);
  renderResourceLists(resources);
  renderProcesses();
}

function renderResourceLists(resources) {
  const filesystems = resources.filesystems || [], disks = resources.disks || [], network = resources.network || [];
  text("filesystemHeading", `디스크 용량 · ${filesystems.length}개`);
  replaceResourceTable("filesystemList", resourceTable(`디스크 용량 · 전체 ${filesystems.length}개 중 ${Math.min(32, filesystems.length)}개 표시`, ["경로", "종류", "사용률", "사용 / 전체", "가용 용량", "남은 inode / 전체"], filesystems.slice(0, 32).map((item) => [
    item.mount || "경로 미확인", item.type || "미확인", item.total_bytes > 0 ? formatPercent(item.used_bytes / item.total_bytes * 100) : "미확인", `${formatBytes(item.used_bytes)} / ${formatBytes(item.total_bytes)}`, formatBytes(item.available_bytes), `${resourceCount(item.free_inodes)} / ${resourceCount(item.total_inodes)}`,
  ])));
  text("diskIOHeading", `디스크 I/O · ${disks.length}개 장치`);
  replaceResourceTable("diskIOList", resourceTable(`디스크 작업량 · 전체 ${disks.length}개 중 ${Math.min(32, disks.length)}개 표시`, ["장치", "읽기", "쓰기", "읽기 / 쓰기 횟수(초당)", "사용 시간 비율"], disks.slice(0, 32).map((item) => [
    item.name || "장치 미확인", formatRate(item.read_bytes_per_second), formatRate(item.write_bytes_per_second), `${Number.isFinite(item.read_iops) ? item.read_iops.toFixed(1) : "계산 중"} / ${Number.isFinite(item.write_iops) ? item.write_iops.toFixed(1) : "계산 중"}`, formatPercent(item.busy_percent),
  ])));
  text("networkHeading", `네트워크 · ${network.length}개 장치`);
  replaceResourceTable("networkList", resourceTable(`네트워크 사용량 · 전체 ${network.length}개 중 ${Math.min(64, network.length)}개 표시`, ["장치", "연결 상태", "수신", "송신", "누적 수신 / 송신", "오류 / 누락(수신·송신)"], network.slice(0, 64).map((item) => [
    item.name || "장치 미확인", resourceNetworkState(item.state), formatRate(item.rx_bytes_per_second), formatRate(item.tx_bytes_per_second), `${formatBytes(item.rx_bytes)} / ${formatBytes(item.tx_bytes)}`, `${resourceCount(item.rx_errors)}·${resourceCount(item.tx_errors)} / ${resourceCount(item.rx_dropped)}·${resourceCount(item.tx_dropped)}`,
  ])));
}

function renderProcesses() {
  const resources = resourceState.snapshot;
  if (!resources) return;
  const processes = resources.processes || [];
  const lastPage = Math.max(0, Math.ceil(processes.length / 10) - 1);
  resourceState.processPage = Math.min(resourceState.processPage, lastPage);
  const start = resourceState.processPage * 10;
  const rows = processes.slice(start, start + 10).map((process) => {
    const row = document.createElement("tr");
    for (const value of [process.exe || process.name || "미확인", serviceLabel(process.origin_service), `${process.pid} / ${process.uid === 0 ? "관리자" : credentialLabel(process.uid)}`, formatPercent(process.cpu_percent), formatBytes(process.rss_bytes)]) {
      const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
    }
    return row;
  });
  byId("processListBody").replaceChildren(...rows);
  const population = Number.isFinite(resources.process_count) ? `${resourceCount(resources.process_count)}개` : "수량 미확인";
  text("processHeading", `프로세스 · 전체 ${population}`);
  text("processListNote", `전체 ${population} 중 ${processes.length}개를 조회했습니다. CPU는 한 코어 기준으로 100%를 넘을 수 있습니다. 실행 인자·환경변수는 수집하지 않습니다.`);
  text("processPage", `${resourceState.processPage + 1} / ${lastPage + 1}페이지`);
  byId("processPrevious").disabled = resourceState.processPage === 0;
  byId("processNext").disabled = resourceState.processPage >= lastPage;
}

function initResources() {
  byId("processPrevious").addEventListener("click", () => { resourceState.processPage = Math.max(0, resourceState.processPage - 1); renderProcesses(); });
  byId("processNext").addEventListener("click", () => { resourceState.processPage++; renderProcesses(); });
}

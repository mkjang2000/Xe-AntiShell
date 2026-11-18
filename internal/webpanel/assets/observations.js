"use strict";

function observationRow(sample) {
  const file = sample.event_type === "file.write";
  const network = sample.event_type === "network.connect";
  const outcomes = file ? {written:"쓰기 바이트 수 확인", no_data:"쓴 바이트 없음", failed:"쓰기 실패", unknown:"쓰기 결과 미확인"} :
    network ? {initiated:"TCP 연결 요청 시작", failed:"TCP 연결 요청 실패", unknown:"연결 요청 결과 미확인"} : {};
  const reviews = {protected_write_candidate:"보호 경로 쓰기 후보", allowed_path:"허용 경로", outside_protected_path:"보호 경로 외부", unconfirmed_write:"실제 쓰기 미확인"};
  const review = Object.hasOwn(reviews, sample.review) ? reviews[sample.review] : sample.review ? "검토 분류 미확인" : "—";
  let target = file ? sample.path || "경로 미확인" : "대상 미확인";
  if (network) {
    target = sample.destination_address || "주소 미확인";
    if (sample.destination_port) target = (target.includes(":") ? "[" + target + "]" : target) + ":" + sample.destination_port;
  }
  const row = document.createElement("tr");
  const fields = [
    [fmtTime(sample.event_time), sample.event_id], [serviceLabel(sample.service)],
    [operatorLabel("event", sample.event_type), target],
    [Object.hasOwn(outcomes, sample.outcome) ? outcomes[sample.outcome] : "결과 미확인"],
    [Number.isSafeInteger(sample.return_value) ? String(sample.return_value) : "미확인"], [review],
  ];
  for (const values of fields) {
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

function initObservations() {
  const form = byId("observationFilters");
  const panel = byId("observationsPanel");
  let requested = false, latest = 0;
  async function load() {
    const request = ++latest;
    requested = true;
    const query = new URLSearchParams();
    for (const [parameter, id] of [["service", "observationService"], ["limit", "observationLimit"], ["protected_dir", "observationProtected"], ["allowed_dir", "observationAllowed"]]) {
      const value = byId(id).value.trim();
      if (value) query.set(parameter, value);
    }
    byId("observationRows").replaceChildren();
    byId("observationTable").hidden = true;
    if ((query.has("protected_dir") && !query.has("service")) || (query.has("allowed_dir") && !query.has("protected_dir"))) {
      text("observationStatus", "경로를 검토하려면 서비스와 보호 경로를 함께 입력하세요.");
      return;
    }
    text("observationStatus", "보존된 관측 표본을 조회하고 있습니다.");
    try {
      const response = await fetch("/api/observations?" + query, {headers:{Accept:"application/json"}});
      if (request !== latest) return;
      if (response.status === 401) {location.href = "/login"; return;}
      if (response.status === 400) {
        text("observationStatus", "조회 조건을 확인하세요. 경로에는 절대 경로를, 최대 표본 수에는 1~100 사이의 값을 입력하세요.");
        return;
      }
      if (!response.ok) throw new Error();
      const report = await response.json();
      if (request !== latest) return;
      if (!Array.isArray(report?.samples)) throw new Error();
      byId("observationRows").replaceChildren(...report.samples.map(observationRow));
      byId("observationTable").hidden = report.samples.length === 0;
      text("observationStatus", report.samples.length ? `최신 관측 표본 ${report.samples.length}건` : "조건에 맞는 보존 표본이 없습니다.");
    } catch {
      if (request === latest) text("observationStatus", "관측 표본을 불러오지 못했습니다. 에이전트 연결과 버전을 확인한 뒤 다시 조회하세요.");
    }
  }
  panel.addEventListener("toggle", () => { if (panel.open && !requested) load(); });
  form.addEventListener("submit", event => { event.preventDefault(); load(); });
}

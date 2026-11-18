"use strict";

function capacityAmount(raw, unit) {
  if (typeof raw !== "string" || !/^\d+(\.\d+)?$/.test(raw)) return "미측정";
  const value = Number(raw);
  if (!Number.isFinite(value) || value > Number.MAX_SAFE_INTEGER) return "미확인";
  if (unit === "bytes") return formatBytes(value);
  return raw + (unit || "");
}

function capacityDate(raw) {
  if (!raw) return "미측정";
  const time = new Date(raw);
  return Number.isNaN(time.getTime()) ? "미확인" : time.toLocaleString("ko-KR", {hour12:false});
}

function renderCapacityFields(id, rows) {
  const nodes = [];
  for (const [label, value] of rows) {
    const key = document.createElement("dt"), result = document.createElement("dd");
    key.textContent = label;
    result.textContent = value;
    nodes.push(key, result);
  }
  byId(id).replaceChildren(...nodes);
}

function renderCapacity(capability, enrolled) {
  const data = capability?.details;
  const available = !!data && typeof data === "object" && Object.keys(data).length > 0;
  byId("capacityData").hidden = !available;
  if (!available) {
    text("capacityStatus", "이 에이전트에서 저장·전송 측정값을 가져오지 못했습니다.");
    text("capacityDay", "");
    return;
  }
  const metric = (key, unit) => capacityAmount(data[key], unit);
  const time = key => capacityDate(data[key]);
  const hasDelivery = typeof data.pending_records === "string";
  text("capacityDay", data.utc_day ? data.utc_day + " UTC" : "집계일 미확인");
  const incomplete = capability.state === "limited" || capability.state === "error" ? "일부 측정값을 가져오지 못했습니다. " : "";
  text("capacityStatus", incomplete + "일일 저장량은 새로 보존한 이벤트의 크기입니다. 측정 시작 시각 · " + time("measurement_started_at"));
  const cards = [
    resourceCard("오늘 저장", metric("stored_bytes_today", "bytes"), metric("stored_events_today", "건")),
    resourceCard("어제 저장", metric("stored_bytes_yesterday", "bytes"), metric("stored_events_yesterday", "건")),
    resourceCard("DB 디스크 가용 공간", metric("disk_available_bytes", "bytes"), "DB 파일 " + metric("database_bytes", "bytes")),
  ];
  if (hasDelivery) cards.push(resourceCard("중앙 전송 대기", metric("pending_bytes", "bytes"), metric("pending_records", "건")));
  byId("capacityCards").replaceChildren(...cards);
  renderCapacityFields("capacityStorage", [
    ["DB 파일 크기", metric("database_bytes", "bytes")], ["WAL 파일 크기", metric("wal_bytes", "bytes")],
    ["가장 오래된 보존 이벤트", time("oldest_event_at")],
    ["보존 기간이 지난 이벤트", metric("retention_backlog_events", "건") + (data.retention_backlog_truncated === "true" ? " 이상" : "")],
  ]);
  renderCapacityFields("capacityIngest", [
    ["수집 대기 / 한도", metric("queue_depth", "건") + " / " + metric("queue_capacity", "건")],
    ["시작 후 최대 대기", metric("queue_high_water", "건")],
    ["최근 저장 지연", metric("last_store_latency_ms", " ms")], ["최대 저장 지연", metric("max_store_latency_ms", " ms")],
    ["인코딩 실패", metric("drop_encode", "건")], ["크기 초과", metric("drop_oversize", "건")],
    ["대기 시간 초과", metric("drop_queue_timeout", "건")], ["유효성 검사 실패", metric("drop_invalid", "건")],
    ["저장 실패", metric("drop_storage", "건")], ["종료 중 손실", metric("drop_shutdown", "건")],
  ]);
  text("capacityManagedState", hasDelivery ? "" : enrolled === false ? "이 호스트는 중앙에 등록되지 않았습니다." : "중앙 전송 측정값을 가져오지 못했습니다.");
  renderCapacityFields("capacityDelivery", hasDelivery ? [
    ["중앙 전송 대기", metric("pending_records", "건")], ["대기 바이트 / 한도", metric("pending_bytes", "bytes") + " / " + metric("spool_limit_bytes", "bytes")],
    ["마지막 ACK 시퀀스", metric("acknowledged")], ["누적 전송 손실", metric("lost_records", "건")],
    ["최근 단절", time("disconnect_at")], ["단절 후 첫 ACK", time("first_recovery_ack_at")],
    ["첫 ACK까지", metric("ack_recovery_seconds", "초")], ["대기열 소진", time("drained_at")],
    ["대기열 소진까지", metric("drain_recovery_seconds", "초")], ["단절 구간 손실", metric("outage_lost_records", "건")],
  ] : []);
}

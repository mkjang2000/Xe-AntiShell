package webpanel

import "testing"

func TestCapacityStatusUsesActualMeasurementAndKeepsQueueOutagesDistinct(t *testing.T) {
	runBrowserBehavior(t, `
context.data={utc_day:"2026-01-02",measurement_started_at:"2026-01-02T01:02:00Z",stored_events_today:"0",stored_bytes_today:"0",database_bytes:"16384",queue_depth:"1",queue_capacity:"8",queue_high_water:"4",retention_backlog_events:"5000",retention_backlog_truncated:"true",drop_encode:"0"};
context.snapshot={status:{health:"healthy",capability_report:{capabilities:{"storage.capacity":{details:context.data}}}},capabilities:{platform:{},capabilities:{}},events:[],findings:[],managed:{enrolled:false}};
vm.runInContext("state.data=snapshot;render()",context);
assert.equal(get("capacityData").hidden,false);
assert.match(flatten(get("capacityCards")),/오늘 저장.*0 B.*0건.*어제 저장.*미측정/);
assert.match(flatten(get("capacityStorage")),/16.0 KiB.*5000건 이상/);
assert.match(flatten(get("capacityIngest")),/1건 \/ 8건.*4건.*인코딩 실패.*0건/);
assert.match(get("capacityManagedState").textContent,/중앙에 등록되지 않았습니다/);
Object.assign(context.data,{pending_records:"2",pending_bytes:"1024",spool_limit_bytes:"4096",acknowledged:"7",lost_records:"0",disconnect_at:"2026-01-02T03:00:00Z",first_recovery_ack_at:"2026-01-02T03:00:02Z",ack_recovery_seconds:"2.025",outage_lost_records:"0"});
context.snapshot.managed.enrolled=true;
vm.runInContext("render()",context);
assert.match(flatten(get("capacityDelivery")),/중앙 전송 대기.*2건.*1.0 KiB \/ 4.0 KiB/);
assert.match(flatten(get("capacityDelivery")),/첫 ACK까지.*2.025초.*대기열 소진.*미측정.*단절 구간 손실.*0건/);
context.data.drain_recovery_seconds="4";context.data.drained_at="2026-01-02T03:00:04Z";context.data.pending_records="0";context.data.pending_bytes="0";
vm.runInContext("render()",context);
assert.match(flatten(get("capacityDelivery")),/중앙 전송 대기.*0건.*대기열 소진까지.*4초/);
delete context.snapshot.status.capability_report;
vm.runInContext("render()",context);
assert.equal(get("capacityData").hidden,true);
assert.match(get("capacityStatus").textContent,/측정값을 가져오지 못/);
`)
}

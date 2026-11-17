package webpanel

import "testing"

func TestOperatorRecordsExplainFindingsWithoutPromotingRawDiagnostics(t *testing.T) {
	runBrowserBehavior(t, operatorRecordsBehaviorTest)
}

func TestOperatorResourcesUseCompactAccessibleTablesAndHonestUnknowns(t *testing.T) {
	runBrowserBehavior(t, operatorResourcesBehaviorTest)
}

const operatorRecordsBehaviorTest = `
(async () => {
  context.finding = {
    finding_id:"finding-operator",rule_id:"web-descendant-root-shell",rule_version:"1",state:"open",
    severity:"critical",confidence:.95,risk_score:95,response_decision:"observe",policy_revision:4,
    created_at:"2026-11-16T06:00:00Z",origin_service:"nginx.service",process_key:"opaque-process",
    summary:"root shell descended <script>alert(1)</script>",evidence_event_ids:["evidence-operator"],
  };
  const finding = vm.runInContext("findingCard(finding)", context);
  const basic = finding.children.filter(child => child.tagName !== "DETAILS").map(flatten).join(" ");
  assert.match(basic,/웹 서비스에서 관리자 권한 셸 실행/);
  assert.match(basic,/정상 배포 작업인지 확인/);
  assert.match(basic,/매우 높음/);
  assert.match(basic,/탐지/);
  assert.doesNotMatch(basic,/web-descendant|critical|observe|root shell descended|95%|opaque-process/);
  const details = finding.children.find(child => child.tagName === "DETAILS");
  assert.equal(details.open,false);
  assert.match(flatten(details),/root shell descended <script>alert\(1\)<\/script>/);
  assert.match(flatten(details),/원본 값 0.95/);
  assert.match(flatten(details),/확률이 아닙니다/);

  context.finding.rule_id="future-rule"; context.finding.response_decision="future-action";
  context.finding.severity="future-severity";
  const unknown=vm.runInContext("findingCard(finding)",context);
  const unknownBasic=unknown.children.filter(child=>child.tagName!=="DETAILS").map(flatten).join(" ");
  assert.match(unknownBasic,/의심 행위 탐지|추가 확인이 필요한 실행/);
  assert.doesNotMatch(unknownBasic,/future-rule|future-action|future-severity|악성 확정/);

  context.execution={event_id:"event-operator",event_type:"process.exec",event_time:"2026-11-16T06:00:00Z",completeness:"partial",source:"tetragon",process:{pid:42,ppid:1,uid:0,euid:0,exe:"/bin/sh",origin_service:"nginx.service",lineage_confidence:"verified"}};
  const event=vm.runInContext("eventCard(execution)",context);
  const eventBasic=event.children.filter(child=>child.tagName!=="DETAILS").map(flatten).join(" ");
  assert.match(eventBasic,/\/bin\/sh/); assert.match(eventBasic,/PID 42/); assert.match(eventBasic,/관리자 권한/);
  assert.doesNotMatch(eventBasic,/process\.exec|partial|tetragon|verified/);
  assert.match(flatten(event.children.find(child=>child.tagName==="DETAILS")),/process\.exec/);

  const paths=[];
  context.fetch=async path=>{paths.push(new URL(path,"http://panel"));return response({items:[],has_more:false,total:0});};
  const view=vm.runInContext("new HistoryView('findings')",context);
  await view.load();
  assert.equal(paths.at(-1).searchParams.get("exclude_self_tests"),"1","operational finding history excludes known self-tests by default");
  view.cursor="previous-page";view.previousCursors=[""];
  get("includeSelfTests").checked=true;get("includeSelfTests").emit("change");await tick();
  assert.equal(paths.at(-1).searchParams.has("exclude_self_tests"),false);
  assert.equal(paths.at(-1).searchParams.has("cursor"),false,"changing test visibility resets the scoped cursor");
  assert.equal(view.previousCursors.length,0);
  context.fetch=async()=>response({items:[context.finding],has_more:false,total:1});
  await view.load();
  context.fetch=async()=>{throw new Error("Failed to fetch");};
  await view.load();
  assert.match(get("findingsStatus").textContent,/이전 결과를 표시/);
  assert.doesNotMatch(get("findingsStatus").textContent,/Failed to fetch/);
  assert.equal(view.lastError,"Failed to fetch","browser transport diagnostics remain available without becoming operator text");
  assert.equal(get("findingsGroups").children.length,1,"a failed refresh must not erase the last successful result");
  context.fetch=async()=>response({items:[],has_more:false,total:0});
  await view.load();assert.equal(view.lastError,"");
})().catch(error=>{console.error(error);process.exitCode=1;});
`

const operatorResourcesBehaviorTest = `
context.resources={
  sampled_at:"2026-11-16T06:00:00Z",interval_seconds:0,cpu:{usage_percent:null,logical_cpus:4},
  memory:{total_bytes:4096,used_bytes:2048},process_count:23,
  filesystems:[{mount:"/",type:"xfs",total_bytes:1000,used_bytes:250,available_bytes:750,total_inodes:10,free_inodes:8}],
  disks:[{name:"vda",read_bytes_per_second:null,write_bytes_per_second:null,read_iops:null,write_iops:null,busy_percent:null}],
  network:[{name:"eno2",state:"down",rx_bytes_per_second:0,tx_bytes_per_second:0},{name:"eth0",state:"up",rx_bytes_per_second:1024,tx_bytes_per_second:2048,rx_errors:0,tx_errors:0,rx_dropped:0,tx_dropped:0}],
  processes:Array.from({length:23},(_,index)=>({pid:index+1,uid:0,exe:"/process/"+index,cpu_percent:null,rss_bytes:1024,origin_service:"nginx.service"})),
  errors:["CPU counters unavailable","<img src=x onerror=alert(1)>"],
};
vm.runInContext("renderResources(resources)",context);
const overview=flatten(get("resourceCards"));
assert.equal(get("systemResourceCards").children.length,4);
assert.equal(flatten(get("systemResourceCards")),overview);
assert.notEqual(get("resourceCards").children[0],get("systemResourceCards").children[0],"both views need independent DOM nodes from the same metrics");
assert.match(overview,/계산 중/);assert.match(overview,/50.0%/);assert.match(overview,/25.0%/);
assert.match(overview,/네트워크 · eth0/);assert.match(overview,/수신/);assert.match(overview,/송신/);
assert.doesNotMatch(overview,/네트워크 · eno2|RX|TX|Load/);
assert.equal(vm.runInContext("resourceNetworkState('constructor')",context),"상태 미확인");
assert.equal(vm.runInContext("resourceWarningLabel('toString')",context),"일부 자원 정보를 확인하지 못했습니다.");
for(const id of ["filesystemList","diskIOList","networkList"]){
  const region=get(id).children[0];
  assert.equal(region.attributes.role,"region");assert.equal(region.attributes.tabindex,"0");
  const table=region.children[0];assert.equal(table.tagName,"TABLE");
  assert.equal(table.children[0].tagName,"CAPTION");
  assert.ok(table.children[1].children[0].children.every(cell=>cell.attributes.scope==="col"));
  assert.ok(table.children[2].children.every(row=>row.children[0].attributes.scope==="row"));
}
assert.match(flatten(get("networkList")),/연결됨/);assert.match(flatten(get("networkList")),/연결 안 됨/);
assert.match(flatten(get("filesystemList")),/xfs/);assert.match(flatten(get("filesystemList")),/8 \/ 10/);
const warning=get("resourceWarnings");
assert.match(warning.children[0].textContent,/CPU 사용량을 확인할 수 없습니다/);
assert.doesNotMatch(warning.children[0].textContent,/counters|<img/);
const technical=warning.children.find(child=>child.tagName==="DETAILS");
assert.equal(technical.open,false);assert.match(flatten(technical),/<img src=x onerror=alert\(1\)>/);
technical.open=true;
const oldRegion=get("networkList").children[0];oldRegion.scrollLeft=120;
context.document.activeElement=oldRegion;
vm.runInContext("renderResources(resources)",context);
assert.equal(get("networkList").children[0].scrollLeft,120);
assert.equal(get("networkList").children[0].focused,true);
assert.equal(get("resourceWarnings").children.find(child=>child.tagName==="DETAILS").open,true);
assert.equal(get("processListBody").children.length,10);
get("processNext").emit("click");assert.equal(get("processListBody").children.length,10);
get("processNext").emit("click");assert.equal(get("processListBody").children.length,3);

context.resources.network=Array.from({length:80},(_,i)=>({name:"veth"+i,state:"unknown"}));
context.resources.cpu=null;context.resources.process_count=undefined;context.resources.processes=[];
vm.runInContext("renderResources(resources)",context);
const network=get("networkList").children[0].children[0];
assert.match(network.children[0].textContent,/전체 80개 중 64개 표시/);
assert.equal(network.children[2].children.length,64);
assert.match(flatten(network),/미확인/);
assert.match(flatten(get("resourceCards")),/확인 불가/);
assert.match(get("processHeading").textContent,/수량 미확인/);
`

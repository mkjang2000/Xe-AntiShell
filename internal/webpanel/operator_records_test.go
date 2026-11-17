package webpanel

import "testing"

func TestOperatorRecordsExplainFindingsWithoutPromotingRawDiagnostics(t *testing.T) {
	runBrowserBehavior(t, operatorRecordsBehaviorTest)
}

func TestOperatorResourcesUseCompactAccessibleTablesAndHonestUnknowns(t *testing.T) {
	runBrowserBehavior(t, operatorResourcesBehaviorTest)
}

func TestExtendedFindingsExplainObservedFactorsAndDetectionOnlyResponse(t *testing.T) {
	runBrowserBehavior(t, extendedFindingBehaviorTest)
}

func TestOperationRecordsExplainProofAndReturnValuesWithoutClaimingCompletion(t *testing.T) {
	runBrowserBehavior(t, operationRecordsBehaviorTest)
}

const operationRecordsBehaviorTest = `
const operation={event_id:"operation-1",event_time:"2026-11-17T06:00:00Z",process:{exe:"/usr/bin/python3",pid:42,euid:1000}};
const observation=value=>{context.operation={...operation,...value};return vm.runInContext("eventObservation(operation)",context)};
const field=(value,name)=>value.fields.find(entry=>entry[0]===name)?.[1];
for(const evidence of ["exact_argv","tetragon_policy"]){
 const value=observation({event_type:"process.exec_observation",execution:{runtime:"python",mode:"inline",evidence,option:"-c",code:"SECRET_SOURCE",arguments:["SECRET_ARG"]}});
 assert.match(value.summary,/코드 내용과 실행 성공 여부는 확인하지 않습니다/);
 assert.equal(field(value,"인터프리터"),"Python");assert.equal(field(value,"확인한 옵션"),"-c");
 assert.match(field(value,"관측 근거"),evidence==="exact_argv"?/분리된 실행 인자/:/전용 수집 정책/);
 assert.doesNotMatch(JSON.stringify(value),/SECRET_SOURCE|SECRET_ARG/);
 const card=vm.runInContext("eventCard(operation)",context);
 assert.match(flatten(card),/실행 옵션 관측/);assert.doesNotMatch(flatten(card),/SECRET_SOURCE|SECRET_ARG/);
}
for(const [location,label] of [["temporary","임시 경로"],["memory","메모리 파일 경로"],["fd","파일 디스크립터 경로"]]){
 const value=observation({event_type:"process.exec",execution:{runtime:"php",mode:"script",evidence:"exact_argv",script_location:location}});
 assert.equal(field(value,"스크립트 경로 종류"),label);assert.equal(field(value,"확인한 옵션"),"위치 인자 (옵션 없음)");
 assert.match(value.summary,/실행 성공 여부는 확인하지 않습니다/);
}
for(const [outcome,result,label] of [["written",12,"쓰기 바이트 수 보고"],["no_data",0,"쓴 데이터 없음"],["failed",-13,"실패"],["unknown",null,"결과 미확인"]]){
 const value=observation({event_type:"file.write",file:{path:"/tmp/<img>",outcome,return_value:result,function:"vfs_write",policy_name:"xeas-file-write-v1"}});
 assert.equal(field(value,"쓰기 결과"),label);assert.equal(field(value,"원래 반환값"),result===null?"미수집":String(result));
 assert.equal(field(value,"파일 경로"),"/tmp/<img>");assert.match(field(value,"반환값 의미"),/바이트 수.*커널 오류.*디스크 반영/);
 assert.match(flatten(vm.runInContext("eventCard(operation)",context)),/파일 쓰기 관측/);
}
for(const [outcome,result] of [["initiated",0],["failed",-111],["unknown",undefined]]){
 const value=observation({event_type:"network.connect",network:{operation:"connect",protocol:"tcp",family:"ipv6",destination_address:"::1",destination_port:443,outcome,return_value:result,function:"tcp_v6_connect"}});
 assert.equal(field(value,"원래 반환값"),result===undefined?"미수집":String(result));assert.equal(field(value,"대상 주소"),"::1");assert.equal(field(value,"대상 포트"),443);assert.equal(field(value,"주소 종류"),"IPv6");
 assert.match(value.summary,/연결 완료/);assert.doesNotMatch(value.summary,/연결 완료했습니다|통신 성공|ESTABLISHED/);
 assert.match(flatten(vm.runInContext("eventCard(operation)",context)),/TCP 연결 요청 관측/);
}
const malformed=observation({event_type:"network.connect",network:{outcome:"constructor",protocol:"__proto__",destination_port:0,return_value:"0"}});
assert.match(malformed.summary,/확인할 수 없습니다/);assert.equal(field(malformed,"원래 반환값"),"정확한 값 미확인");assert.equal(field(malformed,"대상 포트"),"미확인");
assert.equal(observation({event_type:"process.exit",file:{path:"SHOULD_NOT_BE_PROMOTED"}}).fields.length,0);
context.temporaryFinding={rule_id:"web-descendant-temporary-script"};
assert.match(vm.runInContext("findingTitle(temporaryFinding)",context),/스크립트 실행 요청/);
context.temporaryFactor={id:"temporary_script"};assert.match(vm.runInContext("findingRiskFactorText(temporaryFactor)",context),/실행 성공 여부는 확인되지 않았습니다/);
`

const extendedFindingBehaviorTest = `
const titles = [
 ["web-descendant-download-tool","웹 서비스에서 다운로드 도구 실행"],
 ["web-descendant-recon-tool","웹 서비스에서 정보 확인 도구 실행"],
 ["web-descendant-connection-tool","웹 서비스에서 연결 도구 실행"],
 ["web-descendant-inline-interpreter","웹 서비스에서 직접 코드 실행 요청"],
 ["web-descendant-temporary-executable","웹 서비스에서 임시 경로의 실행 파일 실행"],
 ["web-descendant-temporary-script","웹 서비스에서 임시 경로의 스크립트 실행 요청"],
];
context.extended={
 finding_id:"extended-observation",state:"open",severity:"high",confidence:.75,risk_score:100,
 created_at:"2026-11-17T06:00:00Z",origin_service:"nginx.service",summary:"<script>alert(1)</script>",
 response_decision:"sigterm_sent",detection_only:true,evidence_event_ids:["extended-evidence"],
 risk_factors:[{id:"web_origin",score:25},{id:"shell_execution",score:60},{id:"root_identity",score:10},{id:"temporary_working_directory",score:5}],
};
for(const [rule,title] of titles){
 context.extended.rule_id=rule;
 const card=vm.runInContext("findingCard(extended)",context);
 const basic=card.children.filter(child=>child.tagName!=="DETAILS").map(flatten).join(" ");
 assert.match(basic,new RegExp(title));
 assert.match(basic,/확장 탐지 전용/);
 assert.doesNotMatch(basic,/종료 신호 전송|sigterm_sent|web-descendant|<script>|100%|악성 확정/);
 const details=card.children.find(child=>child.tagName==="DETAILS");
 assert.equal(details.open,false);
 const detailText=flatten(details);
 assert.match(detailText,/규칙 기여 점수 합계\s*100\/100/);
 assert.match(detailText,/기여 점수의 합계\(최대 100점\)/);
 assert.match(detailText,/악성 확률이나 실제 공격 확정을 뜻하지 않습니다/);
 assert.match(detailText,/자동 종료 대상에 포함되지 않습니다/);
 assert.match(detailText,/\+25점.*웹 서비스와 연결된 실행 경로/);
 assert.match(detailText,/\+60점.*셸 프로그램 실행/);
 assert.match(detailText,/\+10점.*관리자 권한/);
 assert.match(detailText,/\+5점.*작업 경로가 임시 경로/);
 assert.doesNotMatch(detailText,/web_origin|shell_execution|root_identity|temporary_working_directory/);
 assert.match(detailText,/<script>alert\(1\)<\/script>/,"raw evidence remains plain text in collapsed details");
}
for(const [id,explanation] of [
 ["download_tool",/다운로드 성공 여부는 확인되지 않았습니다/],
 ["recon_tool",/시스템·계정·네트워크 정보 확인용 도구/],
 ["connection_tool",/실제 연결 여부는 확인되지 않았습니다/],
 ["inline_interpreter",/코드 내용은 분석하지 않았습니다/],
 ["temporary_executable",/임시 또는 메모리 파일 경로/],
 ["temporary_script",/실행 성공 여부는 확인되지 않았습니다/],
]){
 context.factor={id,score:20};
 assert.match(vm.runInContext("findingRiskFactorText(factor)",context),explanation);
}
for(const id of ["future-factor","constructor","__proto__","<img src=x onerror=alert(1)>"]){
 context.extended.risk_factors=[{id,score:12,reason:"<script>untrusted reason</script>"}];
 const card=vm.runInContext("findingCard(extended)",context);
 const detailText=flatten(card.children.find(child=>child.tagName==="DETAILS"));
 assert.match(detailText,/\+12점.*추가 관찰 근거/);
 assert.doesNotMatch(detailText,/future-factor|constructor|__proto__|<img|untrusted reason/);
}
context.extended.risk_factors=Array.from({length:12},(_,i)=>({id:"root_identity",score:i+1}));
const bounded=vm.runInContext("recordsRiskFields(extended)",context);
assert.equal(bounded.length,9,"render at most eight factors plus the score explanation");
assert.match(bounded[8][1],/^\+8점/);
context.extended.risk_factors=[null,{id:"download_tool",score:-2},{id:"connection_tool",score:"<img>"}];
const malformed=vm.runInContext("recordsRiskFields(extended)",context);
assert.match(malformed[1][1],/점수 미확인.*추가 관찰 근거/);
assert.match(malformed[2][1],/^점수 미확인/);assert.doesNotMatch(malformed[3][1],/<img>/);
for(const factors of [undefined,null,[]]){
 context.extended.risk_factors=factors;
 const legacy=vm.runInContext("recordsRiskFields(extended)",context);
 assert.equal(legacy.length,1);assert.equal(legacy[0][0],"규칙 점수");
 assert.match(legacy[0][1],/규칙 등급을 점수로 표시한 값이며 악성 확률이 아닙니다/);
}
assert.equal(vm.runInContext("operatorLabel('response','detection_only')",context),"확장 탐지 전용");
context.extended.detection_only=false;context.extended.response_decision="detection_only";
const decisionOnly=vm.runInContext("findingCard(extended)",context);
assert.match(outsideDetails(decisionOnly),/확장 탐지 전용/);
`

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

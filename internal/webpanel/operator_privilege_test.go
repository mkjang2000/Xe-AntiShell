package webpanel

import "testing"

func TestPrivilegeRulesRemainDetectOnlyWithoutChangingLegacyResponse(t *testing.T) {
	runBrowserBehavior(t, `
context.summary={detection_enabled:true,privilege_rules:true,root_exec_alerts:"all",response_mode:"enforce",response_action:"terminate",recent_findings:[]};
const effective=vm.runInContext("effectiveResponse(summary)",context);
assert.equal(effective.label,"조건부 자동 종료","privilege-only must preserve legacy web response");
assert.match(effective.note,/모든 root 실행 경보/);
assert.match(effective.note,/권한 변경 규칙은 탐지 전용/);
assert.match(effective.note,/기존 웹 규칙의 대응 설정과 구분/);
context.summary.root_exec_alerts="suspicious";
assert.match(vm.runInContext("effectiveResponse(summary).note",context),/의심 문맥의 root 실행 경보/);
context.summary.extended_process_rules=true;
assert.equal(vm.runInContext("effectiveResponse(summary).label",context),"확장 탐지 전용");
context.summary.detection_enabled=false;
assert.equal(vm.runInContext("effectiveResponse(summary).label",context),"탐지 중지");
assert.doesNotMatch(vm.runInContext("effectiveResponse(summary).note",context),/전역 root/);
context.finding={finding_id:"privilege-test",rule_id:"privilege-host-root-gain",severity:"high",confidence:.95,risk_score:75,detection_only:true,response_decision:"sigterm_sent",risk_factors:[{id:"initial_namespace_root_gain",score:75}],evidence_event_ids:[]};
for(const id of ["privilege-root-execution","privilege-root-restored","privilege-host-root-gain","privilege-root-identity-change","privilege-capability-gain","privilege-capability-activated"]){
 context.finding.rule_id=id;
 const card=vm.runInContext("findingCard(finding)",context);
 assert.match(outsideDetails(card),/권한 탐지 전용/);
 assert.doesNotMatch(outsideDetails(card),/종료 신호 전송|악성 확정/);
 assert.match(flatten(card),/자동 종료 대상에 포함되지 않습니다/);
 assert.match(flatten(card),/악성 확률이나 인증·인가 확인을 뜻하지 않습니다/);
}
context.finding.rule_id="privilege-root-restored";
assert.match(vm.runInContext("findingRuleText(finding).description",context),/인증·인가가 확인됐다는 뜻은 아닙니다/);
context.finding.rule_id="privilege-root-identity-change";
assert.match(vm.runInContext("findingRuleText(finding).description",context),/호스트 권한 탈취로 단정하지 않습니다/);
context.finding.rule_id="privilege-root-execution";
vm.runInContext("renderRecentFindings([finding])",context);
assert.match(flatten(get("recentFindings")),/권한 탐지 전용/);
assert.doesNotMatch(flatten(get("recentFindings")),/종료 신호 전송/);
context.finding.rule_id="web-descendant-download-tool";
assert.equal(vm.runInContext("findingResponseLabel(finding)",context),"확장 탐지 전용");
for(const key of ["constructor","__proto__","future-privilege"]){context.key=key;assert.equal(vm.runInContext("isPrivilegeRule(key)",context),false);}
context.factor={id:"nonroot_parent_snapshot"};
assert.match(vm.runInContext("findingRiskFactorText(factor)",context),/부모의 현재 권한이나 공격 성공을 증명하지 않습니다/);
`)
}

func TestCredentialUIRequiresPairedProofAndDistinguishesCapabilityActivation(t *testing.T) {
	runBrowserBehavior(t, `
const snapshot=(euid,caps={effective:[],permitted:[],inheritable:[]},namespace={inum:4026531837,is_host:true,level:0})=>({uid:1000,euid,gid:1000,egid:1000,suid:1000,sgid:1000,fsuid:1000,fsgid:1000,capabilities:caps,user_namespace:namespace});
context.event={event_id:"credential-evidence",event_type:"process.credential_change",source:"tetragon",boot_id:"boot",event_time:"2026-11-18T01:00:01Z",process:{pid:42,tid:43,exec_id:"exec",start_time:"2026-11-18T01:00:00Z",uid:1000,euid:1000,exe:"/usr/bin/sudo"},credential:{tgid:42,tid:43,task_start_time_ns:"1000000",evidence:"tetragon_commit_creds_pair",policy_name:"xeas-credential-change-v1",function:"commit_creds",return_value:0,outcome:"applied",before:snapshot(1000,{effective:[],permitted:["CAP_DAC_OVERRIDE"],inheritable:[]}),after:snapshot(0,{effective:["CAP_DAC_OVERRIDE","CAP_SYS_ADMIN"],permitted:["CAP_DAC_OVERRIDE","CAP_SYS_ADMIN"],inheritable:[]})}};
const observed=vm.runInContext("eventObservation(event)",context);
assert.match(observed.summary,/같은 커널 호출/);
assert.equal(new Map(observed.fields).get("이후 실행 권한 EUID"),"0","zero ID must remain visible");
assert.equal(new Map(observed.fields).get("새 권한집합 증가"),"CAP_SYS_ADMIN");
assert.equal(new Map(observed.fields).get("기존 permitted 권한 활성화"),"CAP_DAC_OVERRIDE");
assert.match(new Map(observed.fields).get("이후 user namespace"),/초기 user namespace/);
assert.match(new Map(observed.fields).get("namespace 해석"),/탈출했다는 증거는 아닙니다/);
const card=vm.runInContext("eventCard(event)",context);
assert.match(outsideDetails(card),/권한 변경 관측/);
assert.match(flatten(card),/실행 스냅샷 EUID/);
assert.doesNotMatch(outsideDetails(card),/관리자 권한\(EUID 0\)/,"cached process EUID is not the credential outcome");
const complete=JSON.parse(JSON.stringify(context.event));
for(const alter of [
 event=>{delete event.credential.before;},
 event=>{delete event.credential.before.capabilities.permitted;},
 event=>{event.missing_fields=["credential.before.euid"];},
 event=>{event.redacted_fields=["credential.before.capabilities"];},
 event=>{event.credential.tid=99;},
 event=>{event.credential.evidence="guessed_before";},
 event=>{event.credential.return_value=null;event.credential.outcome="unknown";},
 event=>{event.credential.before.user_namespace.level=1;},
 event=>{delete event.process.exec_id;},
 event=>{event.process.start_time="0001-01-01T00:00:00Z";},
 event=>{event.event_time="0001-01-01T00:00:00Z";},
 event=>{event.credential.task_start_time_ns=1000000;},
 event=>{event.credential.task_start_time_ns="18446744073709551616";},
 event=>{event.credential.task_start_time_ns="0100000";},
 event=>{event.credential.task_start_time_ns="0";},
]){
 context.event=JSON.parse(JSON.stringify(complete));alter(context.event);
 const partial=vm.runInContext("eventObservation(event)",context),fields=new Map(partial.fields);
 assert.match(partial.summary,/정확한 이전→이후 변경으로 단정하지 않습니다/);
 assert.equal(fields.has("새 권한집합 증가"),false,"missing proof must not imply new authority");
 assert.match(fields.get("Capability 변화 판정"),/추정하지 않습니다/);
}
context.event=JSON.parse(JSON.stringify(complete));context.event.credential.task_start_time_ns="18446744073709551615";
const maximum=new Map(vm.runInContext("eventObservation(event).fields",context));
assert.equal(maximum.get("태스크 시작값(ns)"),"18446744073709551615","uint64 must remain exact decimal text");
assert.equal(maximum.get("적용 결과"),"변경 적용 근거 확인");
context.event=JSON.parse(JSON.stringify(complete));context.event.credential.return_value=-1;context.event.credential.outcome="failed";
assert.match(vm.runInContext("eventObservation(event).summary",context),/실패로 보고/);
for(const namespace of [{inum:4026532444,is_host:false,level:1},{inum:4026532444}]){
 context.event=JSON.parse(JSON.stringify(complete));context.event.credential.after.user_namespace=namespace;
 const fields=new Map(vm.runInContext("eventObservation(event).fields",context));
 assert.equal(fields.get("적용 결과"),"변경 적용 근거 확인","namespace scope can be unknown despite complete paired values");
 assert.match(fields.get("이후 user namespace"),namespace.is_host===false?/비호스트 user namespace/:/미확인/);
}
context.event=JSON.parse(JSON.stringify(complete));
delete context.event.credential.before.user_namespace.is_host;delete context.event.credential.after.user_namespace.is_host;
context.event.missing_fields=["credential.user_namespace_scope"];
const advisory=JSON.parse(JSON.stringify(context.event));
const scoped=new Map(vm.runInContext("eventObservation(event).fields",context));
assert.equal(scoped.get("적용 결과"),"변경 적용 근거 확인","scope advisory must not erase a complete pair");
assert.equal(scoped.get("새 권한집합 증가"),"CAP_SYS_ADMIN");assert.equal(scoped.get("이후 user namespace"),"미확인");
for(const field of ["redacted_fields","truncated_fields"]){
 context.event=JSON.parse(JSON.stringify(advisory));context.event[field]=["credential.user_namespace_scope"];
 assert.equal(new Map(vm.runInContext("eventObservation(event).fields",context)).get("적용 결과"),"적용 근거 미확인","only the exact missing-scope advisory is exempt");
}
context.event=JSON.parse(JSON.stringify(complete));context.event.missing_fields=["credential.user_namespace_scope"];
assert.equal(new Map(vm.runInContext("eventObservation(event).fields",context)).get("적용 결과"),"적용 근거 미확인","contradictory known-host data must fail closed");
context.event=JSON.parse(JSON.stringify(complete));context.event.credential.before.capabilities.effective=[];context.event.credential.before.capabilities.permitted=[];
assert.equal(new Map(vm.runInContext("eventObservation(event).fields",context)).get("이전 effective Capability"),"없음 (확인됨)");
context.event.credential.after.code="DO_NOT_PROMOTE_CODE";context.event.credential.after.env={TOKEN:"DO_NOT_PROMOTE_SECRET"};context.event.credential.function="<img src=x onerror=alert(1)>";
assert.doesNotMatch(flatten(vm.runInContext("eventCard(event)",context)),/DO_NOT_PROMOTE_CODE|DO_NOT_PROMOTE_SECRET|<img/);
`)
}

func TestPrivilegeCapabilitiesSeparateEngineSupportFromSensorEvidence(t *testing.T) {
	runBrowserBehavior(t, `
context.feature={state:"supported",implementation:"implemented",runtime_state:"available"};
let feature=vm.runInContext("capabilityPresentation('detection.privilege_rules',feature)",context);
assert.equal(feature.label,"규칙 제공");assert.equal(feature.active,false);
assert.match(feature.description,/실제 동작을 의미하지 않습니다/);
context.feature.runtime_state="active";
feature=vm.runInContext("capabilityPresentation('detection.privilege_rules',feature)",context);
assert.equal(feature.label,"규칙 적용");assert.equal(feature.active,false,"engine must not count as a collection source");
assert.match(feature.description,/실제 권한 변경 센서의 수신 여부/);
context.feature.state="unsupported";
feature=vm.runInContext("capabilityPresentation('detection.privilege_rules',feature)",context);
assert.equal(feature.label,"프로필 사용 불가");assert.equal(feature.active,false);
context.feature.state="supported";context.feature.runtime_state="unverified";
feature=vm.runInContext("capabilityPresentation('observation.credential_change',feature)",context);
assert.equal(feature.active,false);assert.match(feature.description,/전용 정책/);
context.feature.runtime_state="active";
feature=vm.runInContext("capabilityPresentation('observation.credential_change',feature)",context);
assert.equal(feature.active,true);assert.match(feature.description,/성공 반환을 수신/);
assert.match(feature.description,/악성이라는 뜻은 아닙니다/);
context.features={"detection.privilege_rules":{state:"supported",implementation:"implemented",runtime_state:"active"},"observation.credential_change":{state:"supported",implementation:"implemented",runtime_state:"active"}};
vm.runInContext("renderCapabilities(features)",context);
assert.equal(get("capabilitySummary").textContent,"정상 수집 1개");
context.event={event_type:"process.exec",process:{credentials:{suid:0,user_namespace:{inum:4026531837},capabilities:{effective:[]}},exec_privileges:{setuid:0,reasons:["PRIVILEGES_RAISED_EXEC_FILE_CAP"]}}};
const fields=new Map(vm.runInContext("eventObservation(event).fields",context));
assert.equal(fields.get("실행 스냅샷 saved UID"),"0");
assert.equal(fields.get("실행 파일 SUID 메타데이터"),"0");
assert.match(fields.get("실행 권한 메타데이터"),/파일 Capability/);
assert.equal(fields.get("실행 스냅샷 user namespace"),"미확인");
assert.match(fields.get("자격 증명 시점"),/현재 프로세스 권한이나 권한 변경 전후를 증명하지 않습니다/);
`)
}

func TestCredentialHistoryTypeFilterPreservesOtherFiltersAndResetsPage(t *testing.T) {
	runBrowserBehavior(t, `
(async()=>{
 const paths=[];
 context.fetch=async path=>{paths.push(new URL(path,"http://panel"));return response({items:[],total:0,has_more:false});};
 const view=vm.runInContext("historyViews.events",context);
 get("eventsService").value="worker.service";get("eventSearch").value="needle";
 await view.load();assert.equal(paths.at(-1).searchParams.has("event_type"),false,"all remains default");
 view.cursor="old-page";view.previousCursors=[""];view.nextCursor="next-page";
 get("eventTypeFilter").value="process.credential_change";get("eventTypeFilter").emit("change");await tick();
 const query=paths.at(-1).searchParams;
 assert.equal(query.get("event_type"),"process.credential_change");assert.equal(query.get("service"),"worker.service");assert.equal(query.get("q"),"needle");
 assert.equal(query.has("cursor"),false);assert.equal(view.previousCursors.length,0);
 get("eventTypeFilter").value="";get("eventTypeFilter").emit("change");await tick();
 assert.equal(paths.at(-1).searchParams.has("event_type"),false);
})().catch(error=>{console.error(error);process.exitCode=1;});
`)
}

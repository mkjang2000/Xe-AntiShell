package webpanel

import "testing"

func TestEffectiveResponseAndCollectionUncertainty(t *testing.T) {
	runBrowserBehavior(t, `
assert.equal(vm.runInContext("effectiveResponse(null).label", context), "미확인");
context.policy = {detection_enabled:false,response_mode:"enforce",response_action:"terminate"};
assert.equal(vm.runInContext("effectiveResponse(policy).label", context), "탐지 중지");
context.policy.detection_enabled = true;
for (const [mode, action, label] of [["observe","none","탐지 전용"],["would_block","terminate","모의 대응"],["enforce","terminate","조건부 자동 종료"],["enforce","none","확인 필요"],["future","terminate","확인 필요"]]) {
 context.policy.response_mode=mode;context.policy.response_action=action;
 assert.equal(vm.runInContext("effectiveResponse(policy).label", context),label);
}
context.summary={detection_enabled:true,open_findings:0};
vm.runInContext("renderOperationalAttention({health:'starting'},summary,null)",context);
assert.match(flatten(get("attentionList")), /동작 확인 중/);
assert.doesNotMatch(flatten(get("attentionList")), /운영 상태 정상/);
vm.runInContext("renderOperationalAttention({},summary,null)",context);
assert.match(flatten(get("attentionList")), /수집 상태 미확인/);
vm.runInContext("renderOperationalAttention({health:'healthy'},summary,null)",context);
assert.match(flatten(get("attentionList")), /수집 운영 상태 정상/);
context.summary.open_findings=3;
vm.runInContext("renderOperationalAttention({health:'healthy'},summary,null)",context);
assert.match(flatten(get("attentionList")), /탐지 검토 3건/);
assert.doesNotMatch(flatten(get("attentionList")), /운영 상태 정상/);
assert.equal(vm.runInContext("operationalQuantity(undefined)",context),"미확인");
assert.equal(vm.runInContext("operationalQuantity(0)",context),"0건");
context.recent=[{finding_id:"one",rule_id:"web-descendant-shell",origin_service:"review.service",severity:"high"}];
vm.runInContext("renderRecentFindings(recent)",context);
const jump=get("recentFindings").children[0].children[1];
assert.equal(jump.tagName,"BUTTON");
assert.equal(jump.attributes["aria-label"],undefined,"visible button text supplies its accessible name");
get("findingSearch").value="previous nonmatching query";get("severityFilter").value="low";get("includeSelfTests").checked=true;
jump.emit("click");
assert.equal(get("findingSearch").value,"");assert.equal(get("severityFilter").value,"");assert.equal(get("includeSelfTests").checked,false);
assert.equal(get("findingsService").value,"review.service");
assert.equal(vm.runInContext("state.activeView",context),"findings");
assert.equal(vm.runInContext("historyViews.findings.openGroups.has('review.service')",context),true);
context.document.activeElement=jump;
vm.runInContext("renderRecentFindings(recent)",context);
assert.equal(get("recentFindings").children[0].children[1].focused,true,"refresh preserves review focus");
`)
}

func TestOverviewReflectsActiveExtendedDetectionWithoutClaimingAutomaticResponse(t *testing.T) {
	runBrowserBehavior(t, `
context.summary={detection_enabled:true,extended_process_rules:true,response_mode:"enforce",response_action:"terminate",recent_findings:[]};
vm.runInContext("renderOperatorOverview({status:{health:'healthy'},summary})",context);
assert.equal(get("responseValue").textContent,"확장 탐지 전용");
assert.match(get("responseNote").textContent,/셸과 도구 실행을 확장 탐지/);
assert.match(get("responseNote").textContent,/자동 종료하지 않습니다/);
for(const mode of ["observe","would_block","enforce"]){
 context.summary.response_mode=mode;
 assert.equal(vm.runInContext("effectiveResponse(summary).label",context),"확장 탐지 전용");
}
context.summary.detection_enabled=false;
vm.runInContext("renderOperatorOverview({status:{health:'healthy'},summary})",context);
assert.equal(get("responseValue").textContent,"탐지 중지");
assert.doesNotMatch(get("responseNote").textContent,/확장 탐지|사용 중/);
context.summary.detection_enabled=true;context.summary.extended_process_rules=false;
vm.runInContext("renderOperatorOverview({status:{health:'healthy'},summary})",context);
assert.equal(get("responseValue").textContent,"조건부 자동 종료");
assert.match(get("responseNote").textContent,/기본 셸 탐지/);
delete context.summary.extended_process_rules;
assert.match(vm.runInContext("effectiveResponse(summary).note",context),/기본 셸 탐지/);
context.recent=[{finding_id:"extended-recent",rule_id:"web-descendant-download-tool",detection_only:true,response_decision:"sigterm_sent",severity:"high"}];
vm.runInContext("renderRecentFindings(recent)",context);
assert.match(flatten(get("recentFindings")),/웹 서비스에서 다운로드 도구 실행/);
assert.match(flatten(get("recentFindings")),/확장 탐지 전용/);
assert.doesNotMatch(flatten(get("recentFindings")),/종료 신호 전송/);
`)
}

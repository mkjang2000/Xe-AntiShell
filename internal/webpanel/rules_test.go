package webpanel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"xe-antishell/internal/model"
)

type catalogAgent struct {
	fakeAgent
	catalogErr error
}

func (agent catalogAgent) Rules(context.Context) (model.RuleCatalog, error) {
	return model.RuleCatalog{PolicySource: "managed", PolicyRevision: 9, Rules: []model.RuleStatus{{ID: "example", Enabled: true}}}, agent.catalogErr
}

func TestOptionalRuleCatalogInOverview(t *testing.T) {
	for _, tc := range []struct {
		name  string
		agent AgentClient
		live  bool
	}{
		{"reported", catalogAgent{}, true},
		{"temporarily unavailable", catalogAgent{catalogErr: errors.New("unavailable")}, false},
		{"older agent", fakeAgent{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := testServer(t, tc.agent)
			response := httptest.NewRecorder()
			server.overview(response, httptest.NewRequest(http.MethodGet, "/api/overview", nil))
			var snapshot overviewResponse
			if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusOK || snapshot.Status.Health != model.HealthHealthy || (snapshot.Rules != nil) != tc.live {
				t.Fatalf("overview = %d %#v", response.Code, snapshot)
			}
			if tc.live && (snapshot.Rules.PolicyRevision != 9 || len(snapshot.Rules.Rules) != 1 || !snapshot.Rules.Rules[0].Enabled) {
				t.Fatalf("incomplete catalog: %#v", snapshot.Rules)
			}
		})
	}
}

func TestRuleListAndFindingLabelsShareCatalog(t *testing.T) {
	runBrowserBehavior(t, `
context.catalog = {policy_source:"managed", policy_revision:12, rules:[
  {id:"web-descendant-shell", version:"2", title:"현행 규칙명", description:"관측 근거", profile:"base", event_types:["process.exec"], required_fields:["process.exe"], enabled:true, response:"enforce", sensors:[{name:"observation.process_exec",state:"unverified"}]},
  {id:"new-rule",version:"3",title:"새 규칙",enabled:false,reason:"프로필 꺼짐",response:"detection_only",sensors:[{name:"observation.credential_change",state:"active",verified_at:"2026-02-01T12:00:00Z"}]}
]};
vm.runInContext("state.data={rules:catalog};renderRuleCatalog()",context);
assert.equal(get("ruleRows").children.length,2);
assert.match(get("rulePolicy").textContent,/중앙 정책.*12/);
const ruleDetails=get("ruleRows").children[0].children[0].children[1];
assert.equal(ruleDetails.open,false);
assert.match(flatten(ruleDetails),/규칙 상세.*설명.*관측 근거.*프로필.*기본.*입력 이벤트.*process.exec.*필수 필드.*process.exe/);
ruleDetails.open=true;ruleDetails.emit("toggle");
vm.runInContext("renderRuleCatalog()",context);
assert.equal(get("ruleRows").children[0].children[0].children[1].open,true);
assert.match(flatten(get("ruleRows").children[0]),/활성.*관측 미확인.*조건 충족 시 종료 가능/);
assert.match(flatten(get("ruleRows").children[1]),/비활성.*프로필 꺼짐.*관측 확인.*종료 대상 아님/);
context.finding={rule_id:"web-descendant-shell",finding_id:"record",risk_factors:[],evidence_event_ids:[]};
vm.runInContext("renderRecentFindings([finding])",context);
assert.match(flatten(get("recentFindings")),/현행 규칙명/);
assert.match(flatten(vm.runInContext("findingCard(finding)",context)),/현행 규칙명.*관측 근거/);
for (const value of ["새 규칙","NEW-RULE"]) {
  get("ruleSearch").value=value;get("ruleSearch").emit("input");
  assert.equal(get("ruleRows").children.length,1);
  assert.match(flatten(get("ruleRows")),/new-rule/);
}
get("ruleSearch").value="no matches";get("ruleSearch").emit("input");
assert.equal(get("ruleTable").hidden,true);
assert.match(get("ruleCount").textContent,/2개 중 0개/);
vm.runInContext("state.data={};renderRuleCatalog()",context);
assert.equal(get("ruleSearch").disabled,true);
assert.match(get("ruleCount").textContent,/가져오지 못/);
assert.equal(vm.runInContext("findingTitle(finding)",context),"웹 서비스에서 셸 실행");
`)
}

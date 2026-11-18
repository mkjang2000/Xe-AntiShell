package webpanel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"xe-antishell/internal/model"
)

type sampleAgent struct {
	fakeAgent
	query model.ObservationQuery
}

func (agent *sampleAgent) Observations(ctx context.Context, q model.ObservationQuery) (model.ObservationReport, error) {
	agent.query = q
	return model.ObservationReport{Samples: []model.ObservationSample{}}, nil
}

func TestObservationProxyUsesSharedQueryValidation(t *testing.T) {
	agent := &sampleAgent{}
	server := testServer(t, agent)
	request := httptest.NewRequest(http.MethodGet, "/api/observations?limit=15&service=test.service&protected_dir=/app", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || agent.query.Limit != 0 {
		t.Fatalf("unauthenticated request: %d %#v", recorder.Code, agent.query)
	}
	recorder = httptest.NewRecorder()
	server.observations(recorder, request)
	if recorder.Code != http.StatusOK || agent.query != (model.ObservationQuery{Limit: 15, Service: "test.service", ProtectedDir: "/app"}) {
		t.Fatalf("valid request: %d %#v", recorder.Code, agent.query)
	}
	recorder = httptest.NewRecorder()
	server.observations(recorder, httptest.NewRequest(http.MethodGet, "/api/observations?protected_dir=relative", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid request: %d", recorder.Code)
	}
}

func TestSampleReviewAndOutOfOrderQueries(t *testing.T) {
	runBrowserBehavior(t, `
(async()=>{
  const pending=[];
  context.fetch = (path)=>new Promise(resolve=>pending.push({path,resolve}));
  get("observationsPanel").open=true;
  get("observationsPanel").emit("toggle");
  get("observationService").value="web.service";
  get("observationProtected").value="/app";
  get("observationAllowed").value="/app/uploads";
  get("observationLimit").value="20";
  const submit=()=>get("observationFilters").emit("submit",{preventDefault(){}});
  submit();
  const params=new URL(pending[1].path,"http://panel").searchParams;
  assert.equal(params.get("protected_dir"),"/app");
  assert.equal(params.get("allowed_dir"),"/app/uploads");
  assert.equal(params.get("service"),"web.service");
  pending[1].resolve(response({samples:[
    {event_id:"write1",event_type:"file.write",path:"/app/incoming",service:"web.service",outcome:"written",return_value:12,review:"protected_write_candidate"},
    {event_id:"net1",event_type:"network.connect",destination_address:"2001:db8::1",destination_port:443,service:"api.service",outcome:"initiated",return_value:0},
    {event_id:"unknown",event_type:"file.write",path:"<img>",outcome:"unknown",review:"unconfirmed_write"},
  ]}));
  await tick();
  pending[0].resolve(response({samples:[]}));
  await tick();
  assert.equal(get("observationRows").children.length,3);
  assert.match(flatten(get("observationRows").children[0]),/web.service.*\/app\/incoming.*쓰기 바이트 수 확인.*12.*보호 경로 쓰기 후보/);
  assert.match(flatten(get("observationRows").children[1]),/api.service.*\[2001:db8::1\]:443.*TCP 연결 요청 시작.*0/);
  assert.match(flatten(get("observationRows").children[2]),/출처 미확인.*<img>.*쓰.*미확인/);
  get("observationService").value="";submit();
  assert.equal(pending.length,2);
  assert.equal(get("observationTable").hidden,true);
  assert.match(get("observationStatus").textContent,/서비스와 보호 경로/);
  get("observationProtected").value="";get("observationAllowed").value="";submit();
  pending.at(-1).resolve(response({samples:[]}));await tick();
  assert.match(get("observationStatus").textContent,/표본이 없습니다/);
  submit();pending.at(-1).resolve({status:502});await tick();
  assert.match(get("observationStatus").textContent,/불러오지 못/);
})().catch(error=>{console.error(error);process.exitCode=1;});
`)
}

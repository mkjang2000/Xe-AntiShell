package webpanel

import (
	"os/exec"
	"strings"
	"testing"
)

func TestOperatorCapabilityStatusPrecedenceAndDescriptions(t *testing.T) {
	runCapabilityBehavior(t, operatorCapabilityBehavior)
}

func TestOperatorCapabilityRowsHideTechnicalFieldsAndPreserveExpansion(t *testing.T) {
	runCapabilityBehavior(t, operatorCapabilityRowsBehavior)
}

func runCapabilityBehavior(t *testing.T, behavior string) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is not installed; capability presentation test skipped")
	}
	script, err := assets.ReadFile("assets/capabilities.js")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(node, "-e", capabilityBehaviorHarness+behavior)
	command.Stdin = strings.NewReader(string(script))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("capability presentation behavior: %v\n%s", err, output)
	}
}

const capabilityBehaviorHarness = `
const assert = require("node:assert/strict");
const vm = require("node:vm");
class Element {
  constructor(tag) {
    this.tagName=tag;this.textContent="";this.children=[];this.className="";this.open=false;this.handlers={};
    this.classes=new Set();this.classList={toggle:(name,value)=>value?this.classes.add(name):this.classes.delete(name),contains:(name)=>this.classes.has(name)};
  }
  append(...nodes){this.children.push(...nodes)}
  contains(element){return this===element||this.children.some(child=>child.contains(element))}
  replaceChildren(...nodes){if(this.children.some(child=>child.contains(mockDocument.activeElement)))mockDocument.activeElement=null;this.children=nodes}
  addEventListener(name,handler){this.handlers[name]=handler}
  emit(name){this.handlers[name]?.()}
  focus(options={}){mockDocument.activeElement=this;this.focusOptions=options}
}
const elements=new Map();
const get=id=>{if(!elements.has(id))elements.set(id,new Element("div"));return elements.get(id)};
const mockDocument={activeElement:null,createElement:tag=>new Element(tag)};
const context=vm.createContext({document:mockDocument,byId:get,text:(id,value)=>get(id).textContent=value,fmtTime:value=>value});
vm.runInContext(require("node:fs").readFileSync(0,"utf8"),context);
const present=(name,capability)=>{context.name=name;context.capability=capability;return vm.runInContext("capabilityPresentation(name,capability)",context)};
const fixture=(overrides={})=>({state:"limited",implementation:"implemented",runtime_state:"active",runtime_reason:"live Tetragon process execution events received",verified_at:"2026-11-16T07:00:00Z",...overrides});
const flatten=node=>node.textContent+node.children.map(flatten).join(" ");
const outsideDetails=node=>node.tagName==="details"?"":node.textContent+node.children.map(outsideDetails).join(" ");
`

const operatorCapabilityBehavior = `
let value=present("collector.tetragon",fixture());
assert.equal(value.label,"정상 수집");assert.equal(value.active,true);assert.equal(value.tone,"active");
assert.match(value.description,/실시간으로 수집/);assert.doesNotMatch(value.description,/환경 제한|limited|Tetragon/);
value=present("collector.audit",fixture({state:"limited",runtime_state:"inactive",runtime_reason:"not the selected process collector"}));
assert.equal(value.label,"사용 안 함");assert.equal(value.action,"");assert.equal(value.tone,"inactive");
value=present("collector.audit",fixture({state:"unsupported",runtime_state:"inactive",runtime_reason:"not the selected process collector"}));
assert.equal(value.label,"사용 안 함");assert.equal(value.tone,"inactive");
value=present("observation.process_exec",fixture());
assert.equal(value.label,"정상 수집");assert.match(value.description,/탐지 대상 이력만 저장/);
value=present("observation.process_exec",fixture({runtime_reason:"audit execution events received; candidate filters apply and audit provides no process-exit stream"}));
assert.match(value.description,/종료 정보를 제공하지/);
value=present("observation.process_lineage",fixture({runtime_reason:"Tetragon source ancestry received; missing parents remain explicit"}));
assert.match(value.description,/일부 상위 실행 정보가 누락/);
value=present("response.terminate",fixture({state:"supported",runtime_state:"available",runtime_reason:"host-local termination opt-in is disabled"}));
assert.equal(value.title,"의심 프로세스 종료");assert.equal(value.label,"자동 대응 꺼짐");assert.equal(value.tone,"inactive");assert.equal(value.active,false);
value=present("response.terminate",fixture({state:"supported",runtime_reason:"host-local opt-in enabled; strict per-process identity checks still apply"}));
assert.equal(value.label,"조건부 사용");assert.equal(value.tone,"unverified");assert.equal(value.active,false);assert.match(value.description,/보안 정책과 안전 조건/);

for(const state of ["unsupported","error","unexpected",undefined]){
 value=present("collector.tetragon",fixture({state}));
 assert.notEqual(value.tone,"active");assert.equal(value.active,false);assert.notEqual(value.label,"정상 수집");
}
for(const runtime_state of ["error","unexpected",undefined]){
 value=present("collector.tetragon",fixture({runtime_state}));
 assert.notEqual(value.tone,"active");assert.equal(value.active,false);
}
value=present("collector.tetragon",fixture({runtime_state:"unverified",runtime_reason:"selected collector stream is not running"}));
assert.equal(value.label,"수집 중단");assert.equal(value.tone,"error");assert.match(value.action,/연결 상태/);
value=present("kernel.ebpf",fixture({runtime_state:"unverified",runtime_reason:"source operation failed; active attachment is no longer established by this agent"}));
assert.equal(value.label,"확인 필요");assert.notEqual(value.tone,"active");assert.match(value.description,/연결이 중단/);
value=present("collector.future",fixture({state:"supported"}));
assert.equal(value.label,"확인 필요");assert.equal(value.title,"추가 진단 항목");assert.equal(value.active,false);
for(const name of ["constructor","__proto__","toString"]){value=present(name,fixture({state:"supported"}));assert.equal(value.title,"추가 진단 항목");assert.equal(value.active,false);}
value=present("collector.tetragon",null);assert.equal(value.label,"확인 필요");
value=present("observation.file",fixture({implementation:"planned"}));
assert.equal(value.category,"planned");assert.equal(value.label,"개발 예정");assert.equal(value.active,false);
value=present("integrity.tpm",fixture({state:"unsupported",runtime_state:"inactive",implementation:"planned"}));
assert.equal(value.category,"prerequisite");assert.equal(value.label,"장치 없음");assert.match(value.description,/필수인 장치는 아닙니다/);assert.match(value.description,/검증은 아직 제공하지/);
value=present("integrity.ima",fixture({state:"supported",runtime_state:"inactive",implementation:"planned"}));
assert.equal(value.label,"정보 있음");assert.equal(value.tone,"inactive");assert.match(value.description,/무결성 검증은 아직 제공하지/);
`

const operatorCapabilityRowsBehavior = `
context.items={
 "collector.tetragon":fixture(),
 "collector.audit":fixture({runtime_state:"inactive",runtime_reason:"not the selected process collector"}),
 "observation.process_exec":fixture(),
 "response.terminate":fixture({state:"supported",runtime_state:"available",runtime_reason:"host-local termination opt-in is disabled"}),
 "integrity.tpm":fixture({state:"unsupported",runtime_state:"inactive",implementation:"planned"}),
 "observation.file":fixture({state:"unsupported",runtime_state:"inactive",implementation:"planned"}),
};
vm.runInContext("renderCapabilities(items)",context);
assert.equal(get("capabilityList").children.length,4);
assert.equal(get("prerequisiteCapabilityList").children.length,1);
assert.equal(get("plannedCapabilityList").children.length,1);
assert.equal(get("capabilitySummary").textContent,"정상 수집 2개");
assert.equal(get("plannedCapabilities").open,false);
assert.equal(get("plannedCapabilities").classList.contains("hidden"),false);
for(const row of get("capabilityList").children){
 assert.equal(row.children.filter(child=>child.className==="cap-badges")[0].children.length,1,"one representative status per row");
 const technical=row.children.find(child=>child.tagName==="details");assert.ok(technical);assert.equal(technical.open,false);
 assert.equal(technical.children[0].textContent,"기술 정보");
 assert.doesNotMatch(outsideDetails(row),/collector\.|observation\.|response\.|runtime|Tetragon|environment|limited/);
}
let row=get("capabilityList").children.find(row=>flatten(row).includes("collector.tetragon"));
let technical=row.children.find(child=>child.tagName==="details");technical.open=true;technical.emit("toggle");
const oldSummary=technical.children[0];oldSummary.focus();
get("plannedCapabilities").open=true;
context.items["collector.tetragon"].runtime_state="error";
context.items["collector.tetragon"].runtime_reason='<img src=x onerror="alert(1)">';
vm.runInContext("renderCapabilities(items)",context);
assert.equal(get("plannedCapabilities").open,true,"poll preserves planned section expansion");
row=get("capabilityList").children.find(row=>flatten(row).includes("collector.tetragon"));
technical=row.children.find(child=>child.tagName==="details");
assert.equal(technical.open,true,"poll preserves technical expansion");
assert.notEqual(technical.children[0],oldSummary,"poll creates a replacement summary");
assert.equal(mockDocument.activeElement,technical.children[0],"poll restores keyboard focus to the same capability");
assert.equal(technical.children[0].focusOptions.preventScroll,true,"focus restoration must not move the reading position");
assert.doesNotMatch(outsideDetails(row),/<img|onerror/);
assert.match(flatten(technical),/<img src=x onerror="alert\(1\)">/);
const collectTags=node=>[node.tagName,...node.children.flatMap(collectTags)];
assert.equal(collectTags(row).includes("img"),false,"raw diagnostic remains literal text");
assert.equal(get("capabilitySummary").textContent,"정상 수집 1개");
technical.open=false;technical.emit("toggle");
vm.runInContext("renderCapabilities(items)",context);
row=get("capabilityList").children.find(row=>flatten(row).includes("collector.tetragon"));
assert.equal(row.children.find(child=>child.tagName==="details").open,false);
assert.equal(mockDocument.activeElement,row.children.find(child=>child.tagName==="details").children[0],"a closed technical summary also keeps focus");
const outside=get("outsideControl");outside.focus();
vm.runInContext("renderCapabilities(items)",context);
assert.equal(mockDocument.activeElement,outside,"refresh must not steal focus from another control");
row=get("capabilityList").children.find(row=>flatten(row).includes("response.terminate"));
row.children.find(child=>child.tagName==="details").children[0].focus();
vm.runInContext("renderCapabilities(items)",context);
row=get("capabilityList").children.find(row=>flatten(row).includes("response.terminate"));
assert.equal(mockDocument.activeElement,row.children.find(child=>child.tagName==="details").children[0],"focus restoration follows the capability identifier");
context.items={};vm.runInContext("renderCapabilities(items)",context);
assert.equal(get("capabilityList").children.length,0);assert.equal(get("plannedCapabilities").classList.contains("hidden"),true);
assert.equal(mockDocument.activeElement,null,"a removed capability must not redirect focus to a different item");
`

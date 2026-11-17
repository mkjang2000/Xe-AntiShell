package webpanel

import (
	"bytes"
	"math"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestCapabilityPanelGroupingAndRuntimeEvidence(t *testing.T) {
	index, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	details := regexp.MustCompile(`<details\b[^>]*\bid="plannedCapabilities"[^>]*>`).Find(index)
	if len(details) == 0 || regexp.MustCompile(`\bopen(?:\s|=|>)`).Match(details) {
		t.Fatal("unimplemented capabilities must be in a closed-by-default details section")
	}
	runBrowserBehavior(t, capabilityBehaviorTest)
}

func TestOperatorHistoryExcludesSelfTestsByDefault(t *testing.T) {
	index, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	checkbox := regexp.MustCompile(`<input\b[^>]*\bid="includeSelfTests"[^>]*>`).Find(index)
	if len(checkbox) == 0 || regexp.MustCompile(`\bchecked(?:\s|=|>)`).Match(checkbox) {
		t.Fatal("operational history must exclude self-tests by default")
	}
}

func TestHistoryGroupingPaginationAndFilters(t *testing.T) {
	runBrowserBehavior(t, historyBehaviorTest)
}

func TestResourceSamplingAndBoundedProcesses(t *testing.T) {
	runBrowserBehavior(t, resourceBehaviorTest)
}

func TestManagedStatusShowsStandaloneAndDeliveryPolicyState(t *testing.T) {
	runBrowserBehavior(t, managedStatusBehaviorTest)
}

func TestLastRetainedEventSurvivesRuntimeRestart(t *testing.T) {
	runBrowserBehavior(t, `
context.snapshot={status:{health:"healthy"},capabilities:{platform:{},capabilities:{}},events:[{event_time:new Date(Date.now()-300000).toISOString()}],findings:[]};
vm.runInContext("state.data=snapshot;render()",context);
assert.match(get("lastEventValue").textContent,/5분 전/);
context.snapshot.events=[];
vm.runInContext("render()",context);
assert.equal(get("lastEventValue").textContent,"이력 없음");
`)
}

func TestOperatorOverviewUsesWholeStoreCountsAndExplicitUnknowns(t *testing.T) {
	runBrowserBehavior(t, `
context.snapshot={
 status:{health:"healthy",collector:"tetragon-json"},capabilities:{platform:{},capabilities:{}},events:[],
 findings:Array.from({length:100},()=>({state:"open",severity:"critical"})),
 summary:{as_of:new Date().toISOString(),window_start:new Date(Date.now()-86400000).toISOString(),total_events:333,events_24h:30,total_findings:8,open_findings:5,findings_24h:4,self_test_findings:7,critical_open:2,high_open:3,other_open:0,detection_enabled:true,response_mode:"observe",response_action:"none",recent_findings:[]},
};
vm.runInContext("state.data=snapshot;render()",context);
assert.equal(get("findingCount").textContent,"5","recent sample must not replace authoritative retained totals");
delete context.snapshot.summary;
vm.runInContext("render()",context);
assert.equal(get("findingCount").textContent,"미확인","unavailable aggregate must not become zero or a bounded sample");
`)
}

func TestOperatorVocabularyUsesOwnMappingsAndHonestUnknowns(t *testing.T) {
	runBrowserBehavior(t, `
context.query=["severity","critical"];
assert.equal(vm.runInContext("operatorLabel(...query)",context),"매우 높음");
for(const value of ["constructor","__proto__","toString","future-severity"]){
 context.query=["severity",value];
 assert.equal(vm.runInContext("operatorLabel(...query)",context),"미분류");
}
for(const kind of ["constructor","__proto__","toString","future-category"]){
 context.query=[kind,"constructor"];
 assert.equal(vm.runInContext("operatorLabel(...query)",context),"미확인");
}
`)
}

func runBrowserBehavior(t *testing.T, behavior string) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is not installed; browser-script behavior test skipped")
	}
	var scripts bytes.Buffer
	for _, name := range []string{"presentation.js", "capabilities.js", "overview.js", "history.js", "resources.js", "app.js"} {
		script, err := assets.ReadFile("assets/" + name)
		if err != nil {
			t.Fatal(err)
		}
		scripts.Write(script)
		scripts.WriteByte('\n')
	}
	command := exec.Command(node, "-e", browserBehaviorHarness+behavior)
	command.Stdin = &scripts
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser behavior: %v\n%s", err, output)
	}
}

func TestBrowserAssetsAvoidUnsafeDOMRendering(t *testing.T) {
	for _, name := range []string{"presentation.js", "capabilities.js", "overview.js", "app.js", "history.js", "resources.js", "theme.js"} {
		script, err := assets.ReadFile("assets/" + name)
		if err != nil {
			t.Fatal(err)
		}
		for _, unsafe := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"} {
			if strings.Contains(string(script), unsafe) {
				t.Fatalf("%s uses unsafe event rendering primitive %s", name, unsafe)
			}
		}
	}
}

func TestPanelTextAndControlContrast(t *testing.T) {
	css, err := assets.ReadFile("assets/app.css")
	if err != nil {
		t.Fatal(err)
	}
	base := regexp.MustCompile(`(?s):root\s*\{([^}]*)\}`).FindSubmatch(css)
	dark := regexp.MustCompile(`(?s)(?::root)?\[data-theme=["']?dark["']?\]\s*\{([^}]*)\}`).FindSubmatch(css)
	if len(base) != 2 || len(dark) != 2 {
		t.Fatal("explicit light-default and dark token blocks are required")
	}
	if !regexp.MustCompile(`color-scheme:\s*light\s*;`).Match(base[1]) || !regexp.MustCompile(`color-scheme:\s*dark\s*;`).Match(dark[1]) {
		t.Fatal("form control color schemes must match their themes")
	}
	colors := regexp.MustCompile(`--([a-z0-9-]+):\s*(#[a-fA-F0-9]{6})\s*;`)
	for _, theme := range []string{"light", "dark"} {
		t.Run(theme, func(t *testing.T) {
			palette := map[string]string{}
			for _, block := range [][]byte{base[1], dark[1]} {
				for _, match := range colors.FindAllSubmatch(block, -1) {
					palette[string(match[1])] = string(match[2])
				}
				if theme == "light" {
					break
				}
			}
			for _, name := range []string{"bg", "panel", "panel2", "line", "border", "text", "muted", "accent", "accent-text", "accent-hover", "danger", "warn", "blue", "success-bg", "danger-bg", "warning-bg", "neutral-bg", "neutral-text", "inactive-bg", "inactive-text", "blue-bg", "placeholder", "disabled-bg", "disabled-text", "disabled-border", "zero-bar"} {
				if palette[name] == "" {
					t.Errorf("missing %s color token", name)
				}
			}
			pairs := [][2]string{
				{"text", "bg"}, {"text", "panel"}, {"text", "panel2"},
				{"muted", "bg"}, {"muted", "panel"}, {"muted", "panel2"},
				{"accent", "bg"}, {"accent", "panel"}, {"accent", "panel2"}, {"accent", "success-bg"},
				{"accent-text", "accent"}, {"accent-text", "accent-hover"},
				{"danger", "bg"}, {"danger", "panel"}, {"danger", "danger-bg"},
				{"warn", "panel"}, {"warn", "warning-bg"}, {"blue", "blue-bg"},
				{"neutral-text", "neutral-bg"}, {"inactive-text", "inactive-bg"},
				{"placeholder", "bg"}, {"disabled-text", "disabled-bg"},
			}
			for _, pair := range pairs {
				ratio := colorContrast(palette[pair[0]], palette[pair[1]])
				if math.IsNaN(ratio) || ratio < 4.5 {
					t.Errorf("%s/%s text contrast %.2f is below 4.5:1", pair[0], pair[1], ratio)
				}
				t.Logf("%s/%s: %.2f:1", pair[0], pair[1], ratio)
			}
			for _, background := range []string{"bg", "panel", "panel2"} {
				if ratio := colorContrast(palette["line"], palette[background]); math.IsNaN(ratio) || ratio < 3 {
					t.Errorf("control border contrast on %s %.2f is below 3:1", background, ratio)
				}
			}
		})
	}
}

func colorContrast(first, second string) float64 {
	luminance := func(color string) float64 {
		value, err := strconv.ParseUint(strings.TrimPrefix(color, "#"), 16, 32)
		if err != nil {
			return math.NaN()
		}
		var result float64
		for index, weight := range []float64{0.2126, 0.7152, 0.0722} {
			component := float64((value>>uint(16-index*8))&255) / 255
			if component <= 0.04045 {
				component /= 12.92
			} else {
				component = math.Pow((component+0.055)/1.055, 2.4)
			}
			result += component * weight
		}
		return result
	}
	firstValue, secondValue := luminance(first), luminance(second)
	return (math.Max(firstValue, secondValue) + 0.05) / (math.Min(firstValue, secondValue) + 0.05)
}

const browserBehaviorHarness = `
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
class Element {
  constructor(name = "div") {
    this.tagName = name.toUpperCase();
    this.children = [];
    this.textContent = "";
    this.className = "";
    this.open = false;
    this.value = "";
	this.checked = false;
	this.dataset = {};
    this.disabled = false;
    this.hidden = false;
    this.attributes = {};
    this.handlers = {};
    this.classes = new Set();
    this.classList = {
      toggle: (name, force) => force ? this.classes.add(name) : this.classes.delete(name),
      add: (name) => this.classes.add(name),
      remove: (name) => this.classes.delete(name),
      contains: (name) => this.classes.has(name),
    };
  }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  get options() { return this.children; }
  addEventListener(name, handler) { this.handlers[name] = handler; }
  setAttribute(name, value) { this.attributes[name] = value; }
  focus() { this.focused = true; }
  emit(name, event = {}) { if (this.handlers[name]) this.handlers[name](event); }
}
const elements = new Map();
const get = (id) => {
  if (!elements.has(id)) elements.set(id, new Element());
  return elements.get(id);
};
const context = vm.createContext({
  document: {getElementById: get, createElement: (name) => new Element(name)},
  fetch: () => new Promise(() => {}), setInterval: () => {}, console, URLSearchParams,
  location: {},
});
vm.runInContext(fs.readFileSync(0, "utf8"), context);
const flatten = (node) => node.textContent + node.children.map(flatten).join(" ");
const outsideDetails = (node) => node.tagName === "DETAILS" ? "" : node.textContent + node.children.map(outsideDetails).join(" ");
const response = (page) => ({status: 200, ok: true, json: async () => page});
const tick = () => new Promise(setImmediate);
` + "\n"

const capabilityBehaviorTest = `
const fixture = {
  "collector.audit": {state:"limited",implementation:"implemented",runtime_state:"inactive",runtime_reason:"not the selected process collector"},
  "collector.tetragon": {state:"limited",implementation:"implemented",runtime_state:"active",runtime_reason:"actual event received",verified_at:"2026-11-16T04:00:00Z"},
  "observation.process_exec": {state:"limited",implementation:"implemented",runtime_state:"active"},
  "observation.file": {state:"unsupported",implementation:"planned",runtime_state:"inactive"},
  "observation.network": {state:"unsupported",implementation:"planned",runtime_state:"inactive"},
  "observation.credential_change": {state:"unsupported",implementation:"planned",runtime_state:"inactive"},
  "integrity.tpm": {state:"unsupported",implementation:"planned",runtime_state:"inactive",runtime_reason:"no TPM device"},
  "integrity.ima": {state:"supported",implementation:"planned",runtime_state:"inactive"},
  "kernel.ebpf": {state:"limited",implementation:"implemented",runtime_state:"active",runtime_reason:"eBPF hooks attached"},
};
context.fixture = fixture;
vm.runInContext("renderCapabilities(fixture)", context);
assert.equal(get("plannedCapabilities").open, false, "planned features default collapsed");
assert.equal(get("capabilityList").children.length, 3, "installed collectors remain visible");
assert.equal(get("plannedCapabilityList").children.length, 3, "only unimplemented observations fold");
assert.equal(get("prerequisiteCapabilityList").children.length, 3, "IMA and missing TPM remain visible as prerequisites");
assert.equal(get("capabilitySummary").textContent, "정상 수집 2개");
assert.match(outsideDetails(get("capabilityList")), /정상 수집/);
assert.match(outsideDetails(get("capabilityList")), /사용 안 함/);
assert.doesNotMatch(outsideDetails(get("capabilityList")), /환경 제한|collector\.|observation\.|actual event received/);
for (const row of get("capabilityList").children) {
  assert.equal(row.children.find(child=>child.className==="cap-badges").children.length,1,"one operational status per feature");
  const technical=row.children.find(child=>child.tagName==="DETAILS");
  assert.ok(technical);assert.equal(technical.open,false,"technical diagnostics start collapsed");
  assert.equal(technical.children[0].textContent,"기술 정보");
}
assert.match(flatten(get("capabilityList")), /actual event received/);
assert.match(flatten(get("capabilityList")), /동작 확인 시각/);
assert.match(flatten(get("prerequisiteCapabilityList")), /장치 없음/);
assert.match(flatten(get("prerequisiteCapabilityList")), /동작 확인/);
assert.match(outsideDetails(get("prerequisiteCapabilityList")), /무결성 검증은 아직 제공하지/);
get("plannedCapabilities").open = true;
fixture["collector.tetragon"].runtime_state = "error";
fixture["collector.tetragon"].runtime_reason = "<script>alert(1)</script>";
vm.runInContext("renderCapabilities(fixture)", context);
assert.equal(get("plannedCapabilities").open, true, "poll refresh preserves expansion");
assert.equal(get("capabilitySummary").textContent, "정상 수집 1개");
assert.match(outsideDetails(get("capabilityList")), /오류/);
assert.doesNotMatch(outsideDetails(get("capabilityList")), /<script>/);
assert.match(flatten(get("capabilityList")), /<script>alert\(1\)<\/script>/);
`

const historyBehaviorTest = `
(async () => {
  const view = vm.runInContext("historyViews.findings", context);
  const paths = [];
  const records = Array.from({length: 12}, (_, index) => ({
    finding_id: "finding-" + index, rule_id: "web-shell", severity: "high", state: "open",
    origin_service: index === 0 ? "<img src=x onerror=alert(1)>" : "web.service",
    summary: "<script>alert(1)</script>", confidence: 0.95, evidence_event_ids: ["event-" + index],
  }));
  context.fetch = async (path) => {
    paths.push(new URL(path, "http://panel"));
    return response({items: records, has_more: true, next_cursor: "cursor-2", total: 23});
  };
  await view.load();
  assert.equal(paths[0].searchParams.get("limit"), "10");
  assert.equal(paths[0].searchParams.get("exclude_self_tests"),"1");
  const groups = get("findingsGroups").children;
  assert.equal(groups.length, 2, "group by actual origin service");
  assert.equal(groups.reduce((total, group) => total + group.children.length - 1, 0), 10, "never render more than ten records");
  assert.ok(groups.every((group) => !group.open), "service groups start collapsed");
  assert.match(flatten(groups[0]), /<img src=x onerror=alert\(1\)>/);
  assert.match(flatten(groups[0]), /<script>alert\(1\)<\/script>/);
  assert.equal(get("findingsNext").disabled, false);
  groups[1].open = true; groups[1].emit("toggle");
  await view.load();
  assert.equal(get("findingsGroups").children[1].open, true, "refresh preserves service expansion");
  view.next(); await tick();
  assert.equal(paths.at(-1).searchParams.get("cursor"), "cursor-2");
  assert.match(get("findingsPage").textContent, /^2페이지/);
  assert.equal(get("findingsPrevious").disabled, false);
  view.previous(); await tick();
  assert.equal(paths.at(-1).searchParams.has("cursor"), false);
  get("findingsService").value = "web.service";
  get("findingSearch").value = "  shell  ";
  get("severityFilter").value = "high";
  view.reset(); await view.load();
  assert.equal(paths.at(-1).searchParams.get("service"), "web.service");
  assert.equal(paths.at(-1).searchParams.get("q"), "shell");
  assert.equal(paths.at(-1).searchParams.get("severity"), "high");
  const pending = [];
  context.fetch = () => new Promise((resolve) => pending.push(resolve));
  const old = view.load(), recent = view.load();
  pending[1](response({items: [{...records[0], summary:"new result"}], has_more:false, total:1}));
  await recent;
  pending[0](response({items: [{...records[0], summary:"stale result"}], has_more:true, next_cursor:"stale"}));
  await old;
  assert.match(flatten(get("findingsGroups")), /new result/);
  assert.doesNotMatch(flatten(get("findingsGroups")), /stale result/);
  assert.equal(get("findingsNext").disabled, true);
  context.fetch = async () => response({items:[], has_more:false, total:0});
  await view.load();
  assert.equal(get("findingsGroups").children.length, 0);
  assert.equal(get("findingsEmpty").classList.contains("hidden"), false);
  context.fetch = async () => { throw new Error("offline"); };
  await view.load();
  assert.match(get("findingsStatus").textContent, /불러오지 못했습니다/);
  assert.doesNotMatch(get("findingsStatus").textContent, /offline/);
  assert.equal(view.lastError,"offline","raw browser error remains available without leaking developer text into the operator message");
  assert.equal(get("findingsGroups").attributes["aria-busy"], "false");
  context.fetch = async () => ({status:401});
  await view.load();
  assert.equal(context.location.href, "/login");
  get("tab-overview").emit("keydown", {key:"End", preventDefault(){}});
  assert.equal(get("tab-system").attributes["aria-selected"], "true");
  assert.equal(get("tab-system").focused, true);
  assert.equal(get("view-system").hidden, false);
  assert.equal(get("view-overview").hidden, true);
})().catch((error) => { console.error(error); process.exitCode = 1; });
`

const resourceBehaviorTest = `
context.resources = {
  sampled_at: "2026-11-16T05:00:00Z", interval_seconds: 0,
  cpu: {usage_percent:null, load1:1.2, logical_cpus:4},
  memory: {total_bytes:4096, available_bytes:1024, used_bytes:3072},
  filesystems: [{mount:"/", type:"xfs", total_bytes:1000, used_bytes:250, available_bytes:750}],
  disks: [{name:"vda", read_bytes_per_second:null, write_bytes_per_second:null}],
  network: [
    {name:"lo",rx_bytes_per_second:999999,tx_bytes_per_second:999999},
    {name:"veth123",rx_bytes_per_second:888888,tx_bytes_per_second:888888},
    {name:"eno2",state:"down",rx_bytes_per_second:0,tx_bytes_per_second:0},
    {name:"eth0",state:"up",rx_bytes_per_second:1024,tx_bytes_per_second:2048},
  ],
  process_count:23, errors:["<img src=x onerror=alert(1)>"],
  processes: Array.from({length:23}, (_, index) => ({pid:index+1,uid:0,exe:"/process/"+index,cpu_percent:null,rss_bytes:1024,origin_service:"web.service"})),
};
vm.runInContext("renderResources(resources)", context);
assert.equal(get("resourceOverview").classList.contains("hidden"), false);
assert.equal(get("resourceDetails").classList.contains("hidden"), false);
assert.match(flatten(get("resourceCards")), /계산 중/);
assert.match(flatten(get("resourceCards")), /25.0%/);
assert.match(flatten(get("resourceCards")), /네트워크 · eth0/);
assert.doesNotMatch(flatten(get("resourceCards")), /999999|888888/);
assert.match(get("resourceSampleNote").textContent, /다음 측정/);
assert.doesNotMatch(outsideDetails(get("resourceWarnings")), /<img/);
assert.match(flatten(get("resourceWarnings")), /<img src=x onerror=alert\(1\)>/);
assert.equal(get("processListBody").children.length, 10);
assert.equal(get("processPrevious").disabled, true);
get("processNext").emit("click");
assert.equal(get("processListBody").children.length, 10);
assert.match(get("processPage").textContent, /^2/);
get("processNext").emit("click");
assert.equal(get("processListBody").children.length, 3);
assert.equal(get("processNext").disabled, true);
context.resources.processes = context.resources.processes.slice(0, 1);
context.resources.cpu.usage_percent = 42.5;
context.resources.interval_seconds = 15;
context.resources.errors = [];
vm.runInContext("renderResources(resources)", context);
assert.equal(get("processListBody").children.length, 1);
assert.match(get("processPage").textContent, /^1/);
assert.match(flatten(get("resourceCards")), /42.5%/);
assert.equal(get("resourceWarnings").classList.contains("hidden"), true);
vm.runInContext("renderResources(null)", context);
assert.equal(get("resourceOverview").classList.contains("hidden"), true);
assert.equal(get("resourceDetails").classList.contains("hidden"), true);
`

const managedStatusBehaviorTest = `
vm.runInContext("renderManagedStatus(null)", context);
assert.equal(get("managedOverview").classList.contains("hidden"), true);
vm.runInContext("renderManagedStatus({enrolled:false})", context);
assert.equal(get("managedOverview").classList.contains("hidden"), false);
assert.equal(get("managedCards").classList.contains("hidden"), true);
assert.equal(get("managedBadge").textContent, "단독 운영");
context.managed = {
  enrolled:true, agent_id:"<img src=x onerror=alert(1)>", central_url:"https://central.example",
  last_contact_at:new Date().toISOString(), last_error:"",
  delivery:{pending:3,lost_records:0}, policy:{active_revision:4,desired_revision:5,result:"rejected",error:"<script>alert(1)</script>"},
};
vm.runInContext("renderManagedStatus(managed)", context);
assert.equal(get("managedCards").classList.contains("hidden"), false);
assert.equal(get("managedCards").children.length, 3);
assert.equal(get("managedBadge").textContent, "연결 정상");
assert.doesNotMatch(get("managedIdentity").textContent, /<img|https:/);
assert.match(flatten(get("managedCards")), /3건/);
assert.match(flatten(get("managedCards")), /4번/);
assert.match(flatten(get("managedCards")), /적용 확인 필요/);
assert.doesNotMatch(flatten(get("managedCards")), /revision|rejected/);
assert.match(get("managedWarnings").textContent, /정책을 적용하지 못했습니다/);
assert.doesNotMatch(get("managedWarnings").textContent, /<script>/);
assert.match(flatten(get("managedTechnical")), /<img src=x onerror=alert\(1\)>/);
assert.match(flatten(get("managedTechnical")), /<script>alert\(1\)<\/script>/);
assert.match(flatten(get("managedTechnical")), /정책 요청 버전\s*5/);
assert.equal(get("managedTechnical").children[0].open,false);
get("managedTechnical").children[0].open=true;
context.managed.last_error = "offline";
vm.runInContext("renderManagedStatus(managed)", context);
assert.equal(get("managedBadge").textContent, "전송 확인 필요");
assert.match(get("managedWarnings").textContent, /전송 상태를 확인/);
assert.doesNotMatch(get("managedWarnings").textContent, /offline/);
assert.match(flatten(get("managedTechnical")), /offline/);
assert.equal(get("managedTechnical").children[0].open,true,"poll refresh preserves technical-detail expansion");
context.managed.last_error = "";
context.managed.policy.error = "";
context.managed.last_contact_at = "2020-01-01T00:00:00Z";
vm.runInContext("renderManagedStatus(managed)", context);
assert.equal(get("managedBadge").textContent, "연결 확인 필요");
assert.equal(get("managedWarnings").classList.contains("hidden"), true);
context.managed.delivery.lost_records = 1;
vm.runInContext("renderManagedStatus(managed)", context);
assert.equal(get("managedBadge").textContent, "이력 손실 있음");
`

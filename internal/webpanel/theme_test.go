package webpanel

import (
	"os/exec"
	"strings"
	"testing"
)

func TestThemeSelectionPersistenceAndStorageFailure(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is not installed; theme behavior test skipped")
	}
	script, err := assets.ReadFile("assets/theme.js")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(node, "-e", themeBehaviorTest)
	command.Stdin = strings.NewReader(string(script))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("theme behavior: %v\n%s", err, output)
	}
}

const themeBehaviorTest = `
const assert = require("node:assert/strict");
const vm = require("node:vm");
const source = require("node:fs").readFileSync(0, "utf8");

function page(options = {}) {
  let stored = options.stored ?? null;
  const writes = [], events = new Map();
  const buttons = Array.from({length: options.buttons ?? 2}, () => ({
    attributes: {}, click: null,
    setAttribute(name, value) { this.attributes[name] = value; },
    addEventListener(name, handler) { assert.equal(name, "click"); this.click = handler; },
  }));
  const document = {
    readyState: options.ready ?? "loading", documentElement: {dataset: {}},
    querySelectorAll(selector) { assert.equal(selector, "[data-theme-toggle]"); return buttons; },
    addEventListener(name, callback, config) { assert.equal(name, "DOMContentLoaded"); assert.equal(config.once, true); events.set(name, callback); },
  };
  const sandbox = {
    document,
    // Explicit light is the product default even for a dark OS preference.
    matchMedia() { throw new Error("The OS theme must not override the product default"); },
  };
  sandbox.window = sandbox;
  Object.defineProperty(sandbox, "localStorage", {get() {
    if (options.denied) throw new Error("Storage access denied");
    return {
      getItem(key) { assert.equal(key, "xeas-theme"); return stored; },
      setItem(key, value) {
        assert.equal(key, "xeas-theme");
        if (options.writeDenied) throw new Error("Storage writes denied");
        writes.push(value); stored = value;
      },
    };
  }});
  vm.runInNewContext(source, sandbox);
  return {document, buttons, writes, stored: () => stored,
    ready() { if (events.has("DOMContentLoaded")) events.get("DOMContentLoaded")(); },
  };
}

for (const stored of [undefined, null, "", "auto", "DARK", "<script>", "dark "]) {
  const p = page({stored});
  assert.equal(p.document.documentElement.dataset.theme, "light");
  assert.equal(p.buttons[0].click, null, "head execution must wait for the body controls");
  p.ready();
  for (const button of p.buttons) assert.equal(button.attributes["aria-pressed"], "false");
  assert.deepEqual(p.writes, [], "reading a preference must not rewrite it");
}

for (const theme of ["light", "dark"]) {
  const p = page({stored: theme});
  assert.equal(p.document.documentElement.dataset.theme, theme, "apply the preference before DOMContentLoaded");
  p.ready();
  for (const button of p.buttons) assert.equal(button.attributes["aria-pressed"], String(theme === "dark"));
}

const p = page(); p.ready();
p.buttons[0].click();
assert.equal(p.document.documentElement.dataset.theme, "dark");
assert.equal(p.stored(), "dark");
for (const button of p.buttons) assert.equal(button.attributes["aria-pressed"], "true");
p.buttons[1].click();
assert.equal(p.document.documentElement.dataset.theme, "light");
assert.equal(p.stored(), "light");
for (const button of p.buttons) assert.equal(button.attributes["aria-pressed"], "false");
assert.deepEqual(p.writes, ["dark", "light"]);

for (const options of [{denied: true}, {writeDenied: true}]) {
  const p = page(options); p.ready();
  assert.equal(p.document.documentElement.dataset.theme, "light");
  assert.doesNotThrow(() => p.buttons[0].click());
  assert.equal(p.document.documentElement.dataset.theme, "dark");
  assert.equal(p.buttons[1].attributes["aria-pressed"], "true");
}

const readyPage = page({stored:"dark", ready:"interactive", buttons:1});
assert.equal(readyPage.buttons[0].attributes["aria-pressed"], "true");
readyPage.buttons[0].click();
assert.equal(readyPage.document.documentElement.dataset.theme, "light");
assert.doesNotThrow(() => page({ready:"complete", buttons:0}));
`

const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

test("Linux persistence source is literal folded JSON and cannot survive another selection", () => {
  const source = fs.readFileSync(path.join(__dirname, "../static/app.js"), "utf8");
  const start = source.indexOf("function renderPersistenceDetail(data) {");
  const end = source.indexOf("function renderFullPersistenceActions(", start);
  assert.ok(start >= 0 && end > start);
  class Element {
    constructor(tag) {
      this.tag = tag;
      this.children = [];
      Object.defineProperty(this, "innerHTML", { set() { throw new Error("unsafe evidence HTML"); } });
    }
    appendChild(child) { this.children.push(child); }
    replaceChildren() { this.children = []; }
  }
  const container = new Element("div");
  const context = {
    byId: () => container,
    document: { createElement: tag => new Element(tag) },
    appendEvidenceDetailField: () => {},
    renderPersistenceRelatedFiles: () => {},
    renderFullPersistenceActions: () => {},
  };
  vm.createContext(context);
  vm.runInContext(source.slice(start, end), context);
  const artifact = { path: "/etc/cron.d/<script>bad()</script>", uid: 0, content: "IyByYXcA/w==", read_error: "<img onerror=bad()>" };
  const config = { status: "partial", activation: "unknown", directives: [{ value: "<script>bad()</script>" }] };
  const merges = [{ unit: "worker@east.service", profile: "observed-system-service-v2", name_kind: "instance", template: "worker@.service", instance: "east", base_lookup: "template_fallback", status: "observed_subset", activation: "unknown", warnings: ["<script>bad()</script>"], settings: [{ key: "ExecStart", values: [{ value: "/bin/worker %i %I" }] }] }];
  context.renderPersistenceDetail({ item: { title: "Linux candidate" }, linux_artifact: artifact, linux_config: config, linux_systemd_merges: merges });
  const raw = container.children.find(child => child.tag === "details");
  assert.ok(raw);
  assert.notEqual(raw.open, true);
  assert.match(raw.children[0].textContent, /Base64; activation unknown/);
  assert.deepEqual(JSON.parse(raw.children[1].textContent), artifact);
  const parsed = container.children.filter(child => child.tag === "details")[1];
  assert.match(parsed.children[0].textContent, /activation\/execution unknown/);
  assert.deepEqual(JSON.parse(parsed.children[1].textContent), config);
  const merged = container.children.filter(child => child.tag === "details")[2];
  assert.match(merged.children[0].textContent, /not actual effective\/runtime/);
  assert.deepEqual(JSON.parse(merged.children[1].textContent), merges);
  context.renderPersistenceDetail({ item: { title: "Windows service" } });
  assert.equal(container.children.some(child => child.tag === "details"), false);
});

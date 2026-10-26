const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../static/multi-host.js"), "utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
const treeText = element => [element.textContent, ...(element.children || []).map(treeText)].join(" ");
const views = [
  { case_id: "case", host_id: "alpha", version: "1" },
  { case_id: "case", host_id: "beta", version: "2" },
];

function fixture(initialURL = "http://localhost/#/") {
  const elements = new Map();
  class Element {
    constructor(tagName = "div") {
      this.tagName = tagName;
      Object.defineProperty(this, "innerHTML", { set() { throw new Error("Evidence must be rendered as text"); } });
      this.listeners = {}; this.children = []; this.value = "";
      this.disabled = false; this.textContent = "";
      this.classList = { remove: () => {} };
    }
    set id(value) { elements.set(value, this); }
    append(...values) { this.children.push(...values); }
    appendChild(value) { this.append(value); }
    replaceChildren() { this.children = []; this.textContent = ""; }
    addEventListener(name, handler) { (this.listeners[name] ||= []).push(handler); }
    emit(name, event = {}) { for (const handler of this.listeners[name] || []) handler(event); }
  }
  for (const id of ["panel", "views", "query", "category", "order", "search", "timeline", "prev", "next", "results", "detail", "status", "counts", "summary", "user", "pid", "ip", "from", "to", "type", "reset", "copy-link", "link"]) {
    const element = new Element(); element.id = `multi-host-${id}`;
  }
  const el = id => elements.get(`multi-host-${id}`);
  el("order").value = "desc";
  const requests = [];
  const response = (data, status = 200) => ({ ok: status === 200, status, headers: { get: () => "application/json" }, json: async () => data });
  const fetch = async (url, options) => {
    if (url.endsWith("/views")) return response({ views });
    return new Promise(resolve => requests.push({ url, options, body: JSON.parse(options.body), resolve: (data, status) => resolve(response(data, status)) }));
  };
  const location = { href: initialURL };
  const window = { location, history: { state: null, replaceState: (_, unused, url) => { location.href = url; } } };
  vm.runInNewContext(source, {
    document: { getElementById: id => elements.get(id), createElement: tag => new Element(tag), createTextNode: text => ({ textContent: text }) },
    fetch, AbortController, console, URL, window,
    navigator: { clipboard: { writeText: async () => {} } },
  });
  return { el, requests, location };
}

test("search retains per-host identity, unknown time and selected view scope", async () => {
  const { el, requests } = fixture(); await tick();
  el("query").value = "needle"; el("search").emit("click"); await tick();
  assert.equal(requests[0].body.views.length, 2);
  requests[0].resolve({ total: 2, results: views.map(view => ({ view, result: { type: "process", id: "process:42", title: "needle", timestamp: "0001-01-01T00:00:00Z" } })) });
  await tick();
  assert.equal(el("results").children.length, 2);
  assert.match(el("results").children[0].textContent, /alpha.*Time unknown/);
  el("results").children[1].emit("click");
  await tick();
  assert.equal(requests[1].url, "/api/multi-host/evidence/detail");
  assert.equal(requests[1].body.view.host_id, "beta");
  requests[1].resolve({ view: views[1], evidence: { pid: 42, name: "needle" } }); await tick();
  assert.match(treeText(el("detail")), /beta/);
  assert.match(treeText(el("detail")), /Evidence fields/);
  el("view-0").checked = false; el("view-0").emit("change");
  assert.equal(el("results").children.length, 0);
  el("search").emit("click"); await tick();
  assert.equal(requests[2].body.views.length, 1);
  assert.equal(requests[2].body.views[0].host_id, "beta");
});

test("Timeline sends global offsets and follows server has_more", async () => {
  const { el, requests } = fixture(); await tick();
  el("timeline").emit("click"); await tick();
  assert.equal(requests[0].body.offset, 0);
  requests[0].resolve({ total: 104, offset: 0, has_more: true, events: [] }); await tick();
  assert.equal(el("next").disabled, false);
  el("next").emit("click"); await tick();
  assert.equal(requests[1].body.offset, 50);
  requests[1].resolve({ total: 104, offset: 50, has_more: true, events: [] }); await tick();
  assert.equal(el("prev").disabled, false);
  el("prev").emit("click"); await tick();
  assert.equal(requests[2].body.offset, 0);
});

test("typing invalidates in-flight results even when backend ignores cancellation", async () => {
  const { el, requests } = fixture(); await tick();
  el("query").value = "old"; el("search").emit("click"); await tick();
  el("query").value = "new"; el("query").emit("input");
  assert.equal(requests[0].options.signal.aborted, true);
  requests[0].resolve({ total: 1, results: [{ view: views[0], result: { id: "old" } }] }); await tick();
  assert.equal(el("results").children.length, 0);
  assert.match(el("status").textContent, /Selection changed/);
});

test("no selected views blocks queries and clears source details", async () => {
  const { el, requests } = fixture(); await tick();
  el("view-0").checked = false; el("view-1").checked = false;
  el("timeline").emit("click"); await tick();
  assert.equal(requests.length, 0);
  assert.match(el("status").textContent, /Select at least one/);
});

test("Timeline submits filters and UTC time range; category counts remain server totals", async () => {
  const { el, requests } = fixture(); await tick();
  el("user").value = " alice "; el("pid").value = "42"; el("ip").value = "10.0.0.1";
  el("from").value = "2026-01-01T10:00"; el("to").value = "2026-01-02T10:00";
  el("timeline").emit("click"); await tick();
  const body = requests[0].body;
  assert.equal(body.user, "alice"); assert.equal(body.pid, 42); assert.equal(body.ip, "10.0.0.1");
  assert.equal(body.from, new Date("2026-01-01T10:00").toISOString());
  assert.equal(body.to, new Date("2026-01-02T10:00").toISOString());
  requests[0].resolve({ total: 20, offset: 0, events: [], category_counts: { process: 15, login: 5 }, by_view: [{ view: views[0], total: 20, category_counts: { process: 15, login: 5 } }] }); await tick();
  assert.match(el("counts").children[0].textContent, /process: 15/);
  assert.match(el("summary").children[1].textContent, /alpha.*20 matches/);
  el("counts").children[1].emit("click"); await tick();
  assert.equal(requests[1].body.category, "login"); assert.equal(requests[1].body.offset, 0);
});

test("invalid PID or reversed range makes no request; reset preserves selected hosts", async () => {
  const { el, requests } = fixture(); await tick();
  el("pid").value = "4294967296"; el("timeline").emit("click"); await tick();
  assert.equal(requests.length, 0); assert.match(el("status").textContent, /PID/);
  el("pid").value = ""; el("from").value = "2026-01-02T10:00"; el("to").value = "2026-01-01T10:00";
  el("timeline").emit("click"); await tick();
  assert.equal(requests.length, 0); assert.match(el("status").textContent, /From time/);
  el("view-0").checked = false; el("reset").emit("click");
  assert.equal(el("from").value, ""); assert.equal(el("view-0").checked, false);
});

test("Search submits evidence type without Timeline-only filters", async () => {
  const { el, requests } = fixture(); await tick();
  el("query").value = "needle"; el("type").value = "process"; el("pid").value = "invalid";
  el("search").emit("click"); await tick();
  assert.deepEqual(requests[0].body.types, ["process"]);
  assert.equal(requests[0].body.pid, undefined);
  requests[0].resolve({ total: 7, results: [], by_type: { process: 7 }, by_view: [{ view: views[1], total: 7, by_type: { process: 7 } }] }); await tick();
  assert.match(el("counts").children[0].textContent, /process: 7/);
  assert.match(el("summary").children[1].textContent, /beta.*7 matches/);
});

test("late source detail cannot reappear after host selection changes", async () => {
  const { el, requests } = fixture(); await tick();
  el("query").value = "needle"; el("search").emit("click"); await tick();
  requests[0].resolve({ total: 1, results: [{ view: views[1], result: { type: "process", id: "process:42" } }] }); await tick();
  el("results").children[0].emit("click"); await tick();
  el("view-1").checked = false; el("view-1").emit("change");
  assert.equal(requests[1].options.signal.aborted, true);
  requests[1].resolve({ view: views[1], evidence: { name: "late" } }); await tick();
  assert.equal(el("detail").textContent, "");
  assert.equal(el("link").value, "");
});

test("successful investigation link restores exact host versions and query after refresh", async () => {
  const first = fixture(); await tick();
  first.el("query").value = "needle"; first.el("type").value = "process";
  first.el("view-0").checked = false;
  first.el("search").emit("click"); await tick();
  first.requests[0].resolve({ total: 0, results: [] }); await tick();
  assert.equal(first.el("copy-link").disabled, false);
  const second = fixture(first.el("link").value); await tick();
  assert.equal(second.requests.length, 1);
  assert.deepEqual(second.requests[0].body, first.requests[0].body);
  assert.equal(second.el("view-0").checked, false);
  assert.equal(second.el("view-1").checked, true);
});

test("saved Timeline offset and UTC range survive local date restoration", async () => {
  const url = new URL("http://localhost/?unrelated=value#/timeline");
  const body = { views, query: "", limit: 50, offset: 50, order: "asc", from: "2026-01-01T00:00:00.123Z", to: "2026-01-02T00:00:00.123Z", category: "process", user: "alice", pid: 42, ip: "10.0.0.1" };
  url.searchParams.set("multi_host", JSON.stringify({ version: 1, mode: "timeline", query: body }));
  const { requests, el, location } = fixture(url.href); await tick();
  assert.deepEqual(requests[0].body, body);
  requests[0].resolve({ total: 104, offset: 50, has_more: true, events: [] }); await tick();
  const saved = new URL(location.href);
  assert.equal(saved.searchParams.get("unrelated"), "value");
  assert.equal(saved.hash, "#/timeline");
  assert.equal(JSON.parse(saved.searchParams.get("multi_host")).query.offset, 50);
  el("query").emit("input");
  assert.equal(new URL(location.href).searchParams.has("multi_host"), false);
  assert.equal(el("copy-link").disabled, true);
});

test("missing published version and malformed links cannot silently broaden host scope", async () => {
  for (const raw of ["bad JSON", JSON.stringify({ version: 1, mode: "search", query: { views: [{ ...views[1], version: "missing" }], query: "needle", limit: 50 } })]) {
    const url = new URL("http://localhost/"); url.searchParams.set("multi_host", raw);
    const { requests, el } = fixture(url.href); await tick();
    assert.equal(requests.length, 0);
    assert.equal(el("copy-link").disabled, true);
    assert.ok(el("status").textContent.length > 0);
  }
});

test("structured details preserve scalar and nested evidence with literal text and folded raw JSON", async () => {
  const { el, requests } = fixture(); await tick();
  el("query").value = "needle"; el("search").emit("click"); await tick();
  requests[0].resolve({ total: 1, results: [{ view: views[1], result: { type: "process", id: "process:42" } }] }); await tick();
  el("results").children[0].emit("click"); await tick();
  const detail = { view: views[1], type: "process", id: "process:42", evidence: {
    name: "<script>alert(1)</script>", pid: 42, ppid: 0, signed: false,
    start_time: "0001-01-01T00:00:00Z", command_line: "line one\nline two",
    metadata: { source: "fixture" }, related_ids: ["event:1", "event:2"], empty: null,
  } };
  requests[1].resolve(detail); await tick();
  const text = treeText(el("detail"));
  for (const expected of ["Case ID", "beta", "process:42", "PPID", "false", "Time unknown", "Item 1", "event:2", "fixture", "<script>alert(1)</script>", "line one\nline two"]) assert.ok(text.includes(expected), expected);
  const raw = el("detail").children.find(child => child.tagName === "details");
  assert.ok(raw); assert.notEqual(raw.open, true);
  assert.deepEqual(JSON.parse(raw.children[1].textContent), detail);
});

test("detail errors retain source-labelled result preview", async () => {
  const { el, requests } = fixture(); await tick();
  el("query").value = "needle"; el("search").emit("click"); await tick();
  requests[0].resolve({ total: 1, results: [{ view: views[0], result: { type: "process", id: "process:42", title: "preview" } }] }); await tick();
  el("results").children[0].emit("click"); await tick();
  requests[1].resolve({ error: "evidence not found" }, 404); await tick();
  const text = treeText(el("detail"));
  assert.match(text, /alpha/); assert.match(text, /Result preview/);
  assert.match(text, /Source evidence unavailable: evidence not found/);
  assert.match(text, /process:42/);
  assert.equal(JSON.parse(new URL(el("link").value).searchParams.get("multi_host")).detail, undefined);
});

test("evidence link restores exact source even outside the restored result page", async () => {
  const first = fixture(); await tick();
  first.el("query").value = "needle"; first.el("search").emit("click"); await tick();
  first.requests[0].resolve({ total: 1, results: [{ view: views[1], result: { type: "process", id: "process:42" } }] }); await tick();
  first.el("results").children[0].emit("click"); await tick();
  first.requests[1].resolve({ view: views[1], type: "process", id: "process:42", evidence: { name: "beta.exe" } }); await tick();
  const link = first.el("link").value;
  const saved = JSON.parse(new URL(link).searchParams.get("multi_host"));
  assert.deepEqual(saved.detail, { view: views[1], type: "process", id: "process:42" });
  const second = fixture(link); await tick();
  second.requests[0].resolve({ total: 80, results: [] }); await tick();
  assert.equal(second.requests[1].url, "/api/multi-host/evidence/detail");
  assert.deepEqual(second.requests[1].body, saved.detail);
  second.requests[1].resolve({ view: views[1], type: "process", id: "process:42", evidence: { name: "beta.exe" } }); await tick();
  assert.match(treeText(second.el("detail")), /beta.exe/);
});

test("evidence link rejects a detail from an unselected host before issuing requests", async () => {
  const url = new URL("http://localhost/");
  url.searchParams.set("multi_host", JSON.stringify({ version: 1, mode: "search", query: { views: [views[0]], query: "needle", limit: 50 }, detail: { view: views[1], type: "process", id: "process:42" } }));
  const { requests, el } = fixture(url.href); await tick();
  assert.equal(requests.length, 0);
  assert.match(el("status").textContent, /Invalid source evidence/);
});

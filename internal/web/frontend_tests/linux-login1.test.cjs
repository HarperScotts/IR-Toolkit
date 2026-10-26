const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function harness() {
  class Element {
    constructor(tag) { this.tag = tag; this.children = []; this.events = {}; this.classList = { add() {}, remove() {} }; }
    set innerHTML(_) { throw new Error("unsafe HTML"); }
    set textContent(value) { this.content = value; this.children = []; }
    get textContent() { return this.content; }
    replaceChildren(...children) { this.children = children; this.content = ""; }
    appendChild(child) { this.children.push(child); }
    addEventListener(type, handler) { this.events[type] = handler; }
    scrollIntoView() {}
  }
  const elements = new Map();
  const get = id => { if (!elements.has(id)) elements.set(id, new Element("div")); return elements.get(id); };
  const requests = [], timers = [];
  const fields = new Map([["active", "false"]]);
  const context = {
    document: { getElementById: get, createElement: tag => new Element(tag) }, AbortController, URLSearchParams,
    FormData: class { constructor() { return fields; } }, setTimeout: fn => timers.push(fn),
    fetch: (url, options) => new Promise(resolve => requests.push({ url, options, resolve })),
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../static/linux-login1.js"), "utf8"), context);
  const settle = async (index, data, status = 200) => {
    requests[index].resolve({ ok: status === 200, status, json: async () => data });
    await new Promise(resolve => setImmediate(resolve));
  };
  return { get, requests, timers, fields, settle, click: id => get(id).events.click() };
}
const record = { id: "linux-login1:a", session: { session_id: "s1", reported_user: "<img onerror=bad()>" }, properties: { active: false, remote: null, reported_leader_pid: 0, tty: "", state: null, reported_creation_usec: "18446744073709551615" }, property_status: "partial", source_call: { content: "e30=" }, warnings: ["<script>warning</script>"] };

test("login1 page distinguishes false/zero/empty/unknown and renders evidence literally", async () => {
  const h = harness(); h.click("open-linux-login1");
  assert.match(h.requests[0].url, /^\/api\/linux-login1\?/);
  assert.match(h.requests[0].url, /active=false/);
  await h.settle(0, { total: 2, records: [record], coverage: { status: "partial" }, scope: "not identities" });
  const button = h.get("linux-login1-list").children[0];
  assert.match(button.textContent, /Active false/); assert.match(button.textContent, /State Unknown/); assert.match(button.textContent, /<img onerror/);
  button.events.click();
  await h.settle(1, { record, scope: "source claims" });
  const summary = h.get("linux-login1-detail").children[1].textContent;
  assert.match(summary, /active: false/); assert.match(summary, /remote: Unknown/); assert.match(summary, /reported_leader_pid: 0/); assert.match(summary, /tty: ""/);
  assert.match(summary, /reported_creation_usec: "18446744073709551615"/);
  const raw = h.get("linux-login1-detail").children[2];
  assert.equal(raw.tag, "details"); assert.notEqual(raw.open, true);
  assert.deepEqual(JSON.parse(raw.children[1].textContent), record);
});

test("login1 page invalidates stale responses and clears failures/pagination", async () => {
  const h = harness(); h.click("open-linux-login1");
  h.get("linux-login1-form").events.submit({ preventDefault() {} });
  assert.equal(h.requests[0].options.signal.aborted, true);
  await h.settle(1, { total: 26, records: [record], has_more: true });
  await h.settle(0, { total: 999, records: [] });
  assert.match(h.get("linux-login1-status").textContent, /^26 matching/);
  h.get("linux-login1-list").children[0].events.click();
  h.click("linux-login1-next");
  assert.match(h.requests[3].url, /offset=25/);
  assert.equal(h.requests[2].options.signal.aborted, true);
  await h.settle(2, { record, scope: "stale" });
  assert.equal(h.get("linux-login1-detail").children.length, 0);
  await h.settle(3, {}, 500);
  assert.match(h.get("linux-login1-status").textContent, /500/);
  assert.equal(h.get("linux-login1-list").children.length, 0);
  assert.equal(h.get("linux-login1-next").disabled, true);
  h.click("open-linux-login1");
  h.click("close-linux-login1");
  await h.settle(4, { total: 999, records: [record] });
  assert.equal(h.get("linux-login1-list").children.length, 0);
});

test("login1 reset cannot start a hidden request after closing", async () => {
  const h = harness(); h.click("open-linux-login1");
  await h.settle(0, { total: 0, records: [] });
  assert.match(h.get("linux-login1-list").textContent, /does not prove/);
  h.get("linux-login1-form").events.reset();
  h.click("close-linux-login1");
  h.timers.shift()();
  assert.equal(h.requests.length, 1);
});

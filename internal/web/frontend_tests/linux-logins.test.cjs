const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function harness() {
  class Element {
    constructor() { this.children = []; this.events = {}; this.classList = { add() {}, remove() {} }; }
    set innerHTML(_) { throw new Error("unsafe HTML"); }
    set textContent(value) { this.content = value; this.children = []; }
    get textContent() { return this.content; }
    replaceChildren(...children) { this.children = children; this.content = ""; }
    appendChild(child) { this.children.push(child); }
    addEventListener(type, handler) { this.events[type] = handler; }
    scrollIntoView() {}
  }
  const elements = new Map();
  const get = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const requests = [];
  const timers = [];
  const fields = new Map([["since", "2026-10-17T00:00:00+08:00"], ["unknown_time", "include"]]);
  const context = {
    document: { getElementById: get, createElement: () => new Element() },
    AbortController, URLSearchParams,
    FormData: class { constructor() { return fields; } },
    setTimeout: fn => timers.push(fn),
    fetch: (url, options) => new Promise(resolve => requests.push({ url, options, resolve })),
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../static/linux-logins.js"), "utf8"), context);
  const click = id => get(id).events.click();
  const settle = async (index, data, status = 200) => {
    requests[index].resolve({ ok: status === 200, status, json: async () => data });
    await new Promise(resolve => setImmediate(resolve));
  };
  return { get, requests, timers, fields, click, settle };
}
const record = { id: "linux-login:a", time_basis: "unknown", timestamp_raw: "Oct 17 12:00:00", user: "<img onerror=bad()>", outcome: "failed", source_path: "/var/log/auth.log", line: 1, raw_line: "<script>bad()</script>" };

test("native login page preserves literal evidence, query policy, pagination and reset", async () => {
  const h = harness();
  h.click("open-linux-logins");
  const params = new URL(h.requests[0].url, "http://localhost").searchParams;
  assert.equal(params.get("since"), "2026-10-17T00:00:00+08:00");
  assert.equal(params.get("unknown_time"), "include");
  await h.settle(0, { total: 101, has_more: true, records: [record], scope: "context only", sources: [{ status: "partial", warnings: ["<script>coverage</script>"] }] });
  assert.match(h.get("linux-login-coverage").textContent, /partial/);
  assert.match(h.get("linux-login-coverage").textContent, /<script>coverage/);
  const button = h.get("linux-login-list").children[0];
  assert.match(button.textContent, /Unknown time/);
  assert.match(button.textContent, /<img onerror/);
  button.events.click();
  assert.match(h.requests[1].url, /detail\?id=linux-login%3Aa/);
  await h.settle(1, { record, scope: "not a confirmed process" });
  assert.deepEqual(JSON.parse(h.get("linux-login-detail").children[1].textContent), record);
  h.click("linux-login-next");
  assert.equal(h.get("linux-login-coverage").textContent, "");
  assert.match(h.requests[2].url, /offset=100/);
  assert.equal(h.get("linux-login-detail").children.length, 0);
  await h.settle(2, { total: 101, records: [record] });
  assert.equal(h.get("linux-login-next").disabled, true);
  h.fields.clear();
  h.get("linux-login-form").events.reset();
  h.timers.shift()();
  assert.match(h.requests[3].url, /offset=0/);
  await h.settle(3, { total: 0, records: [] });
  assert.match(h.get("linux-login-list").textContent, /does not establish absence/);
});

test("native workspace rejects stale list/detail responses, clears failures and cancels close", async () => {
  const h = harness();
  h.click("open-linux-logins");
  h.get("linux-login-form").events.submit({ preventDefault() {} });
  assert.equal(h.requests[0].options.signal.aborted, true);
  await h.settle(1, { total: 1, records: [record] });
  await h.settle(0, { total: 999, records: [] });
  assert.match(h.get("linux-login-status").textContent, /^1 matching/);
  h.get("linux-login-list").children[0].events.click();
  h.get("linux-login-form").events.submit({ preventDefault() {} });
  assert.equal(h.requests[2].options.signal.aborted, true);
  await h.settle(2, { record, scope: "stale" });
  assert.equal(h.get("linux-login-detail").children.length, 0);
  await h.settle(3, {}, 500);
  assert.match(h.get("linux-login-status").textContent, /500/);
  assert.equal(h.get("linux-login-list").children.length, 0);
  assert.equal(h.get("linux-login-next").disabled, true);
  h.click("open-linux-logins");
  h.click("close-linux-logins");
  assert.equal(h.requests[4].options.signal.aborted, true);
  await h.settle(4, { total: 999, records: [record] });
  assert.equal(h.get("linux-login-list").children.length, 0);
});

/* login1 claims remain independent from SSH/Windows/process workspaces. */
(() => {
  const el = id => document.getElementById(`linux-login1-${id}`);
  const form = el("form");
  const value = v => v === null || v === undefined ? "Unknown" : JSON.stringify(v);
  let offset = 0, more = false, epoch = 0, detailEpoch = 0, opened = false;
  let listController, detailController;
  function clearDetail() {
    ++detailEpoch;
    detailController?.abort();
    el("detail").replaceChildren();
  }
  async function json(url, signal) {
    const response = await fetch(url, { signal });
    if (!response.ok) throw new Error(`Request failed (${response.status})`);
    return response.json();
  }
  async function select(id) {
    clearDetail();
    const token = detailEpoch;
    detailController = new AbortController();
    el("detail").textContent = "Loading saved evidence…";
    try {
      const data = await json(`/api/linux-login1/detail?id=${encodeURIComponent(id)}`, detailController.signal);
      if (token !== detailEpoch) return;
      const note = document.createElement("p"); note.textContent = data.scope;
      const properties = data.record.properties || {};
      const summary = document.createElement("pre");
      summary.textContent = Object.entries(properties).map(([name, v]) => `${name}: ${value(v)}`).join("\n");
      const raw = document.createElement("details");
      const heading = document.createElement("summary"); heading.textContent = "Evidence provenance, warnings and original busctl bytes (Base64)";
      const pre = document.createElement("pre"); pre.textContent = JSON.stringify(data.record, null, 2);
      raw.appendChild(heading); raw.appendChild(pre);
      el("detail").replaceChildren(note, summary, raw);
    } catch (error) {
      if (token === detailEpoch && error.name !== "AbortError") el("detail").textContent = error.message;
    }
  }
  async function load() {
    const token = ++epoch;
    listController?.abort(); listController = new AbortController();
    clearDetail(); more = false;
    el("list").replaceChildren(); el("coverage").textContent = "";
    el("prev").disabled = true; el("next").disabled = true;
    el("status").textContent = "Loading saved observations…";
    const params = new URLSearchParams(new FormData(form));
    params.set("offset", String(offset)); params.set("limit", "25");
    try {
      const data = await json(`/api/linux-login1?${params}`, listController.signal);
      if (token !== epoch) return;
      more = Boolean(data.has_more);
      el("coverage").textContent = JSON.stringify(data.coverage || {}, null, 2);
      el("status").textContent = `${data.total} matching service observations. ${data.scope}`;
      for (const item of data.records || []) {
        const button = document.createElement("button"); button.type = "button"; button.className = "login-list-item";
        button.textContent = `${item.session.session_id} · ${item.session.reported_user} · State ${value(item.properties.state)} · Active ${value(item.properties.active)} · ${item.property_status}`;
        button.addEventListener("click", () => select(item.id)); el("list").appendChild(button);
      }
      if (!(data.records || []).length) el("list").textContent = "No matching saved observations; consult coverage. This does not prove no sessions or activity.";
      el("prev").disabled = offset === 0; el("next").disabled = !more;
    } catch (error) {
      if (token === epoch && error.name !== "AbortError") el("status").textContent = error.message;
    }
  }
  document.getElementById("open-linux-login1").addEventListener("click", () => {
    opened = true; offset = 0; el("section").classList.remove("hidden"); load(); el("section").scrollIntoView({ block: "start" });
  });
  form.addEventListener("submit", event => { event.preventDefault(); offset = 0; load(); });
  form.addEventListener("reset", () => {
    const token = ++epoch; listController?.abort(); clearDetail();
    setTimeout(() => { if (opened && token === epoch) { offset = 0; load(); } }, 0);
  });
  el("prev").addEventListener("click", () => { offset = Math.max(0, offset - 25); load(); });
  el("next").addEventListener("click", () => { if (more) { offset += 25; load(); } });
  document.getElementById("close-linux-login1").addEventListener("click", () => {
    opened = false; ++epoch; listController?.abort(); clearDetail(); el("section").classList.add("hidden");
  });
})();

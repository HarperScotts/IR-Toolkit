/* Separate native evidence workspace: never routes reported PIDs into process links. */
(() => {
  const el = id => document.getElementById(id);
  const form = el("linux-login-form");
  let offset = 0, hasMore = false, listSequence = 0, detailSequence = 0;
  let listController, detailController;
  function invalidateDetail() {
    ++detailSequence;
    detailController?.abort();
    el("linux-login-detail").replaceChildren();
  }
  async function json(url, signal) {
    const response = await fetch(url, { signal });
    if (!response.ok) throw new Error(`Request failed (${response.status})`);
    return response.json();
  }
  async function select(id) {
    invalidateDetail();
    const sequence = detailSequence;
    detailController = new AbortController();
    el("linux-login-detail").textContent = "Loading evidence…";
    try {
      const data = await json(`/api/linux-logins/detail?id=${encodeURIComponent(id)}`, detailController.signal);
      if (sequence !== detailSequence) return;
      const note = document.createElement("p");
      note.textContent = data.scope;
      const raw = document.createElement("pre");
      raw.textContent = JSON.stringify(data.record, null, 2);
      el("linux-login-detail").replaceChildren(note, raw);
    } catch (error) {
      if (sequence === detailSequence && error.name !== "AbortError") el("linux-login-detail").textContent = error.message;
    }
  }
  async function load() {
    const sequence = ++listSequence;
    listController?.abort();
    listController = new AbortController();
    invalidateDetail();
    hasMore = false;
    el("linux-login-prev").disabled = true;
    el("linux-login-next").disabled = true;
    el("linux-login-list").replaceChildren();
    el("linux-login-coverage").textContent = "";
    el("linux-login-status").textContent = "Loading evidence…";
    const params = new URLSearchParams(new FormData(form));
    params.set("offset", String(offset));
    params.set("limit", "100");
    try {
      const data = await json(`/api/linux-logins?${params}`, listController.signal);
      if (sequence !== listSequence) return;
      hasMore = Boolean(data.has_more);
      el("linux-login-coverage").textContent = JSON.stringify({ sources: data.sources || [], warnings: data.warnings || [] }, null, 2);
      const records = data.records || [];
      el("linux-login-status").textContent = `${data.total} matching reported outcomes; ${records.length ? offset + 1 : 0}–${offset + records.length}. ${data.scope}`;
      for (const record of records) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "login-list-item";
        const time = record.time_basis === "explicit_offset" ? record.timestamp : `Unknown time (${record.timestamp_raw || "unavailable"})`;
        button.textContent = `${time} · ${record.outcome} · ${record.user} · ${record.source_ip} · ${record.source_path}:${record.line}`;
        button.addEventListener("click", () => select(record.id));
        el("linux-login-list").appendChild(button);
      }
      if (!records.length) el("linux-login-list").textContent = "No matching supported records. This does not establish absence of authentication activity.";
      el("linux-login-prev").disabled = offset === 0;
      el("linux-login-next").disabled = !hasMore;
    } catch (error) {
      if (sequence === listSequence && error.name !== "AbortError") el("linux-login-status").textContent = error.message;
    }
  }
  el("open-linux-logins").addEventListener("click", () => {
    el("linux-login-section").classList.remove("hidden");
    offset = 0;
    load();
    el("linux-login-section").scrollIntoView({ block: "start" });
  });
  form.addEventListener("submit", event => { event.preventDefault(); offset = 0; load(); });
  form.addEventListener("reset", () => { setTimeout(() => { offset = 0; load(); }, 0); });
  el("linux-login-prev").addEventListener("click", () => { offset = Math.max(0, offset - 100); load(); });
  el("linux-login-next").addEventListener("click", () => { if (hasMore) { offset += 100; load(); } });
  el("close-linux-logins").addEventListener("click", () => {
    ++listSequence;
    listController?.abort();
    invalidateDetail();
    el("linux-login-section").classList.add("hidden");
  });
})();

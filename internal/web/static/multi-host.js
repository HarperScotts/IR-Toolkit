"use strict";

// The server owns aggregation, filtering, ordering and pagination. This panel
// displays scoped results without invoking single-host evidence navigation.
(() => {
  const el = (id) => document.getElementById(`multi-host-${id}`);
  const state = { views: [], mode: "search", offset: 0, limit: 50, controller: null, sequence: 0, detailController: null, detailSequence: 0, queryBody: null };

  function clearLink() {
    el("copy-link").disabled = true;
    el("link").value = "";
    const url = new URL(window.location.href);
    url.searchParams.delete("multi_host");
    window.history.replaceState(window.history.state, "", url.href);
  }

  function saveLink(body, detail) {
    const url = new URL(window.location.href);
    url.searchParams.set("multi_host", JSON.stringify({ version: 1, mode: state.mode, query: body, ...(detail ? { detail } : {}) }));
    window.history.replaceState(window.history.state, "", url.href);
    el("link").value = url.href;
    el("copy-link").disabled = false;
  }

  function localDateValue(value) {
    if (!value) return "";
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) throw new Error("Invalid saved time range.");
    const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
    return local.toISOString().slice(0, 23);
  }

  async function restoreLink() {
    const raw = new URL(window.location.href).searchParams.get("multi_host");
    if (!raw) return;
    try {
      const saved = JSON.parse(raw);
      const query = saved.query;
      if (saved.version !== 1 || !["search", "timeline"].includes(saved.mode) ||
          !query || !Array.isArray(query.views) || !query.views.length ||
          typeof query.query !== "string" || query.limit !== state.limit) {
        throw new Error("Invalid investigation link.");
      }
      const key = view => JSON.stringify([view.case_id, view.host_id, view.version]);
      const selected = new Set();
      for (const view of query.views) {
        if (!view || !state.views.some(available => key(available) === key(view))) {
          throw new Error("A host/version in this link is unavailable. Select the required published views and run the query again.");
        }
        if (selected.has(key(view))) throw new Error("Duplicate view in investigation link.");
        selected.add(key(view));
      }
      if (saved.mode === "timeline" && (!Number.isSafeInteger(query.offset) || query.offset < 0)) {
        throw new Error("Invalid saved Timeline page.");
      }
      const types = ["process", "login", "network", "file", "persistence", "historical_process", "powershell", "windows_event", "ioc", "timeline"];
      if (query.types && (!Array.isArray(query.types) || query.types.length !== 1 || !types.includes(query.types[0]))) {
        throw new Error("Invalid saved evidence type.");
      }
      if (saved.detail) {
        const detail = saved.detail;
        if (!detail.view || !selected.has(key(detail.view)) ||
            ![...types, "correlation_node", "correlation_edge"].includes(detail.type) ||
            typeof detail.id !== "string" || !detail.id) {
          throw new Error("Invalid source evidence in investigation link.");
        }
      }
      const from = localDateValue(query.from), to = localDateValue(query.to);
      state.views.forEach((view, index) => { el(`view-${index}`).checked = selected.has(key(view)); });
      el("query").value = query.query;
      for (const field of ["category", "user", "ip"]) el(field).value = typeof query[field] === "string" ? query[field] : "";
      el("pid").value = query.pid === undefined ? "" : String(query.pid);
      el("from").value = from; el("to").value = to;
      el("order").value = query.order === "asc" ? "asc" : "desc";
      el("type").value = Array.isArray(query.types) ? query.types[0] || "" : "";
      state.mode = saved.mode;
      state.offset = saved.mode === "timeline" ? query.offset : 0;
      const loaded = await run(false);
      if (loaded && saved.detail) {
        await loadDetail({ view: saved.detail.view, result: { type: saved.detail.type, id: saved.detail.id } });
      }
    } catch (error) {
      el("status").textContent = error.message;
      el("copy-link").disabled = true;
    }
  }

  function cancelDetail() {
    state.detailController?.abort();
    state.detailSequence++;
  }

  function invalidate() {
    state.queryBody = null;
    clearLink();
    cancelDetail();
    state.controller?.abort();
    state.sequence++;
    state.offset = 0;
    el("results").replaceChildren();
    el("counts").replaceChildren();
    el("summary").replaceChildren();
    el("detail").replaceChildren();
    el("prev").disabled = true;
    el("next").disabled = true;
    el("status").textContent = "Selection changed. Run Search or Timeline.";
  }

  async function run(reset = true) {
    state.queryBody = null;
    clearLink();
    cancelDetail();
    if (reset) state.offset = 0;
    state.controller?.abort();
    state.controller = new AbortController();
    const sequence = ++state.sequence;
    const views = state.views.filter((_, index) => el(`view-${index}`).checked);
    el("results").replaceChildren();
    el("counts").replaceChildren();
    el("summary").replaceChildren();
    el("detail").replaceChildren();
    el("prev").disabled = true;
    el("next").disabled = true;
    if (!views.length) {
      el("status").textContent = "Select at least one host view.";
      return;
    }
    if (new Set(views.map((view) => view.case_id)).size > 1) {
      el("status").textContent = "Select host views from one case.";
      return;
    }
    const body = { views, query: el("query").value.trim(), limit: state.limit };
    if (state.mode === "timeline") {
      Object.assign(body, { offset: state.offset, category: el("category").value.trim(), order: el("order").value });
      const rawPID = el("pid").value.trim();
      if (rawPID && (!/^\d+$/.test(rawPID) || Number(rawPID) > 4294967295)) {
        el("status").textContent = "PID must be an integer between 0 and 4294967295.";
        return;
      }
      if (rawPID) body.pid = Number(rawPID);
      for (const field of ["user", "ip"]) body[field] = el(field).value.trim();
      for (const field of ["from", "to"]) {
        const value = el(field).value;
        if (!value) continue;
        const date = new Date(value);
        if (!Number.isFinite(date.getTime())) {
          el("status").textContent = `Invalid ${field} time.`;
          return;
        }
        body[field] = date.toISOString();
      }
      if (body.from && body.to && body.from > body.to) {
        el("status").textContent = "From time must be before or equal to To time.";
        return;
      }
    } else if (!body.query) {
      el("status").textContent = "Enter a search query.";
      return;
    }
    if (state.mode === "search" && el("type").value) body.types = [el("type").value];
    el("status").textContent = "Loading…";
    try {
      const response = await fetch(`/api/multi-host/${state.mode}`, {
        method: "POST", cache: "no-store", signal: state.controller.signal,
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
      if (sequence !== state.sequence) return;
      const rows = state.mode === "timeline" ? data.events : data.results;
      el("status").textContent = `${data.total} matches · ${views.length} host views · ${rows.length} shown`;
      renderSummaries(data);
      for (const row of rows) {
        const item = row.event || row.result;
        const button = document.createElement("button");
        button.type = "button";
        button.className = "multi-host-result";
        const timestamp = item.timestamp && !item.timestamp.startsWith("0001-01-01")
          ? new Date(item.timestamp).toLocaleString() : "Time unknown";
        button.textContent = [row.view.host_id, row.view.version, timestamp, item.title || item.description || item.type, item.id].filter(Boolean).join(" · ");
        button.addEventListener("click", () => {
          loadDetail(row);
        });
        el("results").appendChild(button);
      }
      if (!rows.length) el("results").textContent = "No matching evidence.";
      if (state.mode === "timeline") {
        state.offset = data.offset;
        el("prev").disabled = state.offset === 0;
        el("next").disabled = !data.has_more;
      }
      state.queryBody = { ...body, ...(state.mode === "timeline" ? { offset: state.offset } : {}) };
      saveLink(state.queryBody);
      return true;
    } catch (error) {
      if (sequence === state.sequence && error.name !== "AbortError") el("status").textContent = error.message;
    }
  }

  async function loadDetail(row) {
    cancelDetail();
    const sequence = state.detailSequence;
    state.detailController = new AbortController();
    const item = row.event || row.result;
    const source = { view: row.view, type: row.event ? "timeline" : item.type, id: item.id };
    if (state.queryBody) saveLink(state.queryBody);
    renderDetail(row, "Loading source evidence…");
    try {
      const response = await fetch("/api/multi-host/evidence/detail", {
        method: "POST", cache: "no-store", signal: state.detailController.signal,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(source),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
      if (sequence === state.detailSequence) {
        renderDetail(data);
        if (state.queryBody) saveLink(state.queryBody, source);
      }
    } catch (error) {
      if (sequence === state.detailSequence && error.name !== "AbortError") {
        renderDetail(row, `Source evidence unavailable: ${error.message}`);
      }
    }
  }

  function fieldLabel(key) {
    const acronyms = new Set(["id", "pid", "ppid", "ip", "ioc", "sha256", "dns"]);
    return key.split("_").map(word => acronyms.has(word) ? word.toUpperCase() : word.charAt(0).toUpperCase() + word.slice(1)).join(" ");
  }

  function renderFields(value, depth = 0) {
    if (value === null || value === undefined || value === "") {
      const empty = document.createElement("span");
      empty.textContent = "—";
      return empty;
    }
    if (typeof value !== "object") {
      const scalar = document.createElement("span");
      const timestamp = typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value);
      scalar.textContent = timestamp && value.startsWith("0001-01-01T") ? "Time unknown" : String(value);
      return scalar;
    }
    if (depth >= 5) {
      const raw = document.createElement("pre");
      raw.textContent = JSON.stringify(value, null, 2);
      return raw;
    }
    const fields = document.createElement("dl");
    fields.className = "multi-host-evidence-fields";
    const entries = Object.entries(value);
    if (!entries.length) {
      const empty = document.createElement("span");
      empty.textContent = Array.isArray(value) ? "None" : "No fields";
      return empty;
    }
    for (const [key, entry] of entries) {
      const label = document.createElement("dt");
      label.textContent = Array.isArray(value) ? `Item ${Number(key) + 1}` : fieldLabel(key);
      const content = document.createElement("dd");
      content.appendChild(renderFields(entry, depth + 1));
      fields.append(label, content);
    }
    return fields;
  }

  function renderDetail(data, message = "") {
    const container = el("detail");
    container.replaceChildren();
    const item = data.evidence || data.event || data.result || {};
    const title = document.createElement("h3");
    title.textContent = item.title || item.name || item.process_name || item.type || data.type || "Evidence detail";
    container.appendChild(title);
    const sourceTitle = document.createElement("h4");
    sourceTitle.textContent = "Source";
    container.append(sourceTitle, renderFields({
      case_id: data.view.case_id, host_id: data.view.host_id, version: data.view.version,
      type: data.type || (data.event ? "timeline" : item.type), id: data.id || item.id,
    }));
    if (message) {
      const status = document.createElement("p");
      status.textContent = message;
      container.appendChild(status);
    }
    const fieldsTitle = document.createElement("h4");
    fieldsTitle.textContent = data.evidence ? "Evidence fields" : "Result preview";
    container.append(fieldsTitle, renderFields(item));
    const raw = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Raw JSON";
    const json = document.createElement("pre");
    json.textContent = JSON.stringify(data, null, 2);
    raw.append(summary, json);
    container.appendChild(raw);
  }

  function renderSummaries(data) {
    const counts = state.mode === "timeline" ? data.category_counts : data.by_type;
    const note = document.createElement("p");
    note.textContent = state.mode === "timeline"
      ? "Category counts apply the other filters, before category selection and pagination."
      : "Evidence type counts include all matches before the result limit.";
    el("summary").appendChild(note);
    for (const [name, count] of Object.entries(counts || {})) {
      const value = document.createElement(state.mode === "timeline" ? "button" : "span");
      value.textContent = `${name}: ${count}`;
      value.className = "category-tab";
      if (state.mode === "timeline") {
        value.type = "button";
        value.addEventListener("click", () => {
          el("category").value = name;
          run();
        });
      }
      el("counts").appendChild(value);
    }
    for (const summary of data.by_view || []) {
      const row = document.createElement("p");
      const counts = summary.category_counts || summary.by_type || {};
      row.textContent = `${summary.view.host_id} / ${summary.view.version}: ${summary.total} matches` +
        (Object.keys(counts).length ? ` · ${Object.entries(counts).map(([name, count]) => `${name}: ${count}`).join(" · ")}` : "");
      el("summary").appendChild(row);
    }
  }

  async function initialize() {
    try {
      const response = await fetch("/api/multi-host/views", { cache: "no-store" });
      // Local mode has no catalog endpoint.
      if (!response.ok || !response.headers.get("Content-Type")?.includes("application/json")) return;
      const data = await response.json();
      if (!Array.isArray(data.views)) return;
      state.views = data.views;
      el("panel").classList.remove("hidden");
      state.views.forEach((view, index) => {
        const label = document.createElement("label");
        label.className = "multi-host-view";
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.id = `multi-host-view-${index}`;
        checkbox.checked = true;
        checkbox.addEventListener("change", invalidate);
        label.append(checkbox, document.createTextNode(` ${view.case_id} / ${view.host_id} / ${view.version}`));
        el("views").appendChild(label);
      });
      el("status").textContent = `${state.views.length} host views available. Other investigation panels show the primary host.`;
      for (const mode of ["search", "timeline"]) el(mode).addEventListener("click", () => { state.mode = mode; run(); });
      el("prev").addEventListener("click", () => { state.offset = Math.max(0, state.offset - state.limit); run(false); });
      el("next").addEventListener("click", () => { state.offset += state.limit; run(false); });
      for (const field of ["query", "category", "user", "pid", "ip", "from", "to"]) el(field).addEventListener("input", invalidate);
      for (const field of ["order", "type"]) el(field).addEventListener("change", invalidate);
      el("reset").addEventListener("click", () => {
        for (const field of ["query", "category", "user", "pid", "ip", "from", "to", "type"]) el(field).value = "";
        el("order").value = "desc";
        invalidate();
      });
      el("query").addEventListener("keydown", (event) => { if (event.key === "Enter") run(); });
      el("copy-link").addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(el("link").value);
          el("status").textContent = "Investigation link copied.";
        } catch (error) {
          el("status").textContent = "Copy the investigation link from the read-only field.";
        }
      });
      await restoreLink();
    } catch (error) {
      console.error("Load multi-host views:", error);
    }
  }
  initialize();
})();

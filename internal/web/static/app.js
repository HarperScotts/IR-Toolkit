"use strict";

const byId = (id) => document.getElementById(id);

const timelineState = {
  category: "",
  offset: 0,
  limit: 100,
  total: 0,
  hasMore: false,
  events: [],
  selectedID: "",
};

const processState = {
  offset: 0,
  limit: 100,
  total: 0,
  hasMore: false,
  processes: [],
  selectedPID: 0,
};

const correlationState = {
  data: null,

  mode: "chains",

  view: "graph",

  selectedChainID: "",

  selectedGroupID: "",

  selectedNodeID: "",

  selectedEdgeID: "",

  relationshipGroups: [],

  cy: null,

  graphContext: null,

  filters: {
    nodeTypes: new Set(),

    confidence: "all",

    query: "",
  },

  availableNodeTypes: [],
};

const loginState = {
  offset: 0,
  limit: 100,
  total: 0,
  hasMore: false,
  selectedLogonID: "",

  detailController: null,
  detailSequence: 0,
};

const networkState = {
  offset: 0,
  limit: 100,
  total: 0,
  hasMore: false,
  selectedID: "",

  detailController: null,
  detailSequence: 0,
};

const fileState = {
  offset: 0,
  limit: 100,
  total: 0,
  hasMore: false,
  selectedPath: "",

  loaded: false,

  requestController: null,
  requestSequence: 0,

  detailController: null,
  detailSequence: 0,
};

const persistenceState = {
  offset: 0,
  limit: 100,
  total: 0,
  hasMore: false,
  selectedID: "",

  loaded: false,

  requestController: null,

  requestSequence: 0,

  detailController: null,
  detailSequence: 0,
};

const investigationNavigationState = {
  history: [],
  index: -1,
  restoring: false,

  breadcrumb: [],
};

async function loadJSON(url) {
  const response = await fetch(url, {
    cache: "no-store",
  });

  if (!response.ok) {
    const text = await response.text();

    throw new Error(`${response.status}: ${text}`);
  }

  return response.json();
}

function text(id, value, fallback = "-") {
  byId(id).textContent =
    value === undefined || value === null || value === ""
      ? fallback
      : String(value);
}

function percent(value) {
  if (value === undefined || value === null) {
    return "-";
  }

  return `${value}%`;
}

function normalizeStatus(value) {
  if (value === undefined || value === null) {
    return "unknown";
  }

  if (typeof value === "boolean") {
    return value ? "enabled" : "disabled";
  }

  if (typeof value === "object") {
    if (typeof value.status === "string") {
      return value.status;
    }

    if (typeof value.enabled === "boolean") {
      return value.enabled ? "enabled" : "disabled";
    }

    if (typeof value.available === "boolean") {
      return value.available ? "available" : "unavailable";
    }
  }

  return String(value);
}

function statusClass(status) {
  const value = String(status).toLowerCase();

  if (
    value.includes("enabled") ||
    value.includes("available") ||
    value === "ok"
  ) {
    return "state-good";
  }

  if (value.includes("partial") || value.includes("no_events")) {
    return "state-warn";
  }

  if (
    value.includes("disabled") ||
    value.includes("unavailable") ||
    value.includes("not_installed")
  ) {
    return "state-bad";
  }

  return "state-muted";
}

function capabilityRow(name, value) {
  const status = normalizeStatus(value);

  const element = document.createElement("div");

  element.className = "capability";

  const nameElement = document.createElement("span");

  nameElement.className = "capability-name";

  nameElement.textContent = name;

  const statusElement = document.createElement("span");

  statusElement.className = `capability-state ${statusClass(status)}`;

  statusElement.textContent = status;

  element.append(nameElement, statusElement);

  return element;
}

function renderCapabilities(capabilities) {
  const container = byId("capabilities");

  container.replaceChildren();

  const rows = [
    ["Security Log", capabilities.security_log],
    ["Logon Audit", capabilities.logon_audit],
    ["Process Creation Audit", capabilities.process_creation_audit],
    ["4688 History", capabilities.process_creation_events],
    ["PowerShell Operational", capabilities.powershell_operational],
    ["PowerShell 4104", capabilities.powershell_script_block_logging],
    ["Defender Operational", capabilities.defender_operational],
    ["Sysmon", capabilities.sysmon],
  ];

  for (const [name, value] of rows) {
    container.appendChild(capabilityRow(name, value));
  }
}

function renderProviders(snapshot) {
  const container = byId("security-providers");

  container.replaceChildren();

  const providers = Array.isArray(snapshot?.providers)
    ? snapshot.providers
    : [];

  if (providers.length === 0) {
    const empty = document.createElement("div");

    empty.className = "empty";

    empty.textContent = "No registered security providers were collected.";

    container.appendChild(empty);

    return;
  }

  for (const provider of providers) {
    const element = document.createElement("article");

    element.className = "provider";

    const name = document.createElement("div");

    name.className = "provider-name";

    name.textContent = provider.name || "-";

    const type = document.createElement("div");

    type.className = "provider-type";

    const parts = [];

    if (provider.type) {
      parts.push(provider.type);
    }

    if (provider.product_state_hex) {
      parts.push(provider.product_state_hex);
    }

    type.textContent = parts.join(" · ") || "security provider";

    element.append(name, type);

    container.appendChild(element);
  }
}

function summaryMetric(label, value) {
  const element = document.createElement("article");

  element.className = "metric";

  const labelElement = document.createElement("div");

  labelElement.className = "metric-label";

  labelElement.textContent = label;

  const valueElement = document.createElement("div");

  valueElement.className = "metric-value";

  valueElement.textContent = value ?? "-";

  element.append(labelElement, valueElement);

  return element;
}

function renderSummary(report) {
  const container = byId("analysis-summary");

  container.replaceChildren();

  if (!report) {
    container.appendChild(summaryMetric("Analysis", "Not available"));

    return;
  }

  const summary = report.summary || {};

  /*
        不把 overall_severity 作为
        “host compromise verdict”。

        当前首页只展示数据规模。
    */

  container.append(
    summaryMetric("Top Findings", summary.top_finding_count ?? 0),

    summaryMetric("Historical Chains", summary.historical_chain_count ?? 0),

    summaryMetric(
      "Evidence Gaps",
      Array.isArray(report.evidence_gaps) ? report.evidence_gaps.length : 0,
    ),
  );
}

function renderCase(data) {
  text("case-name", data.case_name);

  /*
        HostInfo 不同版本字段可能有所不同。
        前端兼容常见字段名。
    */

  const host = data.host || {};

  text("hostname", host.hostname || host.host_name || host.computer_name);

  const capabilities = data.capabilities || {};

  text("collection-mode", capabilities.collection_mode);

  text("historical-coverage", percent(capabilities.historical_coverage));

  text("snapshot-coverage", percent(capabilities.snapshot_coverage));

  renderCapabilities(capabilities);

  renderProviders(data.security_providers);

  renderSummary(data.report);
}

function formatTimestamp(value) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function renderTimeline(timeline) {
  const container = byId("timeline-list");

  container.replaceChildren();

  const events = Array.isArray(timeline?.events) ? timeline.events : [];

  if (events.length === 0) {
    const empty = document.createElement("div");

    empty.className = "empty";

    empty.textContent = "No timeline events.";

    container.appendChild(empty);

    return;
  }

  /*
        第一版只预览前 100 条。

        V0.2.0-03 会做真正的查询、
        分页、过滤以及虚拟列表。
    */

  for (const event of events.slice(0, 100)) {
    const row = document.createElement("div");

    row.className = "timeline-event";

    const time = document.createElement("div");

    time.className = "timeline-time";

    time.textContent = formatTimestamp(event.timestamp);

    const category = document.createElement("div");

    category.className = "timeline-category";

    category.textContent = event.category || event.type || "-";

    const description = document.createElement("div");

    description.className = "timeline-description";

    description.textContent =
      event.description || event.object || event.type || "-";

    row.append(time, category, description);

    container.appendChild(row);
  }
}

async function openTimeline() {
  byId("timeline-section").classList.remove("hidden");

  await loadTimeline();

  byId("timeline-section").scrollIntoView({
    behavior: "smooth",

    block: "start",
  });
}

async function openLogins() {
  const section = byId("login-section");

  if (!section) {
    return;
  }

  section.classList.remove("hidden");

  loginState.offset = 0;

  await loadLogins();

  section.scrollIntoView({
    behavior: "smooth",

    block: "start",
  });
}

async function openNetwork() {
  const section = byId("network-section");

  if (!section) {
    return;
  }

  section.classList.remove("hidden");

  networkState.offset = 0;

  await loadNetwork();

  section.scrollIntoView({
    behavior: "smooth",

    block: "start",
  });
}

async function openFiles() {
  const section = byId("file-section");

  if (!section) {
    return;
  }

  section.classList.remove("hidden");

  if (!fileState.loaded) {
    fileState.offset = 0;

    await loadFiles();
  }

  section.scrollIntoView({
    behavior: "smooth",
    block: "start",
  });
}

async function loadFiles() {
  if (fileState.requestController) {
    fileState.requestController.abort();
  }

  const controller = new AbortController();

  fileState.requestController = controller;

  const sequence = ++fileState.requestSequence;

  const params = new URLSearchParams();

  const query = byId("file-search")?.value.trim() || "";

  const owner = byId("file-owner")?.value.trim() || "";

  const extension = byId("file-extension")?.value.trim() || "";

  const executable = byId("file-executable")?.value || "";

  const finding = byId("file-finding")?.value || "";

  if (query) {
    params.set("q", query);
  }

  if (owner) {
    params.set("owner", owner);
  }

  if (extension) {
    params.set("extension", extension);
  }

  if (executable) {
    params.set("executable", executable);
  }

  if (finding) {
    params.set("finding", finding);
  }

  params.set("offset", String(fileState.offset));

  params.set("limit", String(fileState.limit));

  try {
    const data = await loadJSONWithSignal(
      `/api/files?${params.toString()}`,
      controller.signal,
    );

    /*
     * 已经有更新的请求发出，
     * 旧响应直接丢弃。
     */
    if (sequence !== fileState.requestSequence) {
      return;
    }

    fileState.total = data.total || 0;

    fileState.hasMore = Boolean(data.has_more);

    fileState.loaded = true;

    renderFileList(data.files || []);

    updateFilePagination();

    text("file-result-count", `${fileState.total} files`);
  } catch (error) {
    if (error.name === "AbortError") {
      return;
    }

    console.error("Load files failed:", error);
  } finally {
    if (fileState.requestController === controller) {
      fileState.requestController = null;
    }
  }
}

function renderFileList(files) {
  const container = byId("file-list");

  if (!container) {
    return;
  }

  container.replaceChildren();

  if (files.length === 0) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent = "No matching file evidence.";

    container.appendChild(empty);

    return;
  }

  for (const file of files) {
    const button = document.createElement("button");

    button.type = "button";

    button.className = "file-list-item";

    if (file.path === fileState.selectedPath) {
      button.classList.add("selected");
    }

    const title = document.createElement("div");

    title.className = "global-search-result-title";

    title.textContent = file.name || file.path || "File";

    const meta = document.createElement("div");

    meta.className = "global-search-result-meta";

    meta.textContent = [
      file.path,
      file.extension,
      file.executable ? "executable" : "",
      file.has_finding ? `finding ${file.finding_severity || ""}` : "",
    ]
      .filter(Boolean)
      .join(" · ");

    button.append(title, meta);
    button.dataset.filePath = file.path || "";

    button.addEventListener("click", () => {
      selectFileEvidence(file.path);
    });

    container.appendChild(button);
  }
}

async function selectFileEvidence(path) {
  if (!path) {
    return;
  }

  fileState.selectedPath = path;

  updateSelectedFileListItem();

  if (fileState.detailController) {
    fileState.detailController.abort();
  }

  const controller = new AbortController();

  fileState.detailController = controller;

  const sequence = ++fileState.detailSequence;

  try {
    const data = await loadJSONWithSignal(
      `/api/file?path=${encodeURIComponent(path)}`,
      controller.signal,
    );

    if (sequence !== fileState.detailSequence) {
      return;
    }

    /*
     * 用户已经选了另一个文件。
     */
    if (fileState.selectedPath !== path) {
      return;
    }

    renderFileDetail(data);
  } catch (error) {
    if (error.name === "AbortError") {
      return;
    }

    console.error("Load file detail failed:", error);
  } finally {
    if (fileState.detailController === controller) {
      fileState.detailController = null;
    }
  }
}

function renderFileDetail(data) {
  const container = byId("file-detail");

  if (!container) {
    return;
  }

  container.replaceChildren();

  const file = data.file || {};

  const finding = data.finding || null;

  const title = document.createElement("h3");

  title.textContent = file.name || file.path || "File";

  container.appendChild(title);

  appendEvidenceDetailField(container, "Path", file.path || "");

  appendEvidenceDetailField(container, "Extension", file.extension || "");

  appendEvidenceDetailField(container, "Size", String(file.size ?? ""));

  appendEvidenceDetailField(container, "Owner", file.owner || "");

  appendEvidenceDetailField(
    container,
    "Executable",
    String(Boolean(file.executable)),
  );

  appendEvidenceDetailField(container, "SHA256", file.sha256 || "");

  appendEvidenceDetailField(
    container,
    "Created",
    file.created_at ? formatTimestamp(file.created_at) : "",
  );

  appendEvidenceDetailField(
    container,
    "Modified",
    file.modified_at ? formatTimestamp(file.modified_at) : "",
  );

  appendEvidenceDetailField(
    container,
    "Accessed",
    file.accessed_at ? formatTimestamp(file.accessed_at) : "",
  );

  appendEvidenceDetailField(
    container,
    "Zone Identifier",
    file.zone_identifier || "",
  );

  appendEvidenceDetailField(container, "Source", file.source || "");

  if (Array.isArray(file.ads) && file.ads.length > 0) {
    const ads = file.ads
      .map(
        (stream) => `${stream.name}${stream.size ? ` (${stream.size})` : ""}`,
      )
      .join(" | ");

    appendEvidenceDetailField(container, "ADS", ads);
  }

  if (finding) {
    appendEvidenceDetailField(
      container,
      "Finding Severity",
      finding.severity || "",
    );

    appendEvidenceDetailField(
      container,
      "Finding Score",
      String(finding.score ?? ""),
    );

    appendEvidenceDetailField(container, "Finding", finding.title || "");

    if (Array.isArray(finding.reasons)) {
      appendEvidenceDetailField(
        container,
        "Reasons",
        finding.reasons.join(" | "),
      );
    }
  }

  renderFileRelatedPersistence(container, data.related_persistence || []);

  renderFullFileActions(container, file, finding);
}

function renderFullFileActions(container, file, finding) {
  const actions = document.createElement("div");

  actions.className = "evidence-detail-actions";

  /*
   * Finding 中只有一个 Related PID 时，
   * 才直接 Open Process。
   */
  if (
    finding &&
    Array.isArray(finding.related_pids) &&
    finding.related_pids.length === 1
  ) {
    const processButton = document.createElement("button");

    processButton.type = "button";

    processButton.className = "secondary-button";

    processButton.textContent = "Open Process";

    processButton.addEventListener("click", async () => {
      await openProcessByPID(finding.related_pids[0]);
    });

    actions.appendChild(processButton);
  }

  const timelineButton = document.createElement("button");

  timelineButton.type = "button";

  timelineButton.className = "secondary-button";

  timelineButton.textContent = "Show in Timeline";

  timelineButton.addEventListener("click", async () => {
    await openTimelineByQuery(file.sha256 || file.path || "");
  });

  actions.appendChild(timelineButton);

  container.appendChild(actions);
}

function updateFilePagination() {
  const start = fileState.total === 0 ? 0 : fileState.offset + 1;

  const end = Math.min(fileState.offset + fileState.limit, fileState.total);

  text("file-page-info", `${start}-${end} of ${fileState.total}`);

  const prev = byId("file-prev");

  const next = byId("file-next");

  if (prev) {
    prev.disabled = fileState.offset <= 0;
  }

  if (next) {
    next.disabled = !fileState.hasMore;
  }
}

function updateSelectedFileListItem() {
  const container = byId("file-list");

  if (!container) {
    return;
  }

  for (const button of container.querySelectorAll(".file-list-item")) {
    button.classList.toggle(
      "selected",
      button.dataset.filePath === fileState.selectedPath,
    );
  }
}

async function openPersistence() {
  const section = byId("persistence-section");

  if (!section) {
    return;
  }

  section.classList.remove("hidden");

  if (!persistenceState.loaded) {
    persistenceState.offset = 0;

    await loadPersistence();
  }

  section.scrollIntoView({
    behavior: "smooth",
    block: "start",
  });
}

async function loadPersistence() {
  if (persistenceState.requestController) {
    persistenceState.requestController.abort();
  }

  const controller = new AbortController();

  persistenceState.requestController = controller;

  const sequence = ++persistenceState.requestSequence;

  const params = new URLSearchParams();

  const query = byId("persistence-search")?.value.trim() || "";

  const type = byId("persistence-type")?.value || "";

  const user = byId("persistence-user")?.value.trim() || "";

  const finding = byId("persistence-finding")?.value || "";

  if (query) {
    params.set("q", query);
  }

  if (type) {
    params.set("type", type);
  }

  if (user) {
    params.set("user", user);
  }

  if (finding) {
    params.set("finding", finding);
  }

  params.set("offset", String(persistenceState.offset));

  params.set("limit", String(persistenceState.limit));

  try {
    const data = await loadJSONWithSignal(
      `/api/persistence?${params.toString()}`,
      controller.signal,
    );

    if (sequence !== persistenceState.requestSequence) {
      return;
    }

    persistenceState.total = data.total || 0;

    persistenceState.hasMore = Boolean(data.has_more);

    persistenceState.loaded = true;

    renderPersistenceList(data.items || []);

    updatePersistencePagination();

    text(
      "persistence-result-count",
      `${persistenceState.total} persistence records`,
    );
  } catch (error) {
    if (error.name === "AbortError") {
      return;
    }

    console.error("Load persistence failed:", error);
  } finally {
    if (persistenceState.requestController === controller) {
      persistenceState.requestController = null;
    }
  }
}

function renderPersistenceList(items) {
  const container = byId("persistence-list");

  if (!container) {
    return;
  }

  container.replaceChildren();

  if (items.length === 0) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent = "No matching persistence evidence.";

    container.appendChild(empty);

    return;
  }

  for (const item of items) {
    const button = document.createElement("button");

    button.type = "button";

    button.className = "persistence-list-item";

    if (item.id === persistenceState.selectedID) {
      button.classList.add("selected");
    }

    const title = document.createElement("div");

    title.className = "global-search-result-title";

    title.textContent = item.title || item.name || item.id;

    const meta = document.createElement("div");

    meta.className = "global-search-result-meta";

    meta.textContent = [
      item.type,
      item.name,
      item.user,
      item.has_finding ? `finding ${item.finding_severity || ""}` : "",
    ]
      .filter(Boolean)
      .join(" · ");

    button.append(title, meta);

    button.dataset.persistenceId = item.id || "";

    button.addEventListener("click", () => {
      selectPersistenceEvidence(item.id);
    });

    container.appendChild(button);
  }
}

async function selectPersistenceEvidence(id) {
  if (!id) {
    return;
  }

  persistenceState.selectedID = id;

  updateSelectedPersistenceListItem();

  if (persistenceState.detailController) {
    persistenceState.detailController.abort();
  }

  const controller = new AbortController();

  persistenceState.detailController = controller;

  const sequence = ++persistenceState.detailSequence;

  try {
    const data = await loadJSONWithSignal(
      `/api/persistence/detail?id=${encodeURIComponent(id)}`,
      controller.signal,
    );

    if (sequence !== persistenceState.detailSequence) {
      return;
    }

    if (persistenceState.selectedID !== id) {
      return;
    }

    renderPersistenceDetail(data);
  } catch (error) {
    if (error.name === "AbortError") {
      return;
    }

    console.error("Load persistence detail failed:", error);
  } finally {
    if (persistenceState.detailController === controller) {
      persistenceState.detailController = null;
    }
  }
}

function updateSelectedPersistenceListItem() {
  const container = byId("persistence-list");

  if (!container) {
    return;
  }

  for (const button of container.querySelectorAll(".persistence-list-item")) {
    button.classList.toggle(
      "selected",
      button.dataset.persistenceId === persistenceState.selectedID,
    );
  }
}

function renderPersistenceDetail(data) {
  const container = byId("persistence-detail");

  if (!container) {
    return;
  }

  container.replaceChildren();

  const item = data.item || {};

  const title = document.createElement("h3");

  title.textContent = item.title || item.name || "Persistence";

  container.appendChild(title);

  appendEvidenceDetailField(container, "Type", item.type || "");

  appendEvidenceDetailField(container, "Name", item.name || "");

  appendEvidenceDetailField(container, "Command", item.command || "");

  appendEvidenceDetailField(container, "User", item.user || "");

  appendEvidenceDetailField(container, "PID", item.pid ? String(item.pid) : "");

  appendEvidenceDetailField(container, "Object", item.object || "");

  if (data.service) {
    appendEvidenceDetailField(
      container,
      "Display Name",
      data.service.display_name || "",
    );

    appendEvidenceDetailField(
      container,
      "Description",
      data.service.description || "",
    );

    appendEvidenceDetailField(
      container,
      "Start Type",
      data.service.start_type || "",
    );

    appendEvidenceDetailField(container, "Account", data.service.account || "");

    appendEvidenceDetailField(container, "State", data.service.state || "");

    appendEvidenceDetailField(
      container,
      "Delayed Auto Start",
      String(Boolean(data.service.delayed_auto_start)),
    );
  }

  if (data.run_key) {
    appendEvidenceDetailField(container, "Hive", data.run_key.hive || "");

    appendEvidenceDetailField(container, "Key", data.run_key.key || "");

    appendEvidenceDetailField(container, "View", data.run_key.view || "");

    appendEvidenceDetailField(
      container,
      "Expanded Command",
      data.run_key.expanded_command || "",
    );

    appendEvidenceDetailField(
      container,
      "Value Type",
      data.run_key.value_type || "",
    );

    appendEvidenceDetailField(
      container,
      "Modified",
      data.run_key.key_modified_at
        ? formatTimestamp(data.run_key.key_modified_at)
        : "",
    );
  }

  if (data.scheduled_task) {
    appendEvidenceDetailField(
      container,
      "Task Path",
      data.scheduled_task.path || "",
    );

    appendEvidenceDetailField(
      container,
      "Task File",
      data.scheduled_task.file_path || "",
    );

    appendEvidenceDetailField(
      container,
      "Author",
      data.scheduled_task.author || "",
    );

    appendEvidenceDetailField(
      container,
      "User ID",
      data.scheduled_task.user_id || "",
    );

    appendEvidenceDetailField(
      container,
      "Logon Type",
      data.scheduled_task.logon_type || "",
    );

    appendEvidenceDetailField(
      container,
      "Run Level",
      data.scheduled_task.run_level || "",
    );

    appendEvidenceDetailField(
      container,
      "Modified",
      data.scheduled_task.modified_at
        ? formatTimestamp(data.scheduled_task.modified_at)
        : "",
    );

    if (Array.isArray(data.scheduled_task.trigger_types)) {
      appendEvidenceDetailField(
        container,
        "Triggers",
        data.scheduled_task.trigger_types.join(", "),
      );
    }

    if (Array.isArray(data.scheduled_task.actions)) {
      const actions = data.scheduled_task.actions
        .map((action) =>
          [action.command, action.arguments].filter(Boolean).join(" "),
        )
        .filter(Boolean)
        .join(" | ");

      appendEvidenceDetailField(container, "Actions", actions);
    }

    appendEvidenceDetailField(
      container,
      "Parse Error",
      data.scheduled_task.parse_error || "",
    );
  }

  if (data.finding) {
    appendEvidenceDetailField(
      container,
      "Finding Severity",
      data.finding.severity || "",
    );

    appendEvidenceDetailField(
      container,
      "Finding Score",
      String(data.finding.score ?? ""),
    );

    appendEvidenceDetailField(container, "Finding", data.finding.title || "");

    if (Array.isArray(data.finding.reasons)) {
      appendEvidenceDetailField(
        container,
        "Reasons",
        data.finding.reasons.join(" | "),
      );
    }
  }

  renderPersistenceRelatedFiles(container, data.related_files || []);

  renderFullPersistenceActions(container, item, data.finding || null);
}

function renderFullPersistenceActions(container, item, finding) {
  const actions = document.createElement("div");

  actions.className = "evidence-detail-actions";

  if (finding && finding.related_pid) {
    const processButton = document.createElement("button");

    processButton.type = "button";

    processButton.className = "secondary-button";

    processButton.textContent = "Open Process";

    processButton.addEventListener("click", async () => {
      await openProcessByPID(finding.related_pid);
    });

    actions.appendChild(processButton);
  }

  const timelineButton = document.createElement("button");

  timelineButton.type = "button";

  timelineButton.className = "secondary-button";

  timelineButton.textContent = "Show in Timeline";

  timelineButton.addEventListener("click", async () => {
    await openTimelineByQuery(item.name || item.command || item.id || "");
  });

  actions.appendChild(timelineButton);

  container.appendChild(actions);
}

function updatePersistencePagination() {
  const start = persistenceState.total === 0 ? 0 : persistenceState.offset + 1;

  const end = Math.min(
    persistenceState.offset + persistenceState.limit,
    persistenceState.total,
  );

  text("persistence-page-info", `${start}-${end} of ${persistenceState.total}`);

  const prev = byId("persistence-prev");

  const next = byId("persistence-next");

  if (prev) {
    prev.disabled = persistenceState.offset <= 0;
  }

  if (next) {
    next.disabled = !persistenceState.hasMore;
  }
}

async function openProcessByPID(pid, source = null) {
  if (!pid) {
    return;
  }

  const section = byId("process-section");

  if (!section) {
    return;
  }

  section.classList.remove("hidden");

  await selectProcess(pid);

  section.scrollIntoView({
    behavior: "smooth",

    block: "start",
  });

  pushInvestigationLocation({
    workspace: "process",

    title: `Process · PID ${pid}`,

    target: {
      pid: Number(pid),
    },

    source: source,
  });
}

async function openLoginByLogonID(logonID, source = null) {
  if (!logonID) {
    return;
  }

  const section = byId("login-section");

  if (!section) {
    return;
  }

  section.classList.remove("hidden");

  await selectLoginSession(logonID);

  section.scrollIntoView({
    behavior: "smooth",

    block: "start",
  });

  pushInvestigationLocation({
    workspace: "login",

    title: `Login · ${logonID}`,

    target: {
      logon_id: logonID,
    },
    source: source,
  });
}

async function openNetworkByID(id, source = null) {
  if (!id) {
    return;
  }

  const section = byId("network-section");

  if (!section) {
    return;
  }

  section.classList.remove("hidden");

  await selectNetworkConnection(id);

  section.scrollIntoView({
    behavior: "smooth",

    block: "start",
  });

  pushInvestigationLocation({
    workspace: "network",

    title: "Network Evidence",

    target: {
      id: id,
    },
    source: source,
  });
}

async function openNetworkByPID(pid) {
  if (!pid) {
    return;
  }

  const section = byId("network-section");

  const input = byId("network-pid");

  if (!section || !input) {
    return;
  }

  section.classList.remove("hidden");

  input.value = String(pid);

  networkState.offset = 0;

  await loadNetwork();

  section.scrollIntoView({
    behavior: "smooth",

    block: "start",
  });

  pushInvestigationLocation({
    workspace: "network",

    title: `Network · PID ${pid}`,

    target: {
      pid: Number(pid),
    },
    source: source,
  });
}

async function openPersistenceByID(id, source = null) {
  if (!id) {
    return;
  }

  const section = byId("persistence-section");

  if (!section) {
    return;
  }

  section.classList.remove("hidden");

  await selectPersistenceEvidence(id);

  section.scrollIntoView({
    behavior: "smooth",

    block: "start",
  });

  pushInvestigationLocation({
    workspace: "persistence",

    title: `Persistence · ${id}`,

    target: {
      id: id,
    },
    source: source,
  });
}

async function openFileByPath(path, source = null) {
  if (!path) {
    return;
  }

  const section = byId("file-section");

  if (!section) {
    return;
  }

  section.classList.remove("hidden");

  await selectFileEvidence(path);

  section.scrollIntoView({
    behavior: "smooth",

    block: "start",
  });

  pushInvestigationLocation({
    workspace: "file",

    title: `File · ${windowsPathBaseName(path)}`,

    target: {
      path: path,
    },
    source: source,
  });
}

async function loadNetwork() {
  const params = new URLSearchParams();

  const query = byId("network-search")?.value.trim() || "";

  const pid = byId("network-pid")?.value.trim() || "";

  const ip = byId("network-ip")?.value.trim() || "";

  const state = byId("network-state")?.value.trim() || "";

  const external = byId("network-external")?.value || "";

  if (query) {
    params.set("q", query);
  }

  if (pid) {
    params.set("pid", pid);
  }

  if (ip) {
    params.set("ip", ip);
  }

  if (state) {
    params.set("state", state);
  }

  if (external) {
    params.set("external", external);
  }

  params.set("offset", String(networkState.offset));

  params.set("limit", String(networkState.limit));

  const data = await loadJSON(`/api/network?${params.toString()}`);

  networkState.total = data.total || 0;

  networkState.hasMore = Boolean(data.has_more);

  renderNetworkList(data.connections || []);

  updateNetworkPagination();

  text("network-result-count", `${networkState.total} network records`);
}

function renderNetworkList(connections) {
  const container = byId("network-list");

  if (!container) {
    return;
  }

  container.replaceChildren();

  if (connections.length === 0) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent = "No matching network evidence.";

    container.appendChild(empty);

    return;
  }

  for (const connection of connections) {
    const button = document.createElement("button");

    button.type = "button";

    button.className = "network-list-item";

    if (connection.id === networkState.selectedID) {
      button.classList.add("selected");
    }

    const title = document.createElement("div");

    title.className = "global-search-result-title";

    title.textContent = connection.process_name || `PID ${connection.pid}`;

    const meta = document.createElement("div");

    meta.className = "global-search-result-meta";

    const endpoint =
      connection.kind === "listener"
        ? `${connection.local_address}:${connection.local_port}`
        : `${connection.local_address}:${connection.local_port} → ${connection.remote_address}:${connection.remote_port}`;

    meta.textContent = [
      connection.kind,
      connection.protocol,
      endpoint,
      connection.state,
      connection.external ? "external" : "",
    ]
      .filter(Boolean)
      .join(" · ");

    button.append(title, meta);

    button.dataset.networkId = item.id || "";

    button.addEventListener("click", () => {
      selectNetworkConnection(connection.id);
    });

    container.appendChild(button);
  }
}

function updateSelectedNetworkListItem() {
  const container = byId("network-list");

  if (!container) {
    return;
  }

  for (const button of container.querySelectorAll(".network-list-item")) {
    button.classList.toggle(
      "selected",
      button.dataset.networkId === networkState.selectedID,
    );
  }
}

async function selectNetworkConnection(id) {
  if (!id) {
    return;
  }

  networkState.selectedID = id;

  updateSelectedNetworkListItem();

  if (networkState.detailController) {
    networkState.detailController.abort();
  }

  const controller = new AbortController();

  networkState.detailController = controller;

  const sequence = ++networkState.detailSequence;

  try {
    const data = await loadJSONWithSignal(
      `/api/network/detail?id=${encodeURIComponent(id)}`,
      controller.signal,
    );

    if (sequence !== networkState.detailSequence) {
      return;
    }

    if (networkState.selectedID !== id) {
      return;
    }

    renderNetworkDetail(data);
  } catch (error) {
    if (error.name === "AbortError") {
      return;
    }

    console.error("Load network detail failed:", error);
  } finally {
    if (networkState.detailController === controller) {
      networkState.detailController = null;
    }
  }
}

function renderNetworkDetail(connection) {
  const container = byId("network-detail");

  if (!container) {
    return;
  }

  container.replaceChildren();

  const title = document.createElement("h3");

  title.textContent = connection.process_name || `PID ${connection.pid}`;

  container.appendChild(title);

  const fields = {
    Kind: connection.kind,

    PID: connection.pid,

    Process: connection.process_name,

    Path: connection.process_path,

    User: connection.user,

    "Authentication ID": connection.authentication_id,

    Protocol: connection.protocol,

    Family: connection.family,

    Local: `${connection.local_address}:${connection.local_port}`,

    Remote: connection.remote_address
      ? `${connection.remote_address}:${connection.remote_port}`
      : "",

    State: connection.state,

    External: String(Boolean(connection.external)),
  };

  for (const [label, value] of Object.entries(fields)) {
    if (value === undefined || value === null || value === "") {
      continue;
    }

    appendEvidenceDetailField(container, label, String(value));
  }

  renderNetworkActions(container, connection);
}

function renderNetworkActions(container, connection) {
  const actions = document.createElement("div");

  actions.className = "evidence-detail-actions";

  /*
   * Process
   */
  if (connection.pid) {
    const processButton = document.createElement("button");

    processButton.type = "button";

    processButton.className = "secondary-button";

    processButton.textContent = "Open Process";

    processButton.addEventListener("click", async () => {
      byId("process-section")?.classList.remove("hidden");

      await openProcessByPID(connection.pid);

      byId("process-section")?.scrollIntoView({
        behavior: "smooth",

        block: "start",
      });
    });

    actions.appendChild(processButton);
  }

  /*
   * Login
   *
   * AuthenticationID 和 LogonID
   * 使用精确匹配。
   */
  if (connection.authentication_id) {
    const loginButton = document.createElement("button");

    loginButton.type = "button";

    loginButton.className = "secondary-button";

    loginButton.textContent = "Open Login";

    loginButton.addEventListener("click", async () => {
      const section = byId("login-section");

      section?.classList.remove("hidden");

      await openLoginByLogonID(
        process.authentication_id,
        investigationSourceFromCurrent(),
      );

      section?.scrollIntoView({
        behavior: "smooth",

        block: "start",
      });
    });

    actions.appendChild(loginButton);
  }

  /*
   * Timeline
   */
  const timelineButton = document.createElement("button");

  timelineButton.type = "button";

  timelineButton.className = "secondary-button";

  timelineButton.textContent = "Show in Timeline";

  timelineButton.addEventListener("click", async () => {
    await openTimelineByQuery(
      connection.remote_address || String(connection.pid || ""),
    );
  });

  actions.appendChild(timelineButton);

  container.appendChild(actions);
}

function updateNetworkPagination() {
  const start = networkState.total === 0 ? 0 : networkState.offset + 1;

  const end = Math.min(
    networkState.offset + networkState.limit,
    networkState.total,
  );

  text("network-page-info", `${start}-${end} of ${networkState.total}`);

  const prev = byId("network-prev");

  const next = byId("network-next");

  if (prev) {
    prev.disabled = networkState.offset <= 0;
  }

  if (next) {
    next.disabled = !networkState.hasMore;
  }
}

function timelineQueryURL() {
  const params = new URLSearchParams();

  const search = byId("timeline-search").value.trim();

  const user = byId("timeline-user").value.trim();

  const pid = byId("timeline-pid").value.trim();

  const ip = byId("timeline-ip").value.trim();

  const from = byId("timeline-from").value;

  const to = byId("timeline-to").value;

  const order = byId("timeline-order").value;

  if (search) {
    params.set("q", search);
  }

  if (user) {
    params.set("user", user);
  }

  if (pid) {
    params.set("pid", pid);
  }

  if (ip) {
    params.set("ip", ip);
  }

  if (timelineState.category) {
    params.set("category", timelineState.category);
  }

  if (from) {
    params.set("from", new Date(from).toISOString());
  }

  if (to) {
    params.set("to", new Date(to).toISOString());
  }

  params.set("order", order);

  params.set("offset", String(timelineState.offset));

  params.set("limit", String(timelineState.limit));

  return "/api/timeline?" + params.toString();
}

async function loadTimeline() {
  const container = byId("timeline-list");

  container.textContent = "Loading...";

  try {
    const data = await loadJSON(timelineQueryURL());

    timelineState.total = data.total || 0;

    timelineState.hasMore = Boolean(data.has_more);

    timelineState.events = Array.isArray(data.events) ? data.events : [];

    renderTimelineCategories(data.category_counts || {});

    renderTimelinePage();
  } catch (error) {
    container.textContent = String(error);
  }
}

function renderTimelineCategories(counts) {
  const container = byId("timeline-categories");

  container.replaceChildren();

  const entries = Object.entries(counts).sort(
    (left, right) => right[1] - left[1],
  );

  const total = Object.values(counts).reduce(
    (current, value) => current + value,
    0,
  );

  container.appendChild(createCategoryButton("", "All", total));

  for (const [category, count] of entries) {
    container.appendChild(createCategoryButton(category, category, count));
  }
}

function createCategoryButton(value, label, count) {
  const button = document.createElement("button");

  button.type = "button";

  button.className = "category-tab";

  if (timelineState.category === value) {
    button.classList.add("active");
  }

  const text = document.createElement("span");

  text.textContent = label;

  const countElement = document.createElement("span");

  countElement.className = "category-count";

  countElement.textContent = String(count);

  button.append(text, countElement);

  button.addEventListener("click", () => {
    timelineState.category = value;

    timelineState.offset = 0;

    timelineState.selectedID = "";

    loadTimeline();
  });

  return button;
}

function renderTimelinePage() {
  const container = byId("timeline-list");

  container.replaceChildren();

  const events = timelineState.events;

  if (events.length === 0) {
    const empty = document.createElement("div");

    empty.className = "empty";

    empty.textContent = "No matching timeline events.";

    container.appendChild(empty);
  } else {
    for (const event of events) {
      container.appendChild(createTimelineEventRow(event));
    }
  }

  renderTimelinePagination();

  text("timeline-result-count", `${timelineState.total} matching events`);
}

function createTimelineEventRow(event) {
  const row = document.createElement("div");

  row.className = "timeline-event";

  if (event.id && event.id === timelineState.selectedID) {
    row.classList.add("selected");
  }

  row.tabIndex = 0;

  const time = document.createElement("div");

  time.className = "timeline-time";

  time.textContent = formatTimestamp(event.timestamp);

  const category = document.createElement("div");

  category.className = "timeline-category";

  category.textContent = event.category || "other";

  const body = document.createElement("div");

  const type = document.createElement("div");

  type.className = "timeline-event-type";

  type.textContent = event.type || "EVENT";

  const description = document.createElement("div");

  description.className = "timeline-description";

  description.textContent = event.description || event.object || "-";

  const meta = document.createElement("div");

  meta.className = "timeline-event-meta";

  const metaParts = [];

  if (event.user) {
    metaParts.push(`User: ${event.user}`);
  }

  if (event.pid) {
    metaParts.push(`PID: ${event.pid}`);
  }

  if (event.source_ip) {
    metaParts.push(`IP: ${event.source_ip}`);
  }

  meta.textContent = metaParts.join(" · ");

  body.append(type, description, meta);

  row.append(time, category, body);

  const select = () => {
    timelineState.selectedID = event.id || "";

    renderTimelinePage();

    renderTimelineDetail(event);
  };

  row.addEventListener("click", select);

  row.addEventListener("keydown", (keyboardEvent) => {
    if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") {
      keyboardEvent.preventDefault();

      select();
    }
  });

  return row;
}

function renderTimelineDetail(event) {
  const container = byId("timeline-detail");

  container.replaceChildren();

  const title = document.createElement("div");

  title.className = "detail-title";

  title.textContent = event.type || "Timeline Event";

  container.appendChild(title);

  const coreRows = [
    ["Time", formatTimestamp(event.timestamp)],
    ["Category", event.category],
    ["Severity", event.severity],
    ["User", event.user],
    ["PID", event.pid],
    ["Process", event.process],
    ["Source IP", event.source_ip],
    ["Object", event.object],
    ["Host", event.host],
  ];

  appendDetailSection(container, "Event", coreRows);

  if (event.description) {
    appendDetailSection(container, "Description", [
      ["Value", event.description],
    ]);
  }

  if (event.metadata && typeof event.metadata === "object") {
    const metadataRows = Object.entries(event.metadata);

    if (metadataRows.length > 0) {
      appendDetailSection(container, "Metadata", metadataRows);
    }
  }

  if (Array.isArray(event.related_ids) && event.related_ids.length > 0) {
    appendDetailSection(
      container,
      "Related Evidence",
      event.related_ids.map((value, index) => [String(index + 1), value]),
    );
  }
}

function appendDetailSection(container, title, rows) {
  const section = document.createElement("div");

  section.className = "detail-section";

  const heading = document.createElement("div");

  heading.className = "detail-section-title";

  heading.textContent = title;

  section.appendChild(heading);

  for (const [key, value] of rows) {
    if (value === undefined || value === null || value === "") {
      continue;
    }

    const row = document.createElement("div");

    row.className = "detail-row";

    const keyElement = document.createElement("div");

    keyElement.className = "detail-key";

    keyElement.textContent = key;

    const valueElement = document.createElement("div");

    valueElement.className = "detail-value";

    valueElement.textContent = String(value);

    row.append(keyElement, valueElement);

    section.appendChild(row);
  }

  container.appendChild(section);
}

function renderTimelinePagination() {
  const start = timelineState.total === 0 ? 0 : timelineState.offset + 1;

  const end = Math.min(
    timelineState.offset + timelineState.events.length,
    timelineState.total,
  );

  text("timeline-page-info", `${start}-${end} / ${timelineState.total}`);

  byId("timeline-prev").disabled = timelineState.offset === 0;

  byId("timeline-next").disabled = !timelineState.hasMore;
}

function resetTimelineFilters() {
  byId("timeline-search").value = "";

  byId("timeline-user").value = "";

  byId("timeline-pid").value = "";

  byId("timeline-ip").value = "";

  byId("timeline-from").value = "";

  byId("timeline-to").value = "";

  byId("timeline-order").value = "asc";

  timelineState.category = "";

  timelineState.offset = 0;

  timelineState.selectedID = "";

  byId("timeline-detail").replaceChildren();

  const empty = document.createElement("div");

  empty.className = "event-detail-empty";

  empty.textContent = "Select an event to inspect the complete evidence.";

  byId("timeline-detail").appendChild(empty);

  loadTimeline();
}

// Process Query

function processQueryURL() {
  const params = new URLSearchParams();

  const search = byId("process-search").value.trim();

  const user = byId("process-user").value.trim();

  if (search) {
    params.set("q", search);
  }

  if (user) {
    params.set("user", user);
  }

  params.set("offset", String(processState.offset));

  params.set("limit", String(processState.limit));

  return "/api/processes?" + params.toString();
}

async function openProcesses() {
  byId("process-section").classList.remove("hidden");

  await loadProcesses();

  byId("process-section").scrollIntoView({
    behavior: "smooth",

    block: "start",
  });
}

async function loadProcesses() {
  const container = byId("process-list");

  container.textContent = "Loading...";

  try {
    const data = await loadJSON(processQueryURL());

    processState.total = data.total || 0;

    processState.hasMore = Boolean(data.has_more);

    processState.processes = Array.isArray(data.processes)
      ? data.processes
      : [];

    renderProcessList();
  } catch (error) {
    container.textContent = String(error);
  }
}

function renderProcessList() {
  const container = byId("process-list");

  container.replaceChildren();

  const header = document.createElement("div");

  header.className = "process-list-header";

  for (const value of ["PID", "Process", "User", "Integrity"]) {
    const cell = document.createElement("div");

    cell.textContent = value;

    header.appendChild(cell);
  }

  container.appendChild(header);

  if (processState.processes.length === 0) {
    const empty = document.createElement("div");

    empty.className = "empty";

    empty.textContent = "No matching processes.";

    container.appendChild(empty);
  } else {
    for (const process of processState.processes) {
      container.appendChild(createProcessRow(process));
    }
  }

  renderProcessPagination();

  text("process-result-count", `${processState.total} processes`);
}

function createProcessRow(process) {
  const button = document.createElement("button");

  button.type = "button";

  button.className = "process-row";

  if (process.pid === processState.selectedPID) {
    button.classList.add("selected");
  }

  const pid = createProcessCell(String(process.pid || 0), "");

  const name = createProcessCell(process.name || "-", "process-name");

  const user = createProcessCell(
    process.user || "-",
    "process-user process-muted",
  );

  const integrity = createProcessCell(
    process.integrity_level || "-",
    "process-integrity process-muted",
  );

  button.append(pid, name, user, integrity);

  button.addEventListener("click", () => {
    selectProcess(process.pid);
  });

  return button;
}

function createProcessCell(value, extraClass) {
  const cell = document.createElement("div");

  cell.className = `process-cell ${extraClass}`.trim();

  cell.textContent = value;

  return cell;
}

async function selectProcess(pid) {
  processState.selectedPID = pid;

  renderProcessList();

  const container = byId("process-detail");

  container.textContent = "Loading...";

  try {
    const [detail, context] = await Promise.all([
      loadJSON(`/api/processes/${encodeURIComponent(pid)}`),

      loadJSON(`/api/processes/${encodeURIComponent(pid)}/context`),
    ]);

    renderProcessDetail(detail, context);
  } catch (error) {
    container.textContent = String(error);
  }
}

function renderProcessDetail(data, context) {
  const container = byId("process-detail");

  container.replaceChildren();

  const process = data.process || {};

  const title = document.createElement("div");

  title.className = "process-detail-title";

  title.textContent = process.name || "Process";

  const pid = document.createElement("div");

  pid.className = "process-detail-pid";

  pid.textContent = `PID ${process.pid || 0} · PPID ${process.ppid || 0}`;

  container.append(title, pid);

  appendDetailSection(container, "Identity", [
    ["User", process.user],
    ["Session", process.session_id],
    ["Auth ID", process.authentication_id],
    ["Integrity", process.integrity_level],
    ["Start", formatTimestamp(process.start_time)],
  ]);

  appendDetailSection(container, "Executable", [
    ["Path", process.path],
    ["SHA256", data.sha256],
    ["Signed", data.signed ? "Yes" : "No"],
    ["Signer", data.signer],
  ]);

  if (data.command_line) {
    const section = document.createElement("div");

    section.className = "detail-section";

    const heading = document.createElement("div");

    heading.className = "detail-section-title";

    heading.textContent = "Command Line";

    const command = document.createElement("div");

    command.className = "command-line";

    command.textContent = data.command_line;

    section.append(heading, command);

    container.appendChild(section);
  }

  renderProcessRelationships(container, data);

  renderProcessContext(container, context);

  renderProcessActions(container, process);
}

function renderProcessRelationships(container, data) {
  const section = document.createElement("div");

  section.className = "detail-section";

  const heading = document.createElement("div");

  heading.className = "detail-section-title";

  heading.textContent = "Process Relationships";

  section.appendChild(heading);

  if (data.parent) {
    section.appendChild(createRelationshipProcess("Parent", data.parent));
  }

  const children = Array.isArray(data.children) ? data.children : [];

  for (const child of children) {
    section.appendChild(createRelationshipProcess("Child", child));
  }

  if (!data.parent && children.length === 0) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent = "No current parent/child process relationship found.";

    section.appendChild(empty);
  }

  container.appendChild(section);
}

function createRelationshipProcess(relation, process) {
  const button = document.createElement("button");

  button.type = "button";

  button.className = "relationship-card relationship-button";

  const name = process.name || "process";

  button.textContent = `${relation}: ${name} (${process.pid})`;

  button.addEventListener("click", () => {
    selectProcess(process.pid);
  });

  return button;
}

function renderProcessActions(container, process) {
  const actions = document.createElement("div");

  actions.className = "process-actions";

  /*
   * Open Login
   */
  if (process.authentication_id) {
    const loginButton = document.createElement("button");

    loginButton.type = "button";

    loginButton.className = "secondary-button";

    loginButton.textContent = "Open Login";

    loginButton.addEventListener("click", async () => {
      await openLoginByLogonID(
        process.authentication_id,
        investigationSourceFromCurrent(),
      );
    });

    actions.appendChild(loginButton);
  }

  /*
   * Open Network
   */
  if (process.pid) {
    const networkButton = document.createElement("button");

    networkButton.type = "button";

    networkButton.className = "secondary-button";

    networkButton.textContent = "Open Network";

    networkButton.addEventListener("click", async () => {
      await openNetworkByPID(process.pid, investigationSourceFromCurrent());
    });

    actions.appendChild(networkButton);
  }

  /*
   * Timeline
   */
  if (process.pid) {
    const timelineButton = document.createElement("button");

    timelineButton.type = "button";

    timelineButton.className = "primary-button";

    timelineButton.textContent = "Show PID in Timeline";

    timelineButton.addEventListener("click", async () => {
      await openTimelineByQuery("", process.pid);
    });

    actions.appendChild(timelineButton);
  }

  if (actions.childElementCount > 0) {
    container.appendChild(actions);
  }
}

function renderProcessPagination() {
  const start = processState.total === 0 ? 0 : processState.offset + 1;

  const end = Math.min(
    processState.offset + processState.processes.length,
    processState.total,
  );

  text("process-page-info", `${start}-${end} / ${processState.total}`);

  byId("process-prev").disabled = processState.offset === 0;

  byId("process-next").disabled = !processState.hasMore;
}

function resetProcessFilters() {
  byId("process-search").value = "";

  byId("process-user").value = "";

  processState.offset = 0;

  processState.selectedPID = 0;

  const detail = byId("process-detail");

  detail.replaceChildren();

  const empty = document.createElement("div");

  empty.className = "event-detail-empty";

  empty.textContent = "Select a process to investigate.";

  detail.appendChild(empty);

  loadProcesses();
}

function renderProcessContext(container, context) {
  if (!context) {
    return;
  }

  renderProcessContextSummary(container, context.statistics || {});

  renderProcessLoginContext(container, context.login_session);

  renderProcessNetworkContext(container, context.network || []);

  renderHistoricalProcessContext(container, context.historical_processes || []);

  renderPowerShellContext(container, context.powershell || []);
}

function renderProcessContextSummary(container, statistics) {
  appendDetailSection(container, "Related Evidence", [
    ["Network", statistics.network_count ?? 0],
    ["Listeners", statistics.listener_count ?? 0],
    ["External", statistics.external_network_count ?? 0],
    ["Historical", statistics.historical_process_count ?? 0],
    ["PowerShell", statistics.powershell_count ?? 0],
    ["Timeline", statistics.timeline_event_count ?? 0],
  ]);
}

function renderProcessLoginContext(container, login) {
  const section = document.createElement("div");

  section.className = "detail-section";

  const heading = document.createElement("div");

  heading.className = "detail-section-title";

  heading.textContent = "Login Session";

  section.appendChild(heading);

  if (!login) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent = "No exact Logon ID relationship found.";

    section.appendChild(empty);

    container.appendChild(section);

    return;
  }

  appendRowsToSection(section, [
    ["User", [login.domain, login.user].filter(Boolean).join("\\")],
    ["Logon ID", login.logon_id],
    [
      "Logon Type",
      login.logon_type_name
        ? `${login.logon_type} (${login.logon_type_name})`
        : login.logon_type,
    ],
    ["Source IP", login.source_ip],
    ["Workstation", login.workstation],
    ["Auth Package", login.authentication_package],
    ["Privileged", login.privileged ? "Yes" : "No"],
    ["Privileges", login.privileges],
    ["Time", formatTimestamp(login.timestamp)],
    ["Match", login.match_type],
    ["Confidence", login.confidence],
  ]);

  container.appendChild(section);
}

function appendRowsToSection(section, rows) {
  for (const [key, value] of rows) {
    if (value === undefined || value === null || value === "") {
      continue;
    }

    const row = document.createElement("div");

    row.className = "detail-row";

    const keyElement = document.createElement("div");

    keyElement.className = "detail-key";

    keyElement.textContent = key;

    const valueElement = document.createElement("div");

    valueElement.className = "detail-value";

    valueElement.textContent = String(value);

    row.append(keyElement, valueElement);

    section.appendChild(row);
  }
}

function renderProcessNetworkContext(container, connections) {
  const section = document.createElement("div");

  section.className = "detail-section";

  const heading = document.createElement("div");

  heading.className = "detail-section-title";

  heading.textContent = `Network (${connections.length})`;

  section.appendChild(heading);

  if (connections.length === 0) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent = "No network connections in the collected snapshot.";

    section.appendChild(empty);
  } else {
    for (const connection of connections) {
      section.appendChild(createNetworkCard(connection));
    }
  }

  container.appendChild(section);
}

function createNetworkCard(connection) {
  const card = document.createElement("div");

  card.className = "evidence-card";

  if (connection.external) {
    card.classList.add("evidence-card-attention");
  }

  const title = document.createElement("div");

  title.className = "evidence-card-title";

  if (connection.listener) {
    title.textContent = `Listen ${connection.local_address || "*"}:${connection.local_port || 0}`;
  } else if (connection.remote_address) {
    title.textContent =
      `${connection.local_address || "*"}:${connection.local_port || 0}` +
      ` → ` +
      `${connection.remote_address}:${connection.remote_port || 0}`;
  } else {
    title.textContent = `${connection.local_address || "*"}:${connection.local_port || 0}`;
  }

  const meta = document.createElement("div");

  meta.className = "evidence-card-meta";

  const parts = [connection.protocol, connection.family, connection.state];

  if (connection.listener) {
    parts.push("Listener");
  }

  if (connection.external) {
    parts.push("External");
  }

  meta.textContent = parts.filter(Boolean).join(" · ");

  card.append(title, meta);

  return card;
}

function renderHistoricalProcessContext(container, processes) {
  const section = document.createElement("div");

  section.className = "detail-section";

  const heading = document.createElement("div");

  heading.className = "detail-section-title";

  heading.textContent = `Historical Process Evidence (${processes.length})`;

  section.appendChild(heading);

  if (processes.length === 0) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent =
      "No historical process evidence could be confidently associated.";

    section.appendChild(empty);
  } else {
    for (const process of processes) {
      section.appendChild(createHistoricalProcessCard(process));
    }
  }

  container.appendChild(section);
}

function createHistoricalProcessCard(process) {
  const card = document.createElement("div");

  card.className = "evidence-card";

  const title = document.createElement("div");

  title.className = "evidence-card-title";

  title.textContent = `${process.process_name || "Process"} (${process.pid})`;

  const time = document.createElement("div");

  time.className = "evidence-card-meta";

  time.textContent = formatTimestamp(process.timestamp);

  const relation = document.createElement("div");

  relation.className = "evidence-card-meta";

  relation.textContent = `Match: ${process.match_type || "-"} · Confidence: ${process.confidence || "-"}`;

  card.append(title, time, relation);

  if (process.command_line) {
    const command = document.createElement("div");

    command.className = "evidence-command";

    command.textContent = process.command_line;

    card.appendChild(command);
  }

  return card;
}

function scriptPreview(value, maximum = 600) {
  if (!value) {
    return "";
  }

  if (value.length <= maximum) {
    return value;
  }

  return value.slice(0, maximum) + "\n…";
}

function renderPowerShellContext(container, blocks) {
  const section = document.createElement("div");

  section.className = "detail-section";

  const heading = document.createElement("div");

  heading.className = "detail-section-title";

  heading.textContent = `PowerShell (${blocks.length})`;

  section.appendChild(heading);

  if (blocks.length === 0) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent = "No correlated PowerShell ScriptBlock evidence.";

    section.appendChild(empty);
  } else {
    for (const block of blocks) {
      section.appendChild(createPowerShellCard(block));
    }
  }

  container.appendChild(section);
}

function createPowerShellCard(block) {
  const card = document.createElement("div");

  card.className = "evidence-card";

  const title = document.createElement("div");

  title.className = "evidence-card-title";

  title.textContent = block.script_block_id
    ? `ScriptBlock ${block.script_block_id}`
    : "PowerShell ScriptBlock";

  const meta = document.createElement("div");

  meta.className = "evidence-card-meta";

  meta.textContent = [
    formatTimestamp(block.timestamp),
    block.complete ? "Complete" : "Partial",
    block.confidence ? `Confidence: ${block.confidence}` : "",
  ]
    .filter(Boolean)
    .join(" · ");

  card.append(title, meta);

  if (Array.isArray(block.indicators) && block.indicators.length > 0) {
    const indicators = document.createElement("div");

    indicators.className = "indicator-list";

    for (const value of block.indicators) {
      const indicator = document.createElement("span");

      indicator.className = "indicator";

      indicator.textContent = value;

      indicators.appendChild(indicator);
    }

    card.appendChild(indicators);
  }

  if (block.script_text) {
    const code = document.createElement("pre");

    code.className = "evidence-script";

    code.textContent = scriptPreview(block.script_text);

    card.appendChild(code);
  }

  return card;
}

function renderEmptyCorrelation() {
  const graph = byId("correlation-graph");

  graph.replaceChildren();

  const empty = document.createElement("div");

  empty.className = "event-detail-empty";

  empty.textContent =
    "No historical correlation chains or correlated relationships are available.";

  graph.appendChild(empty);

  const detail = byId("correlation-detail");

  detail.replaceChildren();

  const detailEmpty = document.createElement("div");

  detailEmpty.className = "event-detail-empty";

  detailEmpty.textContent = "Select a node or relationship.";

  detail.appendChild(detailEmpty);
}

async function openCorrelation() {
  byId("correlation-section").classList.remove("hidden");

  initializeCorrelationGraph();

  setCorrelationView("graph");

  await loadCorrelation();

  byId("correlation-section").scrollIntoView({
    behavior: "smooth",

    block: "start",
  });
}

async function loadCorrelation() {
  const graph = byId("correlation-graph");

  graph.textContent = "Loading...";

  try {
    const data = await loadJSON("/api/correlation");

    correlationState.data = data;

    correlationState.selectedChainID = "";
    correlationState.selectedGroupID = "";
    correlationState.selectedNodeID = "";
    correlationState.selectedEdgeID = "";

    /*
     * Relationship Group 仅用于 UI 导航。
     * 它由已有 Correlation Edge 的 connected components 构成，
     * 不创建任何新的 evidence relationship。
     */
    correlationState.relationshipGroups = buildCorrelationRelationshipGroups(
      data.nodes || [],
      data.edges || [],
    );

    renderCorrelationStatistics(data.statistics || {});

    text(
      "correlation-subtitle",
      [
        `${data.statistics?.chain_count || 0} historical chains`,
        `${data.statistics?.edge_count || 0} relationships`,
      ].join(" · "),
    );

    const chains = Array.isArray(data.chains) ? data.chains : [];

    /*
     * Case 1:
     * Analyzer 已经构建 HistoricalChain，
     * 优先展示真正的 Historical Chains。
     */
    if (chains.length > 0) {
      setCorrelationMode("chains");

      selectCorrelationChain(chains[0].id);

      return;
    }

    /*
     * Case 2:
     * 没有 HistoricalChain，
     * 但存在真实 Correlation Edges。
     *
     * 自动切换到 Relationships，
     * 避免明明有证据关系却显示一个空页面。
     */
    if (correlationState.relationshipGroups.length > 0) {
      setCorrelationMode("relationships");

      selectCorrelationRelationshipGroup(
        correlationState.relationshipGroups[0].id,
      );

      return;
    }

    /*
     * Case 3:
     * HistoricalChain 和 Correlation Edge 都没有。
     */
    setCorrelationMode("chains");

    renderEmptyCorrelation();
  } catch (error) {
    graph.replaceChildren();

    const message = document.createElement("div");

    message.className = "event-detail-empty";

    message.textContent = `Failed to load correlation data: ${String(error)}`;

    graph.appendChild(message);
  }
}

function renderCorrelationStatistics(statistics) {
  const container = byId("correlation-statistics");

  container.replaceChildren();

  container.append(
    summaryMetric("Nodes", statistics.node_count ?? 0),

    summaryMetric("Edges", statistics.edge_count ?? 0),

    summaryMetric("Chains", statistics.chain_count ?? 0),

    summaryMetric("High Confidence", statistics.high_confidence_edges ?? 0),

    summaryMetric("Medium Confidence", statistics.medium_confidence_edges ?? 0),
  );
}

function renderCorrelationChains(chains) {
  const container = byId("correlation-chain-list");

  container.replaceChildren();

  if (chains.length === 0) {
    const empty = document.createElement("div");

    empty.className = "empty";

    empty.textContent = "No historical chains.";

    container.appendChild(empty);

    return;
  }

  for (const chain of chains) {
    const button = document.createElement("button");

    button.type = "button";

    button.className = "chain-button";

    if (chain.id === correlationState.selectedChainID) {
      button.classList.add("selected");
    }

    const title = document.createElement("div");

    title.className = "chain-title";

    title.textContent = chain.title || chain.id || "Historical Chain";

    const meta = document.createElement("div");

    meta.className = "chain-meta";

    meta.textContent = [
      `${chain.node_count || 0} nodes`,

      `${chain.edge_count || 0} edges`,

      chain.confidence ? `confidence ${chain.confidence}` : "",

      chain.severity ? `severity ${chain.severity}` : "",

      Number.isFinite(chain.score) ? `score ${chain.score}` : "",
    ]
      .filter(Boolean)
      .join(" · ");

    button.append(title, meta);

    button.addEventListener("click", () => {
      selectCorrelationChain(chain.id);
    });

    container.appendChild(button);
  }
}

function correlationNodeMap() {
  const result = new Map();

  for (const node of correlationState.data?.nodes || []) {
    result.set(node.id, node);
  }

  return result;
}

function correlationEdgeMap() {
  const result = new Map();

  for (const edge of correlationState.data?.edges || []) {
    result.set(edge.id, edge);
  }

  return result;
}

function selectCorrelationChain(chainID) {
  correlationState.selectedChainID = chainID;

  correlationState.selectedGroupID = "";

  correlationState.selectedNodeID = "";

  correlationState.selectedEdgeID = "";

  renderCorrelationChains(correlationState.data?.chains || []);

  const chain = correlationState.data?.chains?.find(
    (value) => value.id === chainID,
  );

  if (!chain) {
    return;
  }

  /*
   * 保留 05A List。
   */
  renderCorrelationChain(chain);

  /*
   * 新增 Graph。
   */
  renderInteractiveCorrelationGraph(buildChainGraphElements(chain), {
    type: "chain",
    id: chain.id,
  });

  renderCorrelationChainDetail(chain);
}

function renderCorrelationChainDetail(chain) {
  const container = byId("correlation-detail");

  container.replaceChildren();

  const title = document.createElement("div");

  title.className = "detail-title";

  title.textContent = chain.title || chain.id || "Historical Chain";

  container.appendChild(title);

  appendDetailSection(container, "Chain", [
    ["Severity", chain.severity],
    ["Confidence", chain.confidence],
    ["Score", chain.score],
    ["Start", formatTimestamp(chain.start_time)],
    ["End", formatTimestamp(chain.end_time)],
    ["Nodes", chain.node_count],
    ["Edges", chain.edge_count],
    ["ID", chain.id],
  ]);

  if (chain.summary) {
    appendDetailSection(container, "Summary", [["Value", chain.summary]]);
  }

  if (Array.isArray(chain.reasons) && chain.reasons.length > 0) {
    appendDetailSection(
      container,
      "Reasons",
      chain.reasons.map((reason, index) => [String(index + 1), reason]),
    );
  }
}

function renderCorrelationChain(chain) {
  const container = byId("correlation-graph");

  container.replaceChildren();

  const nodeMap = correlationNodeMap();

  const edgeMap = correlationEdgeMap();

  const nodeIDs = Array.isArray(chain.node_ids) ? chain.node_ids : [];

  const edgeIDs = Array.isArray(chain.edge_ids) ? chain.edge_ids : [];

  if (nodeIDs.length === 0) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent = "Chain contains no nodes.";

    container.appendChild(empty);

    return;
  }

  const graph = document.createElement("div");

  graph.className = "graph-chain";

  for (let index = 0; index < nodeIDs.length; index++) {
    const nodeID = nodeIDs[index];

    const node = nodeMap.get(nodeID);

    if (node) {
      graph.appendChild(createCorrelationNode(node));
    } else {
      graph.appendChild(createMissingCorrelationNode(nodeID));
    }

    if (index >= nodeIDs.length - 1) {
      continue;
    }

    /*
     * HistoricalChain 已经明确给出了 EdgeIDs，
     * Web 不需要重新推导关系。
     */
    const edgeID = edgeIDs[index];

    const edge = edgeID ? edgeMap.get(edgeID) : null;

    if (edge) {
      graph.appendChild(createCorrelationEdge(edge));
    } else {
      graph.appendChild(createMissingCorrelationEdge(edgeID));
    }
  }

  container.appendChild(graph);
}

function createCorrelationNode(node) {
  const button = document.createElement("button");

  button.type = "button";

  button.className = "graph-node";

  button.dataset.nodeType = node.type || "";

  if (node.id === correlationState.selectedNodeID) {
    button.classList.add("selected");
  }

  const type = document.createElement("div");

  type.className = "graph-node-type";

  type.textContent = node.type || "evidence";

  const label = document.createElement("div");

  label.className = "graph-node-label";

  label.textContent = node.object
    ? `${node.label || node.type}: ${node.object}`
    : node.label || node.id;

  button.append(type, label);

  button.addEventListener("click", () => {
    correlationState.selectedNodeID = node.id;

    correlationState.selectedEdgeID = "";

    renderCorrelationNodeDetail(node);

    const chain = correlationState.data.chains.find(
      (value) => value.id === correlationState.selectedChainID,
    );

    if (chain) {
      renderCorrelationChain(chain);
    }
  });

  return button;
}

function createCorrelationEdge(edge) {
  const element = document.createElement("button");

  element.type = "button";

  element.className = "graph-edge";

  element.dataset.confidence = edge.confidence || "";

  element.dataset.edgeType = edge.type || "";

  if (edge.id === correlationState.selectedEdgeID) {
    element.classList.add("selected");
  }

  const line1 = document.createElement("div");

  line1.className = "graph-edge-line";

  const label = document.createElement("div");

  label.className = "graph-edge-label";

  label.textContent = edge.type || "relationship";

  const line2 = document.createElement("div");

  line2.className = "graph-edge-line";

  element.append(line1, label, line2);

  element.addEventListener("click", () => {
    correlationState.selectedEdgeID = edge.id;

    correlationState.selectedNodeID = "";

    renderCorrelationEdgeDetail(edge);

    const chain = correlationState.data.chains.find(
      (value) => value.id === correlationState.selectedChainID,
    );

    if (chain) {
      renderCorrelationChain(chain);
    }
  });

  return element;
}

function renderCorrelationEdgeDetail(edge) {
  const container = byId("correlation-detail");

  container.replaceChildren();

  const title = document.createElement("div");

  title.className = "detail-title";

  title.textContent = edge.type || "Relationship";

  container.appendChild(title);

  appendDetailSection(container, "Relationship", [
    ["From", edge.from],
    ["To", edge.to],
    ["Confidence", edge.confidence],
    ["Score", edge.score],
    ["Time", formatTimestamp(edge.timestamp)],
  ]);

  const basis = Array.isArray(edge.basis) ? edge.basis : [];

  if (basis.length > 0) {
    const section = document.createElement("div");

    section.className = "detail-section";

    const heading = document.createElement("div");

    heading.className = "detail-section-title";

    heading.textContent = "Evidence Basis";

    section.appendChild(heading);

    for (const evidence of basis) {
      const card = document.createElement("div");

      card.className = "evidence-card";

      const name = document.createElement("div");

      name.className = "evidence-card-title";

      name.textContent = evidence.type || "Evidence";

      const value = document.createElement("div");

      value.className = "evidence-card-meta";

      value.textContent = evidence.value || "-";

      card.append(name, value);

      if (evidence.description) {
        const description = document.createElement("div");

        description.className = "evidence-card-description";

        description.textContent = evidence.description;

        card.appendChild(description);
      }

      section.appendChild(card);
    }

    container.appendChild(section);
  }
  renderCorrelationEdgeActions(container, edge);
}

function renderCorrelationNodeDetail(node) {
  const container = byId("correlation-detail");

  if (!container) {
    return;
  }

  container.replaceChildren();

  const title = document.createElement("div");

  title.className = "detail-title";

  title.textContent = node.label || node.object || node.id || "Evidence";

  container.appendChild(title);

  /*
   * 通用 Evidence 信息。
   */
  appendDetailSection(container, "Evidence", [
    ["Type", node.type],
    ["Label", node.label],
    ["Time", formatTimestamp(node.timestamp)],
    ["User", node.user],
    ["Logon ID", node.logon_id],
    ["PID", node.pid],
    ["Object", node.object],
    ["Evidence ID", node.id],
  ]);

  /*
   * PowerShell 专门字段。
   */
  if (node.type === "powershell") {
    appendDetailSection(container, "PowerShell", [
      ["ScriptBlock ID", node.metadata?.script_block_id],
      ["SHA256", node.metadata?.sha256],
      ["Complete", node.metadata?.complete],
    ]);
  }

  /*
   * Remote Session 专门字段。
   */
  if (node.type === "remote_session") {
    appendDetailSection(container, "Remote Session", [
      ["Session ID", node.metadata?.session_id],
      ["Source Address", node.metadata?.source_address],
    ]);
  }

  /*
   * WMI 专门字段。
   */
  if (node.type === "wmi") {
    appendDetailSection(container, "WMI Activity", [
      ["Namespace", node.metadata?.namespace],
      ["Operation", node.metadata?.operation],
      ["Result", node.metadata?.result],
    ]);
  }

  /*
   * 通用 Metadata。
   *
   * 即使上面已经把 PowerShell / RDP / WMI
   * 的常用字段做了语义化展示，
   * 这里仍然保留完整 Metadata，
   * 防止将来 Analyzer 新增字段时 Web 丢数据。
   */
  if (node.metadata && typeof node.metadata === "object") {
    const metadataRows = Object.entries(node.metadata).filter(
      ([, value]) => value !== undefined && value !== null && value !== "",
    );

    if (metadataRows.length > 0) {
      appendDetailSection(container, "Metadata", metadataRows);
    }
  }

  /*
   * Cross-workspace actions。
   */
  renderCorrelationNodeActions(container, node);
}

function correlationNodeHasProcessPivot(node) {
  return node.type === "process" || node.type === "historical_process";
}

function renderCorrelationNodeActions(container, node) {
  const pivot = correlationNodePivot(node);

  const actions = document.createElement("div");

  actions.className = "process-actions";

  /*
   * Current Process
   */
  if (pivot.kind === "current_process" && pivot.pid) {
    const processButton = document.createElement("button");

    processButton.type = "button";

    processButton.className = "primary-button";

    processButton.textContent = "Open Process";

    processButton.addEventListener("click", async () => {
      await openCorrelationCurrentProcess(node);
    });

    actions.appendChild(processButton);
  }

  /*
   * 所有 evidence 类型都可以通过 Timeline
   * 做历史 Pivot。
   */
  const timelineButton = document.createElement("button");

  timelineButton.type = "button";

  timelineButton.className = "secondary-button";

  timelineButton.textContent = correlationTimelineButtonLabel(pivot);

  timelineButton.addEventListener("click", async () => {
    await openTimelineByQuery(
      pivot.query || "",
      pivot.kind === "current_process" ? pivot.pid : 0,
    );
  });

  actions.appendChild(timelineButton);

  container.appendChild(actions);
}

function renderCorrelationChainDetail(chain) {
  const container = byId("correlation-detail");

  container.replaceChildren();

  const title = document.createElement("div");

  title.className = "detail-title";

  title.textContent = chain.id || "Historical Chain";

  container.appendChild(title);

  appendDetailSection(container, "Chain", [
    ["Severity", chain.severity],
    ["Confidence", chain.confidence],
    ["Score", chain.score],
    ["Nodes", chain.node_count],
    ["Edges", chain.edge_count],
  ]);
}

function buildCorrelationRelationshipGroups(nodes, edges) {
  const nodeMap = new Map();

  for (const node of nodes || []) {
    nodeMap.set(node.id, node);
  }

  /*
   * adjacency 只由真实 Edge 建立。
   * 不创造任何新的 evidence relationship。
   */
  const adjacency = new Map();

  function addNeighbor(from, to) {
    if (!adjacency.has(from)) {
      adjacency.set(from, new Set());
    }

    adjacency.get(from).add(to);
  }

  for (const edge of edges || []) {
    if (!edge.from || !edge.to) {
      continue;
    }

    /*
     * Connected Component 导航阶段
     * 使用无向连接性。
     *
     * Edge 本身的方向仍然完整保留，
     * 展示时仍然使用 from → to。
     */
    addNeighbor(edge.from, edge.to);

    addNeighbor(edge.to, edge.from);
  }

  const visited = new Set();

  const groups = [];

  for (const nodeID of adjacency.keys()) {
    if (visited.has(nodeID)) {
      continue;
    }

    const queue = [nodeID];

    const componentNodeIDs = [];

    visited.add(nodeID);

    while (queue.length > 0) {
      const current = queue.shift();

      componentNodeIDs.push(current);

      for (const neighbor of adjacency.get(current) || []) {
        if (visited.has(neighbor)) {
          continue;
        }

        visited.add(neighbor);

        queue.push(neighbor);
      }
    }

    const componentSet = new Set(componentNodeIDs);

    const componentEdges = (edges || []).filter(
      (edge) => componentSet.has(edge.from) && componentSet.has(edge.to),
    );

    const componentNodes = componentNodeIDs
      .map((id) => nodeMap.get(id))
      .filter(Boolean);

    groups.push({
      id: `relationship-group-${groups.length + 1}`,

      node_ids: componentNodeIDs,

      nodes: componentNodes,

      edges: componentEdges,
    });
  }

  /*
   * 有更多 Edge 的 Group 优先，
   * 便于调查人员首先看到复杂关系集合。
   */
  groups.sort((left, right) => {
    if (right.edges.length !== left.edges.length) {
      return right.edges.length - left.edges.length;
    }

    return right.nodes.length - left.nodes.length;
  });

  /*
   * 排序后重新生成稳定的 UI 编号。
   */
  groups.forEach((group, index) => {
    group.id = `relationship-group-${index + 1}`;
  });

  return groups;
}

function setCorrelationMode(mode) {
  correlationState.mode = mode;

  correlationState.selectedNodeID = "";
  correlationState.selectedEdgeID = "";

  const chainsButton = byId("correlation-tab-chains");

  const relationshipsButton = byId("correlation-tab-relationships");

  chainsButton.classList.toggle("selected", mode === "chains");

  relationshipsButton.classList.toggle("selected", mode === "relationships");

  if (mode === "chains") {
    renderCorrelationChains(correlationState.data?.chains || []);

    return;
  }

  renderCorrelationRelationshipGroups(correlationState.relationshipGroups);
}

function renderCorrelationRelationshipGroups(groups) {
  const container = byId("correlation-chain-list");

  container.replaceChildren();

  if (groups.length === 0) {
    const empty = document.createElement("div");

    empty.className = "empty";

    empty.textContent = "No correlated relationships.";

    container.appendChild(empty);

    return;
  }

  for (const group of groups) {
    const button = document.createElement("button");

    button.type = "button";

    button.className = "chain-button";

    if (group.id === correlationState.selectedGroupID) {
      button.classList.add("selected");
    }

    const title = document.createElement("div");

    title.className = "chain-title";

    title.textContent = relationshipGroupTitle(group);

    const meta = document.createElement("div");

    meta.className = "chain-meta";

    meta.textContent = [
      `${group.nodes.length} nodes`,
      `${group.edges.length} relationships`,
      relationshipGroupConfidence(group),
    ]
      .filter(Boolean)
      .join(" · ");

    button.append(title, meta);

    button.addEventListener("click", () => {
      selectCorrelationRelationshipGroup(group.id);
    });

    container.appendChild(button);
  }
}

function relationshipGroupTitle(group) {
  const labels = group.nodes
    .slice(0, 2)
    .map((node) => node.label || node.type || node.id);

  if (labels.length === 0) {
    return group.id;
  }

  if (group.nodes.length > 2) {
    labels.push(`+${group.nodes.length - 2}`);
  }

  return labels.join(" · ");
}

function relationshipGroupConfidence(group) {
  const confidences = group.edges.map((edge) =>
    String(edge.confidence || "").toLowerCase(),
  );

  if (confidences.length === 0) {
    return "";
  }

  if (confidences.every((value) => value === "high")) {
    return "all high confidence";
  }

  if (confidences.some((value) => value === "low")) {
    return "mixed confidence";
  }

  if (confidences.some((value) => value === "medium")) {
    return "mixed confidence";
  }

  return "";
}

function selectCorrelationRelationshipGroup(groupID) {
  correlationState.selectedGroupID = groupID;

  correlationState.selectedChainID = "";

  correlationState.selectedNodeID = "";

  correlationState.selectedEdgeID = "";

  renderCorrelationRelationshipGroups(correlationState.relationshipGroups);

  const group = correlationState.relationshipGroups.find(
    (value) => value.id === groupID,
  );

  if (!group) {
    return;
  }

  /*
   * 05B 原来的 List。
   */
  renderCorrelationRelationshipGroup(group);

  /*
   * 新的 Graph。
   */
  renderInteractiveCorrelationGraph(
    buildRelationshipGroupGraphElements(group),
    {
      type: "relationship_group",

      id: group.id,
    },
  );

  renderCorrelationRelationshipGroupDetail(group);
}

function renderCorrelationRelationshipGroup(group) {
  const container = byId("correlation-graph");

  container.replaceChildren();

  const nodeMap = correlationNodeMap();

  const wrapper = document.createElement("div");

  wrapper.className = "relationship-edge-list";

  for (const edge of group.edges) {
    const from = nodeMap.get(edge.from);

    const to = nodeMap.get(edge.to);

    wrapper.appendChild(createCorrelationRelationshipCard(edge, from, to));
  }

  container.appendChild(wrapper);
}

function createCorrelationRelationshipCard(edge, from, to) {
  const card = document.createElement("div");

  card.className = "relationship-card";

  const fromButton = from
    ? createCompactCorrelationNode(from)
    : createMissingCorrelationNode(edge.from);

  const relationship = document.createElement("button");

  relationship.type = "button";

  relationship.className = "relationship-card-edge";

  relationship.dataset.confidence = edge.confidence || "";

  const edgeType = document.createElement("strong");

  edgeType.textContent = edge.type || "relationship";

  const confidence = document.createElement("span");

  confidence.textContent = [
    edge.confidence,
    Number.isFinite(edge.score) ? `score ${edge.score}` : "",
  ]
    .filter(Boolean)
    .join(" · ");

  relationship.append(edgeType, confidence);

  relationship.addEventListener("click", () => {
    correlationState.selectedEdgeID = edge.id;

    correlationState.selectedNodeID = "";

    renderCorrelationEdgeDetail(edge);
  });

  const toButton = to
    ? createCompactCorrelationNode(to)
    : createMissingCorrelationNode(edge.to);

  card.append(fromButton, relationship, toButton);

  return card;
}

function createCompactCorrelationNode(node) {
  const button = document.createElement("button");

  button.type = "button";

  button.className = "compact-correlation-node";

  button.dataset.nodeType = node.type || "";

  const type = document.createElement("span");

  type.className = "compact-node-type";

  type.textContent = node.type || "evidence";

  const label = document.createElement("strong");

  label.textContent = node.label || node.object || node.id;

  const meta = document.createElement("span");

  meta.className = "compact-node-meta";

  meta.textContent = [
    node.pid ? `PID ${node.pid}` : "",

    node.timestamp ? formatTimestamp(node.timestamp) : "",
  ]
    .filter(Boolean)
    .join(" · ");

  button.append(type, label, meta);

  button.addEventListener("click", () => {
    correlationState.selectedNodeID = node.id;

    correlationState.selectedEdgeID = "";

    renderCorrelationNodeDetail(node);
  });

  return button;
}

function renderCorrelationRelationshipGroupDetail(group) {
  const container = byId("correlation-detail");

  container.replaceChildren();

  const title = document.createElement("div");

  title.className = "detail-title";

  title.textContent = "Relationship Group";

  container.appendChild(title);

  appendDetailSection(container, "Graph Component", [
    ["Nodes", group.nodes.length],
    ["Relationships", group.edges.length],
    ["Confidence", relationshipGroupConfidence(group)],
  ]);

  const note = document.createElement("div");

  note.className = "correlation-note";

  note.textContent =
    "This group is a navigation view of connected correlation edges. It is not an analyzer-generated HistoricalChain.";

  container.appendChild(note);
}

function initializeCorrelationGraph() {
  const container = byId("correlation-graph-canvas");

  if (typeof window.cytoscape !== "function") {
    container.textContent = "Correlation graph library is unavailable.";

    return;
  }

  if (correlationState.cy) {
    return;
  }

  correlationState.cy = window.cytoscape({
    container,

    elements: [],

    minZoom: 0.2,

    maxZoom: 3,

    wheelSensitivity: 0.2,

    selectionType: "single",

    boxSelectionEnabled: false,

    autoungrabify: false,

    style: correlationGraphStyles(),

    layout: {
      name: "preset",
    },
  });

  wireCorrelationGraphEvents();
}

function correlationGraphStyles() {
  return [
    {
      selector: "node",

      style: {
        "background-color": "#182431",

        "border-width": 1,

        "border-color": "#415469",

        label: "data(label)",

        color: "#e7edf4",

        "font-size": 10,

        "text-wrap": "wrap",

        "text-max-width": 150,

        "text-valign": "center",

        "text-halign": "center",

        width: 150,

        height: 54,

        shape: "round-rectangle",

        padding: 8,
      },
    },

    {
      selector: 'node[nodeType = "login"]',

      style: {
        "border-width": 3,
      },
    },

    {
      selector: 'node[nodeType = "historical_process"]',

      style: {
        shape: "round-rectangle",
      },
    },

    {
      selector: 'node[nodeType = "powershell"]',

      style: {
        shape: "round-rectangle",
      },
    },

    {
      selector: 'node[nodeType = "remote_session"]',

      style: {
        shape: "round-rectangle",
      },
    },

    {
      selector: 'node[nodeType = "wmi"]',

      style: {
        shape: "round-rectangle",
      },
    },

    {
      selector: "edge",

      style: {
        width: 1.5,

        "line-color": "#52677d",

        "target-arrow-color": "#52677d",

        "target-arrow-shape": "triangle",

        "curve-style": "bezier",

        label: "data(label)",

        "font-size": 8,

        color: "#98aabd",

        "text-background-color": "#0c141c",

        "text-background-opacity": 0.85,

        "text-background-padding": 3,
      },
    },

    {
      selector: 'edge[confidence = "high"]',

      style: {
        width: 2.5,
      },
    },

    {
      selector: 'edge[confidence = "medium"]',

      style: {
        "line-style": "dashed",
      },
    },

    {
      selector: 'edge[confidence = "low"]',

      style: {
        "line-style": "dotted",

        opacity: 0.7,
      },
    },

    {
      selector: ".graph-selected",

      style: {
        "border-width": 3,

        "border-color": "#d8e5f2",

        "z-index": 100,
      },
    },

    {
      selector: "edge.graph-selected",

      style: {
        width: 4,

        "line-color": "#d8e5f2",

        "target-arrow-color": "#d8e5f2",
      },
    },

    {
      selector: ".graph-neighbor",

      style: {
        opacity: 1,
      },
    },

    {
      selector: ".graph-dimmed",

      style: {
        opacity: 0.18,
      },
    },
  ];
}

function correlationNodeToElement(node) {
  let label = node.label || node.object || node.id;

  if (node.object && node.label) {
    label = `${node.label}\n${node.object}`;
  }

  if (node.pid) {
    label += `\nPID ${node.pid}`;
  }

  return {
    group: "nodes",

    data: {
      id: node.id,

      label,

      nodeType: node.type || "evidence",

      pid: node.pid || 0,

      evidence: node,
    },
  };
}

function correlationEdgeToElement(edge) {
  return {
    group: "edges",

    data: {
      id: edge.id,

      source: edge.from,

      target: edge.to,

      label: edge.type || "relationship",

      edgeType: edge.type || "",

      confidence: edge.confidence || "",

      score: edge.score ?? 0,

      evidence: edge,
    },
  };
}

function buildChainGraphElements(chain) {
  const nodeMap = correlationNodeMap();

  const edgeMap = correlationEdgeMap();

  const elements = [];

  const includedNodeIDs = new Set();

  for (const nodeID of chain.node_ids || []) {
    const node = nodeMap.get(nodeID);

    if (!node) {
      continue;
    }

    elements.push(correlationNodeToElement(node));

    includedNodeIDs.add(nodeID);
  }

  for (const edgeID of chain.edge_ids || []) {
    const edge = edgeMap.get(edgeID);

    if (!edge) {
      continue;
    }

    /*
     * 两端 Node 都存在时才交给 Cytoscape。
     */
    if (!includedNodeIDs.has(edge.from) || !includedNodeIDs.has(edge.to)) {
      continue;
    }

    elements.push(correlationEdgeToElement(edge));
  }

  return elements;
}

function buildRelationshipGroupGraphElements(group) {
  const elements = [];

  const nodeIDs = new Set();

  for (const node of group.nodes || []) {
    elements.push(correlationNodeToElement(node));

    nodeIDs.add(node.id);
  }

  for (const edge of group.edges || []) {
    if (!nodeIDs.has(edge.from) || !nodeIDs.has(edge.to)) {
      continue;
    }

    elements.push(correlationEdgeToElement(edge));
  }

  return elements;
}

function renderInteractiveCorrelationGraph(elements, context) {
  initializeCorrelationGraph();

  const cy = correlationState.cy;

  if (!cy) {
    return;
  }

  correlationState.graphContext = context;

  correlationState.selectedNodeID = "";

  correlationState.selectedEdgeID = "";

  cy.elements().remove();

  cy.add(elements);

  correlationState.filters.nodeTypes.clear();

  correlationState.filters.confidence = "all";

  correlationState.filters.query = "";

  const search = byId("correlation-search");

  if (search) {
    search.value = "";
  }

  const confidence = byId("correlation-confidence");

  if (confidence) {
    confidence.value = "all";
  }

  renderCorrelationNodeTypeFilters(collectGraphNodeTypes(elements));

  if (cy.nodes().length === 0) {
    return;
  }

  /*
   * Chain 优先使用 breadthfirst，
   * Relationship Group 使用 cose。
   */
  const layoutName = context?.type === "chain" ? "breadthfirst" : "cose";

  const layoutOptions =
    layoutName === "breadthfirst"
      ? {
          name: "breadthfirst",

          directed: true,

          spacingFactor: 1.3,

          padding: 40,

          animate: false,
        }
      : {
          name: "cose",

          animate: false,

          fit: true,

          padding: 40,

          nodeRepulsion: 7000,

          idealEdgeLength: 130,

          edgeElasticity: 100,
        };

  cy.layout(layoutOptions).run();

  applyCorrelationGraphFilters();

  cy.fit(cy.elements(), 45);
}

function wireCorrelationGraphEvents() {
  const cy = correlationState.cy;

  if (!cy) {
    return;
  }

  cy.on("tap", "node", (event) => {
    const element = event.target;

    const node = element.data("evidence");

    if (!node) {
      return;
    }

    correlationState.selectedNodeID = node.id;

    correlationState.selectedEdgeID = "";

    highlightCorrelationNode(element);

    renderCorrelationNodeDetail(node);
  });

  cy.on("tap", "edge", (event) => {
    const element = event.target;

    const edge = element.data("evidence");

    if (!edge) {
      return;
    }

    correlationState.selectedEdgeID = edge.id;

    correlationState.selectedNodeID = "";

    highlightCorrelationEdge(element);

    renderCorrelationEdgeDetail(edge);
  });

  /*
   * 点击空白区域：
   * 清除 Highlight。
   */
  cy.on("tap", (event) => {
    if (event.target !== cy) {
      return;
    }

    clearCorrelationGraphHighlight();

    restoreCorrelationContextDetail();
  });
}

function highlightCorrelationNode(node) {
  const cy = correlationState.cy;

  if (!cy) {
    return;
  }

  cy.elements()
    .removeClass("graph-selected")
    .removeClass("graph-neighbor")
    .removeClass("graph-dimmed");

  const neighborhood = node.closedNeighborhood();

  cy.elements().difference(neighborhood).addClass("graph-dimmed");

  neighborhood.addClass("graph-neighbor");

  node.addClass("graph-selected");
}

function highlightCorrelationEdge(edge) {
  const cy = correlationState.cy;

  if (!cy) {
    return;
  }

  cy.elements()
    .removeClass("graph-selected")
    .removeClass("graph-neighbor")
    .removeClass("graph-dimmed");

  const related = edge.connectedNodes().union(edge);

  cy.elements().difference(related).addClass("graph-dimmed");

  related.addClass("graph-neighbor");

  edge.addClass("graph-selected");
}

function clearCorrelationGraphHighlight() {
  const cy = correlationState.cy;

  if (!cy) {
    return;
  }

  cy.elements()
    .removeClass("graph-selected")
    .removeClass("graph-neighbor")
    .removeClass("graph-dimmed");

  correlationState.selectedNodeID = "";

  correlationState.selectedEdgeID = "";
}

function restoreCorrelationContextDetail() {
  if (correlationState.mode === "chains") {
    const chain = correlationState.data?.chains?.find(
      (value) => value.id === correlationState.selectedChainID,
    );

    if (chain) {
      renderCorrelationChainDetail(chain);
    }

    return;
  }

  const group = correlationState.relationshipGroups.find(
    (value) => value.id === correlationState.selectedGroupID,
  );

  if (group) {
    renderCorrelationRelationshipGroupDetail(group);
  }
}

function setCorrelationView(view) {
  correlationState.view = view;

  const graphButton = byId("correlation-view-graph");

  const listButton = byId("correlation-view-list");

  const canvas = byId("correlation-graph-canvas");

  const list = byId("correlation-graph");

  const isGraph = view === "graph";

  graphButton.classList.toggle("selected", isGraph);

  listButton.classList.toggle("selected", !isGraph);

  canvas.classList.toggle("hidden", !isGraph);

  list.classList.toggle("hidden", isGraph);

  if (isGraph && correlationState.cy) {
    /*
     * display:none → visible 后，
     * Cytoscape 需要 resize。
     */
    requestAnimationFrame(() => {
      correlationState.cy.resize();

      correlationState.cy.fit(correlationState.cy.elements(), 45);
    });
  }
}

function fitCorrelationGraph() {
  const cy = correlationState.cy;

  if (!cy || cy.elements().length === 0) {
    return;
  }

  cy.fit(cy.elements(), 45);
}

function zoomCorrelationGraph(factor) {
  const cy = correlationState.cy;

  if (!cy) {
    return;
  }

  const nextZoom = Math.max(
    cy.minZoom(),
    Math.min(cy.maxZoom(), cy.zoom() * factor),
  );

  cy.zoom({
    level: nextZoom,

    renderedPosition: {
      x: cy.width() / 2,

      y: cy.height() / 2,
    },
  });
}

function resetCorrelationGraph() {
  clearCorrelationGraphHighlight();

  const cy = correlationState.cy;

  if (!cy) {
    return;
  }

  const context = correlationState.graphContext;

  if (context?.type === "chain") {
    cy.layout({
      name: "breadthfirst",

      directed: true,

      spacingFactor: 1.3,

      padding: 40,

      animate: false,
    }).run();
  } else {
    cy.layout({
      name: "cose",

      animate: false,

      fit: true,

      padding: 40,

      nodeRepulsion: 7000,

      idealEdgeLength: 130,
    }).run();
  }

  fitCorrelationGraph();

  restoreCorrelationContextDetail();
}

function correlationNodeHasCurrentProcessPivot(node) {
  if (!node || !node.pid) {
    return false;
  }

  const id = String(node.id || "");

  /*
   * historical-process:* 明确不是 current snapshot process。
   */
  if (id.startsWith("historical-process:")) {
    return false;
  }

  return node.type === "current_process" || id.startsWith("current-process:");
}

function renderCorrelationNodeActions(container, node) {
  /*
   * Current Process Pivot
   * 必须有明确的 current-process 语义。
   */
  if (!correlationNodeHasCurrentProcessPivot(node)) {
    renderCorrelationTimelineAction(container, node);

    return;
  }

  // Open Process...
}

function collectGraphNodeTypes(elements) {
  const types = new Set();

  for (const element of elements || []) {
    if (element.group !== "nodes") {
      continue;
    }

    const type = element.data?.nodeType;

    if (!type) {
      continue;
    }

    types.add(type);
  }

  return Array.from(types).sort();
}

function renderCorrelationNodeTypeFilters(types) {
  correlationState.availableNodeTypes = types;

  const container = byId("correlation-node-type-filters");

  if (!container) {
    return;
  }

  container.replaceChildren();

  for (const type of types) {
    const button = document.createElement("button");

    button.type = "button";

    button.className = "correlation-node-type-button";

    button.textContent = type;

    button.dataset.nodeType = type;

    /*
     * Set 为空表示不过滤，即所有类型可见。
     */
    if (correlationState.filters.nodeTypes.has(type)) {
      button.classList.add("selected");
    }

    button.addEventListener("click", () => {
      toggleCorrelationNodeType(type);
    });

    container.appendChild(button);
  }
}

function toggleCorrelationNodeType(type) {
  const selected = correlationState.filters.nodeTypes;

  if (selected.has(type)) {
    selected.delete(type);
  } else {
    selected.add(type);
  }

  renderCorrelationNodeTypeFilters(correlationState.availableNodeTypes);

  applyCorrelationGraphFilters();
}

function applyCorrelationGraphFilters() {
  const cy = correlationState.cy;

  if (!cy) {
    return;
  }

  const selectedTypes = correlationState.filters.nodeTypes;

  const confidence = correlationState.filters.confidence;

  const query = normalizeCorrelationSearchQuery(correlationState.filters.query);

  cy.batch(() => {
    /*
     * 先全部恢复。
     */
    cy.elements().show();

    /*
     * Node Type + Search。
     */
    cy.nodes().forEach((node) => {
      const evidence = node.data("evidence");

      const type = node.data("nodeType");

      const typeMatches = selectedTypes.size === 0 || selectedTypes.has(type);

      const queryMatches =
        !query || correlationNodeMatchesQuery(evidence, query);

      if (!typeMatches || !queryMatches) {
        node.hide();
      }
    });

    /*
     * Edge Confidence + Search。
     */
    cy.edges().forEach((edge) => {
      const evidence = edge.data("evidence");

      const source = edge.source();

      const target = edge.target();

      /*
       * 任意一端 Node 被隐藏，
       * 该 Edge 也不能显示。
       */
      if (!source.visible() || !target.visible()) {
        edge.hide();

        return;
      }

      const confidenceMatches =
        confidence === "all" ||
        String(edge.data("confidence") || "").toLowerCase() === confidence;

      /*
       * 有搜索词时：
       * Node 匹配即可保留相关 Edge，
       * 或 Edge 自身 Basis / ID / Type 匹配。
       */
      const queryMatches =
        !query ||
        correlationEdgeMatchesQuery(evidence, query) ||
        correlationNodeMatchesQuery(source.data("evidence"), query) ||
        correlationNodeMatchesQuery(target.data("evidence"), query);

      if (!confidenceMatches || !queryMatches) {
        edge.hide();
      }
    });
  });

  clearCorrelationGraphHighlight();

  updateCorrelationFilterStatus();
}

function normalizeCorrelationSearchQuery(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function correlationNodeMatchesQuery(node, query) {
  if (!node || !query) {
    return true;
  }

  const values = [
    node.id,
    node.type,
    node.label,
    node.object,
    node.user,
    node.logon_id,
  ];

  if (node.pid !== undefined && node.pid !== null) {
    values.push(String(node.pid));

    values.push(`pid ${node.pid}`);
  }

  if (node.metadata && typeof node.metadata === "object") {
    for (const [key, value] of Object.entries(node.metadata)) {
      values.push(key);

      values.push(value);

      /*
       * 可以匹配：
       * logon_id:0x3e7
       */
      values.push(`${key}:${value}`);
    }
  }

  return values.some((value) =>
    String(value || "")
      .toLowerCase()
      .includes(query),
  );
}

function correlationEdgeMatchesQuery(edge, query) {
  if (!edge || !query) {
    return true;
  }

  const values = [
    edge.id,
    edge.from,
    edge.to,
    edge.type,
    edge.confidence,
    edge.score,
  ];

  for (const basis of edge.basis || []) {
    values.push(basis.type, basis.value, basis.description);
  }

  return values.some((value) =>
    String(value || "")
      .toLowerCase()
      .includes(query),
  );
}

function updateCorrelationFilterStatus() {
  const status = byId("correlation-filter-status");

  const cy = correlationState.cy;

  if (!status || !cy) {
    return;
  }

  const visibleNodes = cy.nodes(":visible").length;

  const visibleEdges = cy.edges(":visible").length;

  const totalNodes = cy.nodes().length;

  const totalEdges = cy.edges().length;

  status.textContent =
    `${visibleNodes} / ${totalNodes} nodes · ` +
    `${visibleEdges} / ${totalEdges} relationships`;
}

function clearCorrelationFiltersState() {
  correlationState.filters.nodeTypes.clear();

  correlationState.filters.confidence = "all";

  correlationState.filters.query = "";

  const search = byId("correlation-search");

  if (search) {
    search.value = "";
  }

  const confidence = byId("correlation-confidence");

  if (confidence) {
    confidence.value = "all";
  }

  renderCorrelationNodeTypeFilters(correlationState.availableNodeTypes);

  applyCorrelationGraphFilters();

  fitCorrelationGraph();
}

function focusUniqueCorrelationSearchResult() {
  const cy = correlationState.cy;

  if (!cy) {
    return;
  }

  const nodes = cy.nodes(":visible");

  if (nodes.length !== 1) {
    return;
  }

  const node = nodes[0];

  cy.animate({
    center: {
      eles: node,
    },

    zoom: Math.max(cy.zoom(), 1.2),

    duration: 200,
  });

  const evidence = node.data("evidence");

  if (evidence) {
    highlightCorrelationNode(node);

    renderCorrelationNodeDetail(evidence);
  }
}

function correlationNodePivot(node) {
  const id = String(node.id || "");

  /*
   * Historical Process
   *
   * 注意：
   * historical_correlation.json 中
   * Historical Process 的 type 也是 "process"。
   *
   * 因此不能仅靠 node.type 判断。
   */
  if (id.startsWith("historical-process:")) {
    return {
      kind: "historical_process",

      query: node.id || node.object || String(node.pid || ""),
    };
  }

  /*
   * PowerShell ScriptBlock
   */
  if (node.type === "powershell" || id.startsWith("powershell-script:")) {
    return {
      kind: "powershell",

      query: correlationPowerShellQuery(node),
    };
  }

  /*
   * Generic Windows Event evidence.
   */
  if (
    node.type === "remote_session" ||
    node.type === "wmi" ||
    node.type === "task" ||
    node.type === "scheduled_task" ||
    id.startsWith("win-event:")
  ) {
    return {
      kind: "windows_event",

      query: correlationWindowsEventQuery(node),
    };
  }

  /*
   * Current Process
   *
   * 只有在将来 Correlation Node 明确使用
   * current-process / current_process 之类的
   * identity 时才允许直接 Pivot 到当前 Process。
   *
   * 不要因为 type == "process" 就认为是 Current Process。
   */
  if (node.type === "current_process" || id.startsWith("current-process:")) {
    return {
      kind: "current_process",

      pid: node.pid,

      query: node.id || "",
    };
  }

  /*
   * 其它 evidence 默认去 Timeline。
   */
  return {
    kind: "timeline",

    query: node.id || node.label || node.object || "",
  };
}

function correlationPowerShellQuery(node) {
  const scriptBlockID = node.metadata?.script_block_id;

  if (scriptBlockID) {
    return scriptBlockID;
  }

  if (node.object) {
    return node.object;
  }

  if (node.id) {
    return node.id;
  }

  return node.label || "";
}

function correlationWindowsEventQuery(node) {
  /*
   * 优先 label，因为 timeline 本身已有
   * activity type / description 搜索。
   */
  if (node.label) {
    return node.label;
  }

  if (node.id) {
    return node.id;
  }

  return "";
}

async function openCorrelationCurrentProcess(node) {
  if (!node.pid) {
    return;
  }

  const section = byId("process-section");

  if (!section) {
    return;
  }

  section.classList.remove("hidden");

  await selectProcess(node.pid);

  section.scrollIntoView({
    behavior: "smooth",

    block: "start",
  });
}
// 按钮文字按 Evidence 类型变化
function correlationTimelineButtonLabel(pivot) {
  switch (pivot.kind) {
    case "powershell":
      return "Show PowerShell in Timeline";

    case "windows_event":
      return "Show Windows Event in Timeline";

    case "historical_process":
      return "Show Historical Process in Timeline";

    case "current_process":
      return "Show PID in Timeline";

    default:
      return "Show Evidence in Timeline";
  }
}

function findCorrelationNodeByID(id) {
  return correlationState.data?.nodes?.find((node) => node.id === id) || null;
}

function renderCorrelationEdgeActions(container, edge) {
  const from = findCorrelationNodeByID(edge.from);

  const to = findCorrelationNodeByID(edge.to);

  if (!from && !to) {
    return;
  }

  const actions = document.createElement("div");

  actions.className = "process-actions";

  if (from) {
    const button = document.createElement("button");

    button.type = "button";

    button.className = "secondary-button";

    button.textContent = "Open From Evidence";

    button.addEventListener("click", () => {
      selectCorrelationNodeInGraph(from.id);
    });

    actions.appendChild(button);
  }

  if (to) {
    const button = document.createElement("button");

    button.type = "button";

    button.className = "secondary-button";

    button.textContent = "Open To Evidence";

    button.addEventListener("click", () => {
      selectCorrelationNodeInGraph(to.id);
    });

    actions.appendChild(button);
  }

  const timelineButton = document.createElement("button");

  timelineButton.type = "button";

  timelineButton.className = "secondary-button";

  timelineButton.textContent = "Show Relationship Evidence in Timeline";

  timelineButton.addEventListener("click", async () => {
    await openTimelineByQuery(correlationEdgeTimelineQuery(edge));
  });

  actions.appendChild(timelineButton);

  container.appendChild(actions);
}

// 通过 ID 在 Graph 中选择节点
function selectCorrelationNodeInGraph(nodeID) {
  const cy = correlationState.cy;

  if (!cy) {
    return;
  }

  const element = cy.getElementById(nodeID);

  if (!element || element.empty()) {
    return;
  }

  /*
   * Smart Pivot 进入新 Group 后，
   * 避免旧 Filter 把目标隐藏。
   */
  clearCorrelationFiltersState();

  element.show();

  const connectedEdges = element.connectedEdges();

  connectedEdges.show();

  connectedEdges.connectedNodes().show();

  cy.animate({
    center: {
      eles: element,
    },

    zoom: Math.max(cy.zoom(), 1.15),

    duration: 200,
  });

  const node = element.data("evidence");

  highlightCorrelationNode(element);

  if (node) {
    renderCorrelationNodeDetail(node);
  }
}

function correlationEdgeTimelineQuery(edge) {
  for (const basis of edge.basis || []) {
    if (basis.value) {
      return basis.value;
    }
  }

  return edge.type || edge.id || "";
}

async function runGlobalSearch() {
  const input = byId("global-search-input");

  const results = byId("global-search-results");

  const status = byId("global-search-status");

  if (!input || !results || !status) {
    return;
  }

  const query = input.value.trim();

  results.replaceChildren();

  byId("global-search-type-stats")?.replaceChildren();

  if (!query) {
    status.textContent = "";

    return;
  }

  status.textContent = "Searching...";

  const type = byId("global-search-type")?.value || "";

  let url = `/api/search?q=${encodeURIComponent(query)}`;

  if (type) {
    url += `&type=${encodeURIComponent(type)}`;
  }

  try {
    const data = await loadJSON(url);

    renderGlobalSearchTypeStats(data.by_type || {});

    renderGlobalSearchResults(data.results || []);

    status.textContent = `${data.total || 0} matching evidence records`;
  } catch (error) {
    status.textContent = `Search failed: ${String(error)}`;
  }
}

function renderGlobalSearchResults(results) {
  const container = byId("global-search-results");

  container.replaceChildren();

  if (results.length === 0) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent = "No matching evidence.";

    container.appendChild(empty);

    return;
  }

  for (const result of results) {
    const card = document.createElement("button");

    card.type = "button";

    card.className = "global-search-result";

    const type = document.createElement("div");

    type.className = "global-search-result-type";

    type.textContent = globalSearchTypeLabel(result.type);

    const content = document.createElement("div");

    const title = document.createElement("div");

    title.className = "global-search-result-title";

    title.textContent = result.title || result.id || "Evidence";

    const meta = document.createElement("div");

    meta.className = "global-search-result-meta";

    meta.textContent = [
      result.subtitle,
      result.pid ? `PID ${result.pid}` : "",
      result.user,
      result.ip,
      result.match,
      result.timestamp ? formatTimestamp(result.timestamp) : "",
    ]
      .filter(Boolean)
      .join(" · ");

    content.append(title, meta);

    card.append(type, content);

    /*
     * 06A 先绑定统一 Pivot。
     */
    card.addEventListener("click", () => {
      openGlobalSearchResult(result);
    });

    container.appendChild(card);
  }
}

function globalSearchTypeLabel(type) {
  switch (type) {
    case "process":
      return "Process";

    case "historical_process":
      return "Historical Process";

    case "powershell":
      return "PowerShell";

    case "correlation_node":
      return "Correlation Node";

    case "correlation_edge":
      return "Correlation Edge";

    case "timeline":
      return "Timeline";

    case "login":
      return "Login";

    case "network":
      return "Network";

    case "windows_event":
      return "Windows Event";

    case "ioc":
      return "IOC Match";

    case "file":
      return "File";

    case "persistence":
      return "Persistence";

    default:
      return type || "Evidence";
  }
}

async function openGlobalSearchResult(result) {
  switch (result.type) {
    case "process":
      await openProcessByPID(result.pid);

      return;

    case "historical_process":
      await openHistoricalEvidence(result);

      return;

    case "powershell":
      await ensureCorrelationLoaded();

      if (correlationHasNode(result.id)) {
        await openCorrelationNodeByID(result.id);

        return;
      }

      await openEvidenceDetail(result);

      return;

    case "correlation_node":
      await openCorrelationNodeByID(result.id);

      return;

    case "correlation_edge":
      await openCorrelationEdgeByID(result.id);

      return;

    case "login":
      await openLoginByLogonID(
        result.object || result.id.replace(/^login:/i, ""),
      );

      return;

    case "network":
      if (result.id) {
        await openNetworkByID(result.id);

        return;
      }

      if (result.pid) {
        await openNetworkByPID(result.pid);

        return;
      }

      return;

    case "windows_event":
    case "ioc":
    case "file":
      await openFileByPath(result.object || result.metadata?.path || "");

      return;
    case "persistence":
      await openPersistenceByID(result.id);

      return;

    default:
      await openTimelineByQuery(result.id || result.title || "");
  }
}

function selectCorrelationEdgeInGraph(edgeID) {
  const cy = correlationState.cy;

  if (!cy) {
    return;
  }

  const edge = cy.getElementById(edgeID);

  if (!edge || edge.empty()) {
    return;
  }

  clearCorrelationFiltersState();

  edge.show();

  edge.connectedNodes().show();

  cy.animate({
    center: {
      eles: edge.connectedNodes(),
    },

    zoom: Math.max(cy.zoom(), 1.1),

    duration: 200,
  });

  const evidence = edge.data("evidence");

  highlightCorrelationEdge(edge);

  if (evidence) {
    renderCorrelationEdgeDetail(evidence);
  }
}

function findHistoricalChainForNode(nodeID) {
  const chains = correlationState.data?.chains || [];

  return (
    chains.find(
      (chain) =>
        Array.isArray(chain.node_ids) && chain.node_ids.includes(nodeID),
    ) || null
  );
}

function findHistoricalChainForEdge(edgeID) {
  const chains = correlationState.data?.chains || [];

  return (
    chains.find(
      (chain) =>
        Array.isArray(chain.edge_ids) && chain.edge_ids.includes(edgeID),
    ) || null
  );
}

function findRelationshipGroupForNode(nodeID) {
  return (
    correlationState.relationshipGroups.find(
      (group) =>
        Array.isArray(group.node_ids) && group.node_ids.includes(nodeID),
    ) || null
  );
}

function findRelationshipGroupForEdge(edgeID) {
  return (
    correlationState.relationshipGroups.find(
      (group) =>
        Array.isArray(group.edges) &&
        group.edges.some((edge) => edge.id === edgeID),
    ) || null
  );
}

async function openCorrelationNodeByID(nodeID) {
  if (!nodeID) {
    return;
  }

  await ensureCorrelationLoaded();

  const chain = findHistoricalChainForNode(nodeID);

  if (chain) {
    setCorrelationMode("chains");

    selectCorrelationChain(chain.id);

    setCorrelationView("graph");

    requestAnimationFrame(() => {
      selectCorrelationNodeInGraph(nodeID);
    });

    byId("correlation-section")?.scrollIntoView({
      behavior: "smooth",

      block: "start",
    });

    return;
  }

  const group = findRelationshipGroupForNode(nodeID);

  if (group) {
    setCorrelationMode("relationships");

    selectCorrelationRelationshipGroup(group.id);

    setCorrelationView("graph");

    requestAnimationFrame(() => {
      selectCorrelationNodeInGraph(nodeID);
    });

    byId("correlation-section")?.scrollIntoView({
      behavior: "smooth",

      block: "start",
    });

    pushInvestigationLocation({
      workspace: "correlation_node",

      title: `Correlation · ${nodeID}`,

      target: {
        id: nodeID,
      },
    });

    return;
  }

  /*
   * 没有可展示 Graph Context，
   * 退回 Timeline。
   */
  await openTimelineByQuery(nodeID);
}

async function openCorrelationEdgeByID(edgeID) {
  if (!edgeID) {
    return;
  }

  await ensureCorrelationLoaded();

  const chain = findHistoricalChainForEdge(edgeID);

  if (chain) {
    setCorrelationMode("chains");

    selectCorrelationChain(chain.id);

    setCorrelationView("graph");

    requestAnimationFrame(() => {
      selectCorrelationEdgeInGraph(edgeID);
    });

    byId("correlation-section")?.scrollIntoView({
      behavior: "smooth",

      block: "start",
    });

    pushInvestigationLocation({
      workspace: "correlation_edge",

      title: `Relationship · ${edgeID}`,

      target: {
        id: edgeID,
      },
    });

    return;
  }

  const group = findRelationshipGroupForEdge(edgeID);

  if (group) {
    setCorrelationMode("relationships");

    selectCorrelationRelationshipGroup(group.id);

    setCorrelationView("graph");

    requestAnimationFrame(() => {
      selectCorrelationEdgeInGraph(edgeID);
    });

    byId("correlation-section")?.scrollIntoView({
      behavior: "smooth",

      block: "start",
    });

    return;
  }

  /*
   * Edge 至少还有 Type / Basis 可以拿去 Timeline 搜。
   */
  const edge = correlationState.data?.edges?.find(
    (value) => value.id === edgeID,
  );

  await openTimelineByQuery(edge ? correlationEdgeTimelineQuery(edge) : edgeID);
}

function showCorrelationNavigationMessage(message) {
  const detail = byId("correlation-detail");

  if (!detail) {
    return;
  }

  detail.replaceChildren();

  const empty = document.createElement("div");

  empty.className = "event-detail-empty";

  empty.textContent = message;

  detail.appendChild(empty);
}

function correlationHasNode(nodeID) {
  return (
    correlationState.data?.nodes?.some((node) => node.id === nodeID) || false
  );
}

async function openHistoricalEvidence(result) {
  await openCorrelation();

  if (correlationHasNode(result.id)) {
    await openCorrelationNodeByID(result.id);

    return;
  }

  await openTimelineByQuery(result.id || result.object || "");
}

async function ensureCorrelationLoaded() {
  const section = byId("correlation-section");

  if (section) {
    section.classList.remove("hidden");
  }

  if (!correlationState.data) {
    initializeCorrelationGraph();

    setCorrelationView("graph");

    await loadCorrelation();
  }
}

function renderGlobalSearchTypeStats(byType) {
  const container = byId("global-search-type-stats");

  if (!container) {
    return;
  }

  container.replaceChildren();

  for (const [type, count] of Object.entries(byType || {})) {
    const item = document.createElement("span");

    item.textContent = `${globalSearchTypeLabel(type)} ${count}`;

    container.appendChild(item);
  }
}

async function openEvidenceDetail(result) {
  if (!result || !result.type || !result.id) {
    return;
  }

  const section = byId("evidence-detail-section");

  const container = byId("evidence-detail");

  if (!section || !container) {
    return;
  }

  section.classList.remove("hidden");

  container.replaceChildren();

  text("evidence-detail-subtitle", "Loading...");

  try {
    const data = await loadJSON(
      `/api/evidence/detail?type=${encodeURIComponent(result.type)}&id=${encodeURIComponent(result.id)}`,
    );

    renderEvidenceDetail(data);

    section.scrollIntoView({
      behavior: "smooth",

      block: "start",
    });
  } catch (error) {
    text("evidence-detail-subtitle", "Failed to load evidence");

    container.textContent = String(error);
  }
}

function renderEvidenceDetail(data) {
  const container = byId("evidence-detail");

  if (!container) {
    return;
  }

  container.replaceChildren();

  text(
    "evidence-detail-subtitle",
    [globalSearchTypeLabel(data.type), data.id].filter(Boolean).join(" · "),
  );

  const title = document.createElement("h3");

  title.textContent = data.title || data.id || "Evidence";

  container.appendChild(title);

  if (data.subtitle) {
    const subtitle = document.createElement("div");

    subtitle.className = "event-detail-meta";

    subtitle.textContent = data.subtitle;

    container.appendChild(subtitle);
  }

  const fields = {
    Timestamp: data.timestamp ? formatTimestamp(data.timestamp) : "",

    PID: data.pid || "",

    User: data.user || "",

    IP: data.ip || "",

    Object: data.object || "",

    Description: data.description || "",
  };

  for (const [key, value] of Object.entries(fields)) {
    if (!value) {
      continue;
    }

    appendEvidenceDetailField(container, key, String(value));
  }

  for (const [key, value] of Object.entries(data.fields || {})) {
    if (value === undefined || value === null || value === "") {
      continue;
    }

    appendEvidenceDetailField(container, key, String(value));
  }

  renderEvidenceDetailActions(container, data);
}

function renderEvidenceDetailActions(container, data) {
  const actions = document.createElement("div");

  actions.className = "evidence-detail-actions";

  /*
   * Direct Current Process Pivot
   */
  if (data.pid) {
    const processButton = document.createElement("button");

    processButton.type = "button";

    processButton.className = "secondary-button";

    processButton.textContent = "Open Process";

    processButton.addEventListener("click", async () => {
      await openProcessByPID(data.pid);

      byId("process-section")?.classList.remove("hidden");

      byId("process-section")?.scrollIntoView({
        behavior: "smooth",

        block: "start",
      });
    });

    actions.appendChild(processButton);
  }

  /*
   * Evidence-aware investigation pivot.
   */
  const investigateButton = document.createElement("button");

  investigateButton.type = "button";

  investigateButton.className = "secondary-button";

  investigateButton.textContent = "Investigate";

  investigateButton.addEventListener("click", async () => {
    await openEvidenceDetailPivot(data);
  });

  actions.appendChild(investigateButton);

  /*
   * Explicit Correlation Pivot.
   */
  if (data.type === "powershell" || data.type === "windows_event") {
    const correlationButton = document.createElement("button");

    correlationButton.type = "button";

    correlationButton.className = "secondary-button";

    correlationButton.textContent = "Open Correlation";

    correlationButton.addEventListener("click", async () => {
      await ensureCorrelationLoaded();

      if (correlationHasNode(data.id)) {
        await openCorrelationNodeByID(data.id);

        return;
      }

      await openTimelineByQuery(data.id || data.title || "");
    });

    actions.appendChild(correlationButton);
  }

  if (actions.childElementCount > 0) {
    container.appendChild(actions);
  }
}

function appendEvidenceDetailField(container, label, value) {
  const row = document.createElement("div");

  row.className = "event-detail-row";

  const key = document.createElement("div");

  key.className = "event-detail-key";

  key.textContent = label;

  const content = document.createElement("div");

  content.className = "event-detail-value";

  content.textContent = value;

  row.append(key, content);

  container.appendChild(row);
}

function evidenceDetailTimelineQuery(data) {
  if (!data) {
    return "";
  }

  if (data.type === "powershell") {
    return data.fields?.script_block_id || data.id || "";
  }

  if (data.type === "windows_event") {
    return data.id || data.title || data.object || "";
  }

  if (data.type === "ioc") {
    return data.fields?.ioc_value || data.ip || data.object || "";
  }

  if (data.type === "file") {
    return data.fields?.sha256 || data.object || data.id || "";
  }

  if (data.type === "persistence") {
    return data.object || data.fields?.name || data.id || "";
  }

  return data.id || data.object || "";
}

async function openEvidenceDetailPivot(data) {
  if (!data) {
    return;
  }

  switch (data.type) {
    case "powershell":
      await openPowerShellEvidencePivot(data);

      return;

    case "windows_event":
      await openWindowsEventEvidencePivot(data);

      return;

    case "ioc":
      await openIOCEvidencePivot(data);

      return;

    case "file":
      await openFileEvidencePivot(data);

      return;

    case "persistence":
      await openPersistenceEvidencePivot(data);

      return;

    default:
      await openTimelineByQuery(data.id || data.object || "");
  }
}

async function openPowerShellEvidencePivot(data) {
  await ensureCorrelationLoaded();

  if (correlationHasNode(data.id)) {
    await openCorrelationNodeByID(data.id);

    return;
  }

  const historicalID = data.fields?.related_historical_process_id || "";

  if (historicalID) {
    await openTimelineByQuery(historicalID);

    return;
  }

  const scriptBlockID = data.fields?.script_block_id || data.id || "";

  await openTimelineByQuery(scriptBlockID);
}

async function openWindowsEventEvidencePivot(data) {
  await ensureCorrelationLoaded();

  if (correlationHasNode(data.id)) {
    await openCorrelationNodeByID(data.id);

    return;
  }

  if (data.id) {
    await openTimelineByQuery(data.id);

    return;
  }

  const sessionID = data.fields?.session_id || "";

  if (sessionID) {
    await openTimelineByQuery(sessionID);

    return;
  }

  await openTimelineByQuery(data.title || data.object || "");
}

async function openIOCEvidencePivot(data) {
  const fields = data.fields || {};

  const iocType = String(fields.ioc_type || "").toLowerCase();

  /*
   * Process related IOC
   */
  if (data.pid && (iocType.includes("process") || fields.process)) {
    await openProcessByPID(data.pid);

    return;
  }

  /*
   * Network IOC
   */
  if (fields.remote_address || data.ip) {
    await openTimelineByQuery(fields.remote_address || data.ip);

    return;
  }

  /*
   * File/hash/path IOC
   */
  if (fields.sha256) {
    await openTimelineByQuery(fields.sha256);

    return;
  }

  if (fields.path) {
    await openTimelineByQuery(fields.path);

    return;
  }

  /*
   * Persistence IOC
   */
  if (fields.persistence_name) {
    await openTimelineByQuery(fields.persistence_name);

    return;
  }

  await openTimelineByQuery(fields.ioc_value || data.object || data.id || "");
}

async function openFileEvidencePivot(data) {
  if (data.pid) {
    await openProcessByPID(data.pid);

    return;
  }

  const sha256 = data.fields?.sha256 || "";

  if (sha256) {
    await openTimelineByQuery(sha256);

    return;
  }

  if (data.object) {
    await openTimelineByQuery(data.object);

    return;
  }

  await openTimelineByQuery(data.id);
}

async function openPersistenceEvidencePivot(data) {
  if (data.pid) {
    await openProcessByPID(data.pid);

    return;
  }

  const fields = data.fields || {};

  if (fields.executable_path) {
    await openTimelineByQuery(fields.executable_path);

    return;
  }

  if (fields.name) {
    await openTimelineByQuery(fields.name);

    return;
  }

  if (fields.command) {
    await openTimelineByQuery(fields.command);

    return;
  }

  await openTimelineByQuery(data.id);
}

async function loadLogins() {
  const params = new URLSearchParams();

  const query = byId("login-search")?.value.trim() || "";

  const user = byId("login-user")?.value.trim() || "";

  const ip = byId("login-ip")?.value.trim() || "";

  const type = byId("login-type")?.value.trim() || "";

  if (query) {
    params.set("q", query);
  }

  if (user) {
    params.set("user", user);
  }

  if (ip) {
    params.set("ip", ip);
  }

  if (type) {
    params.set("type", type);
  }

  params.set("offset", String(loginState.offset));

  params.set("limit", String(loginState.limit));

  const data = await loadJSON(`/api/logins?${params.toString()}`);

  loginState.total = data.total || 0;

  loginState.hasMore = Boolean(data.has_more);

  renderLoginList(data.sessions || []);

  updateLoginPagination();

  text("login-result-count", `${loginState.total} login sessions`);
}

// Login List 渲染
function renderLoginList(sessions) {
  const container = byId("login-list");

  if (!container) {
    return;
  }

  container.replaceChildren();

  if (sessions.length === 0) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent = "No matching login sessions.";

    container.appendChild(empty);

    return;
  }

  for (const session of sessions) {
    const button = document.createElement("button");

    button.type = "button";

    button.className = "login-list-item";

    if (
      loginState.selectedLogonID &&
      String(session.logon_id).toLowerCase() ===
        loginState.selectedLogonID.toLowerCase()
    ) {
      button.classList.add("selected");
    }

    const user = [session.domain, session.user].filter(Boolean).join("\\");

    const title = document.createElement("div");

    title.className = "global-search-result-title";

    title.textContent = user || session.logon_id || "Login Session";

    const meta = document.createElement("div");

    meta.className = "global-search-result-meta";

    meta.textContent = [
      session.logon_id,
      session.logon_type_name,
      session.source_ip,
      session.timestamp ? formatTimestamp(session.timestamp) : "",
    ]
      .filter(Boolean)
      .join(" · ");

    button.append(title, meta);

    button.dataset.logonId = session.logon_id || "";

    button.addEventListener("click", () => {
      selectLoginSession(session.logon_id);
    });

    container.appendChild(button);
  }
}

function updateSelectedLoginListItem() {
  const container = byId("login-list");

  if (!container) {
    return;
  }

  for (const button of container.querySelectorAll(".login-list-item")) {
    button.classList.toggle(
      "selected",
      button.dataset.logonId === loginState.selectedID,
    );
  }
}

// Detail 加载
async function selectLoginSession(logonID) {
  if (!logonID) {
    return;
  }

  loginState.selectedID = logonID;

  updateSelectedLoginListItem();

  if (loginState.detailController) {
    loginState.detailController.abort();
  }

  const controller = new AbortController();

  loginState.detailController = controller;

  const sequence = ++loginState.detailSequence;

  try {
    const data = await loadJSONWithSignal(
      `/api/login?id=${encodeURIComponent(logonID)}`,
      controller.signal,
    );

    if (sequence !== loginState.detailSequence) {
      return;
    }

    if (loginState.selectedID !== logonID) {
      return;
    }

    renderLoginDetail(data);
  } catch (error) {
    if (error.name === "AbortError") {
      return;
    }

    console.error("Load login detail failed:", error);
  } finally {
    if (loginState.detailController === controller) {
      loginState.detailController = null;
    }
  }
}

// Detail 渲染
function renderLoginDetail(session) {
  const container = byId("login-detail");

  if (!container) {
    return;
  }

  container.replaceChildren();

  const title = document.createElement("h3");

  title.textContent =
    [session.domain, session.user].filter(Boolean).join("\\") ||
    session.logon_id ||
    "Login Session";

  container.appendChild(title);

  const fields = {
    "Logon ID": session.logon_id,

    Timestamp: session.timestamp ? formatTimestamp(session.timestamp) : "",

    "Logon Type": [session.logon_type, session.logon_type_name]
      .filter((value) => value !== undefined && value !== null && value !== "")
      .join(" · "),

    "Source IP": session.source_ip,

    "Source Port": session.source_port,

    Workstation: session.workstation,

    "Authentication Package": session.authentication_package,

    Privileged: String(Boolean(session.privileged)),

    Privileges: session.privileges,

    "Process Count": String(session.process_count || 0),

    "Processes With Network": String(session.processes_with_network || 0),

    "Processes With External Network": String(
      session.processes_with_external_network || 0,
    ),
  };

  for (const [label, value] of Object.entries(fields)) {
    if (!value) {
      continue;
    }

    appendEvidenceDetailField(container, label, String(value));
  }

  renderLoginRelatedProcesses(container, session.processes || []);

  renderLoginActions(container, session);
}

function renderLoginRelatedProcesses(container, processes) {
  const heading = document.createElement("h4");

  heading.textContent = "Related Processes";

  container.appendChild(heading);

  if (processes.length === 0) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent = "No process was correlated to this LogonID.";

    container.appendChild(empty);

    return;
  }

  for (const process of processes) {
    const button = document.createElement("button");

    button.type = "button";

    button.className = "secondary-button";

    button.textContent = `${process.name || "Process"} · PID ${process.pid}`;

    button.addEventListener("click", async () => {
      byId("process-section")?.classList.remove("hidden");

      await openProcessByPID(process.pid);

      byId("process-section")?.scrollIntoView({
        behavior: "smooth",

        block: "start",
      });
    });

    container.appendChild(button);

    const networkButton = document.createElement("button");

    networkButton.type = "button";

    networkButton.className = "secondary-button";

    networkButton.textContent = `Network · PID ${process.pid}`;

    networkButton.addEventListener("click", async () => {
      await openNetworkByPID(process.pid, investigationSourceFromCurrent());
    });

    container.appendChild(networkButton);
  }
}

// Login Actions
function renderLoginActions(container, session) {
  const actions = document.createElement("div");

  actions.className = "evidence-detail-actions";

  const timeline = document.createElement("button");

  timeline.type = "button";

  timeline.className = "secondary-button";

  timeline.textContent = "Show in Timeline";

  timeline.addEventListener("click", async () => {
    await openTimelineByQuery(session.logon_id);
  });

  actions.appendChild(timeline);

  /*
   * 如果 Correlation 里存在对应 login node，
   * Smart Pivot 会进入正确 Chain / Group。
   */
  const correlation = document.createElement("button");

  correlation.type = "button";

  correlation.className = "secondary-button";

  correlation.textContent = "Open Correlation";

  correlation.addEventListener("click", async () => {
    await ensureCorrelationLoaded();

    const candidates = [`login:${session.logon_id}`, session.logon_id];

    for (const id of candidates) {
      if (correlationHasNode(id)) {
        await openCorrelationNodeByID(id);

        return;
      }
    }

    await openTimelineByQuery(session.logon_id);
  });

  actions.appendChild(correlation);

  container.appendChild(actions);
}

function updateLoginPagination() {
  const start = loginState.total === 0 ? 0 : loginState.offset + 1;

  const end = Math.min(loginState.offset + loginState.limit, loginState.total);

  text("login-page-info", `${start}-${end} of ${loginState.total}`);

  const prev = byId("login-prev");

  const next = byId("login-next");

  if (prev) {
    prev.disabled = loginState.offset <= 0;
  }

  if (next) {
    next.disabled = !loginState.hasMore;
  }
}

async function openTimelineByQuery(query, pid = 0, source = null) {
  const timelineSection = byId("timeline-section");

  if (!timelineSection) {
    return;
  }

  timelineSection.classList.remove("hidden");

  const q = byId("timeline-search");

  if (q) {
    q.value = query || "";
  }

  const pidInput = byId("timeline-pid");

  if (pidInput) {
    pidInput.value = pid ? String(pid) : "";
  }

  timelineState.offset = 0;

  timelineState.category = "";

  await loadTimeline();

  timelineSection.scrollIntoView({
    behavior: "smooth",

    block: "start",
  });

  pushInvestigationLocation({
    workspace: "timeline",

    title: pid
      ? `Timeline · PID ${pid}`
      : query
        ? `Timeline · ${query}`
        : "Timeline",

    target: {
      query: query || "",

      pid: Number(pid || 0),
    },
    source: source,
  });
}

function renderFileRelatedPersistence(container, references) {
  const section = document.createElement("div");

  section.className = "detail-section";

  const heading = document.createElement("div");

  heading.className = "detail-section-title";

  heading.textContent = "Related Persistence";

  section.appendChild(heading);

  if (!Array.isArray(references) || references.length === 0) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent =
      "No persistence evidence was explicitly related to this file.";

    section.appendChild(empty);

    container.appendChild(section);

    return;
  }

  for (const reference of references) {
    const row = document.createElement("div");

    row.className = "related-evidence-row";

    const info = document.createElement("div");

    const title = document.createElement("div");

    title.className = "global-search-result-title";

    title.textContent = reference.title || reference.name || reference.id;

    const meta = document.createElement("div");

    meta.className = "global-search-result-meta";

    meta.textContent = [reference.type, reference.name, reference.finding_id]
      .filter(Boolean)
      .join(" · ");

    info.append(title, meta);

    const button = document.createElement("button");

    button.type = "button";

    button.className = "secondary-button";

    button.textContent = "Open Persistence";

    button.addEventListener("click", async () => {
      await openPersistenceByID(reference.id, investigationSourceFromCurrent());
    });

    row.append(info, button);

    section.appendChild(row);
  }

  container.appendChild(section);
}

function renderPersistenceRelatedFiles(container, files) {
  const section = document.createElement("div");

  section.className = "detail-section";

  const heading = document.createElement("div");

  heading.className = "detail-section-title";

  heading.textContent = "Related Files";

  section.appendChild(heading);

  if (!Array.isArray(files) || files.length === 0) {
    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent =
      "No collected file exactly matches this persistence executable path.";

    section.appendChild(empty);

    container.appendChild(section);

    return;
  }

  for (const file of files) {
    const row = document.createElement("div");

    row.className = "related-evidence-row";

    const info = document.createElement("div");

    const title = document.createElement("div");

    title.className = "global-search-result-title";

    title.textContent = file.name || file.path;

    const meta = document.createElement("div");

    meta.className = "global-search-result-meta";

    meta.textContent = [file.path, file.sha256].filter(Boolean).join(" · ");

    info.append(title, meta);

    const button = document.createElement("button");

    button.type = "button";

    button.className = "secondary-button";

    button.textContent = "Open File";

    button.addEventListener("click", async () => {
      await openFileByPath(file.path, investigationSourceFromCurrent());
    });

    row.append(info, button);

    section.appendChild(row);
  }

  container.appendChild(section);
}

function pushInvestigationLocation(location) {
  if (!location || investigationNavigationState.restoring) {
    return;
  }

  const normalized = {
    workspace: location.workspace || "case",

    title: location.title || "Case Overview",

    target: location.target || {},

    source: location.source || null,
  };

  /*
   * 如果当前位置和新位置完全相同，
   * 不重复入栈。
   */
  const current =
    investigationNavigationState.history[investigationNavigationState.index];

  if (current && JSON.stringify(current) === JSON.stringify(normalized)) {
    return;
  }

  /*
   * Back 后再进入新证据，
   * 丢弃旧 Forward 分支。
   */
  if (
    investigationNavigationState.index <
    investigationNavigationState.history.length - 1
  ) {
    investigationNavigationState.history =
      investigationNavigationState.history.slice(
        0,
        investigationNavigationState.index + 1,
      );
  }

  investigationNavigationState.history.push(normalized);

  investigationNavigationState.index =
    investigationNavigationState.history.length - 1;

  updateInvestigationBreadcrumb(normalized);

  const hash = investigationLocationToHash(normalized);

  if (window.location.hash !== hash) {
    window.history.pushState(null, "", hash);
  }

  updateInvestigationNavigation();
}

function updateInvestigationNavigation() {
  const back = byId("investigation-back");

  const forward = byId("investigation-forward");

  const location = byId("investigation-current-location");

  if (back) {
    back.disabled = investigationNavigationState.index <= 0;
  }

  if (forward) {
    forward.disabled =
      investigationNavigationState.index < 0 ||
      investigationNavigationState.index >=
        investigationNavigationState.history.length - 1;
  }

  if (location) {
    const current =
      investigationNavigationState.history[investigationNavigationState.index];

    location.textContent = current?.title || "Case Overview";
  }
}

async function restoreInvestigationLocation(location) {
  if (!location) {
    return;
  }

  investigationNavigationState.restoring = true;

  try {
    switch (location.workspace) {
      case "case":
        window.scrollTo({
          top: 0,

          behavior: "smooth",
        });

        break;

      case "timeline":
        await openTimelineByQuery(
          location.target?.query || "",
          location.target?.pid || 0,
        );

        break;

      case "process":
        await openProcessByPID(location.target?.pid);

        break;

      case "login":
        await openLoginByLogonID(location.target?.logon_id);

        break;

      case "network":
        if (location.target?.id) {
          await openNetworkByID(location.target.id);
        } else {
          await openNetworkByPID(location.target?.pid);
        }

        break;

      case "file":
        await openFileByPath(location.target?.path);

        break;

      case "persistence":
        await openPersistenceByID(location.target?.id);

        break;

      case "correlation_node":
        await openCorrelationNodeByID(location.target?.id);

        break;

      case "correlation_edge":
        await openCorrelationEdgeByID(location.target?.id);

        break;
    }
  } finally {
    investigationNavigationState.restoring = false;

    updateInvestigationNavigation();
  }
}

async function navigateInvestigationBack() {
  if (investigationNavigationState.index <= 0) {
    return;
  }

  investigationNavigationState.index--;

  const location =
    investigationNavigationState.history[investigationNavigationState.index];

  const hash = investigationLocationToHash(location);

  if (window.location.hash !== hash) {
    window.history.replaceState(null, "", hash);
  }

  await restoreInvestigationLocation(location);
  renderInvestigationBreadcrumb();
}

async function navigateInvestigationForward() {
  if (
    investigationNavigationState.index >=
    investigationNavigationState.history.length - 1
  ) {
    return;
  }

  investigationNavigationState.index++;

  const location =
    investigationNavigationState.history[investigationNavigationState.index];

  const hash = investigationLocationToHash(location);

  if (window.location.hash !== hash) {
    window.history.replaceState(null, "", hash);
  }

  await restoreInvestigationLocation(location);
  renderInvestigationBreadcrumb();
}

function investigationLocationToHash(location) {
  if (!location) {
    return "#/";
  }

  const target = location.target || {};

  switch (location.workspace) {
    case "process":
      return `#/process/${encodeURIComponent(target.pid || "")}`;

    case "login":
      return `#/login/${encodeURIComponent(target.logon_id || "")}`;

    case "network": {
      const params = new URLSearchParams();

      if (target.id) {
        params.set("id", target.id);
      }

      if (target.pid) {
        params.set("pid", String(target.pid));
      }

      return `#/network${params.toString() ? `?${params.toString()}` : ""}`;
    }

    case "file": {
      const params = new URLSearchParams();

      if (target.path) {
        params.set("path", target.path);
      }

      return `#/file?${params.toString()}`;
    }

    case "persistence": {
      const params = new URLSearchParams();

      if (target.id) {
        params.set("id", target.id);
      }

      return `#/persistence?${params.toString()}`;
    }

    case "timeline": {
      const params = new URLSearchParams();

      if (target.query) {
        params.set("q", target.query);
      }

      if (target.pid) {
        params.set("pid", String(target.pid));
      }

      return `#/timeline${params.toString() ? `?${params.toString()}` : ""}`;
    }

    case "correlation_node":
      return `#/correlation/node/${encodeURIComponent(target.id || "")}`;

    case "correlation_edge":
      return `#/correlation/edge/${encodeURIComponent(target.id || "")}`;

    case "case":
    default:
      return "#/";
  }
}

function parseInvestigationHash() {
  const raw = window.location.hash || "#/";

  const withoutHash = raw.startsWith("#") ? raw.slice(1) : raw;

  const [pathPart, queryPart = ""] = withoutHash.split("?", 2);

  const segments = pathPart
    .split("/")
    .filter(Boolean)
    .map((segment) => decodeURIComponent(segment));

  const params = new URLSearchParams(queryPart);

  if (segments.length === 0) {
    return {
      workspace: "case",

      title: "Case Overview",

      target: {},
    };
  }

  switch (segments[0]) {
    case "process": {
      const pid = Number(segments[1] || 0);

      if (!pid) {
        return null;
      }

      return {
        workspace: "process",

        title: `Process · PID ${pid}`,

        target: {
          pid: pid,
        },
      };
    }

    case "login": {
      const logonID = segments[1] || "";

      if (!logonID) {
        return null;
      }

      return {
        workspace: "login",

        title: `Login · ${logonID}`,

        target: {
          logon_id: logonID,
        },
      };
    }

    case "network": {
      const id = params.get("id") || "";

      const pid = Number(params.get("pid") || 0);

      if (!id && !pid) {
        return null;
      }

      return {
        workspace: "network",

        title: id ? "Network Evidence" : `Network · PID ${pid}`,

        target: {
          id: id,

          pid: pid,
        },
      };
    }

    case "file": {
      const path = params.get("path") || "";

      if (!path) {
        return null;
      }

      return {
        workspace: "file",

        title: `File · ${windowsPathBaseName(path)}`,

        target: {
          path: path,
        },
      };
    }

    case "persistence": {
      const id = params.get("id") || "";

      if (!id) {
        return null;
      }

      return {
        workspace: "persistence",

        title: `Persistence · ${id}`,

        target: {
          id: id,
        },
      };
    }

    case "timeline": {
      const query = params.get("q") || "";

      const pid = Number(params.get("pid") || 0);

      return {
        workspace: "timeline",

        title: pid
          ? `Timeline · PID ${pid}`
          : query
            ? `Timeline · ${query}`
            : "Timeline",

        target: {
          query: query,

          pid: pid,
        },
      };
    }

    case "correlation": {
      const type = segments[1] || "";

      const id = segments[2] || "";

      if (!id) {
        return null;
      }

      if (type === "node") {
        return {
          workspace: "correlation_node",

          title: `Correlation · ${id}`,

          target: {
            id: id,
          },
        };
      }

      if (type === "edge") {
        return {
          workspace: "correlation_edge",

          title: `Relationship · ${id}`,

          target: {
            id: id,
          },
        };
      }

      return null;
    }

    default:
      return null;
  }
}

async function restoreInvestigationFromURL() {
  const location = parseInvestigationHash();

  if (!location) {
    return false;
  }

  investigationNavigationState.history = [location];

  investigationNavigationState.breadcrumb = [location];

  investigationNavigationState.index = 0;

  updateInvestigationNavigation();

  renderInvestigationBreadcrumb();

  try {
    await restoreInvestigationLocation(location);

    return true;
  } catch (error) {
    console.error("Failed to restore investigation URL:", error);

    return false;
  }
}

async function handleInvestigationHashChange() {
  if (investigationNavigationState.restoring) {
    return;
  }

  const location = parseInvestigationHash();

  if (!location) {
    return;
  }

  const current =
    investigationNavigationState.history[investigationNavigationState.index];

  if (
    current &&
    investigationLocationToHash(current) ===
      investigationLocationToHash(location)
  ) {
    return;
  }

  /*
   * 地址栏发生外部导航：
   * 作为新的 Investigation Location。
   */
  investigationNavigationState.history =
    investigationNavigationState.history.slice(
      0,
      investigationNavigationState.index + 1,
    );

  investigationNavigationState.history.push(location);

  investigationNavigationState.index =
    investigationNavigationState.history.length - 1;

  updateInvestigationNavigation();

  await restoreInvestigationLocation(location);
}

async function handleBrowserNavigation() {
  const location = parseInvestigationHash();

  if (!location) {
    return;
  }

  const hash = investigationLocationToHash(location);

  const foundIndex = investigationNavigationState.history.findIndex(
    (item) => investigationLocationToHash(item) === hash,
  );

  if (foundIndex >= 0) {
    investigationNavigationState.index = foundIndex;
  } else {
    investigationNavigationState.history.push(location);

    investigationNavigationState.index =
      investigationNavigationState.history.length - 1;
  }

  updateInvestigationNavigation();

  await restoreInvestigationLocation(location);
  renderInvestigationBreadcrumb();
}

function windowsPathBaseName(path) {
  const value = String(path || "");

  const parts = value.split(/[\\/]/);

  return parts[parts.length - 1] || value;
}

function updateInvestigationBreadcrumb(location) {
  if (!location || investigationNavigationState.restoring) {
    return;
  }

  const breadcrumb = investigationNavigationState.breadcrumb;

  /*
   * Case Overview 重置路径。
   */
  if (location.workspace === "case") {
    investigationNavigationState.breadcrumb = [location];

    renderInvestigationBreadcrumb();

    return;
  }

  const current = breadcrumb[breadcrumb.length - 1];

  if (
    current &&
    investigationLocationToHash(current) ===
      investigationLocationToHash(location)
  ) {
    return;
  }

  breadcrumb.push(location);

  /*
   * 避免无限增长。
   */
  if (breadcrumb.length > 12) {
    breadcrumb.splice(0, breadcrumb.length - 12);
  }

  renderInvestigationBreadcrumb();
}

function renderInvestigationBreadcrumb() {
  const container = byId("investigation-breadcrumb");

  if (!container) {
    return;
  }

  container.replaceChildren();

  const breadcrumb = investigationNavigationState.breadcrumb;

  if (!Array.isArray(breadcrumb) || breadcrumb.length === 0) {
    return;
  }

  const currentLocation = currentInvestigationLocation();

  breadcrumb.forEach((location, index) => {
    // separator...

    const button = document.createElement("button");

    button.type = "button";

    button.className = "investigation-breadcrumb-item";

    button.textContent = investigationBreadcrumbLabel(location);

    const isCurrent =
      currentLocation &&
      investigationLocationToHash(currentLocation) ===
        investigationLocationToHash(location);

    if (isCurrent) {
      button.classList.add("current");
    }

    button.addEventListener("click", async () => {
      if (isCurrent) {
        return;
      }

      await navigateToBreadcrumbIndex(index);
    });

    container.appendChild(button);
  });
}

function investigationBreadcrumbLabel(location) {
  if (!location) {
    return "Unknown";
  }

  const target = location.target || {};

  switch (location.workspace) {
    case "case":
      return "Case";

    case "process":
      return target.pid ? `PID ${target.pid}` : "Process";

    case "login":
      return target.logon_id ? `Login ${target.logon_id}` : "Login";

    case "network":
      if (target.pid) {
        return `Network PID ${target.pid}`;
      }

      return "Network";

    case "file":
      return windowsPathBaseName(target.path || "") || "File";

    case "persistence":
      return "Persistence";

    case "timeline":
      if (target.pid) {
        return `Timeline PID ${target.pid}`;
      }

      if (target.query) {
        return `Timeline ${target.query}`;
      }

      return "Timeline";

    case "correlation_node":
      return "Correlation Node";

    case "correlation_edge":
      return "Relationship";

    default:
      return location.title || "Evidence";
  }
}

async function navigateToBreadcrumbIndex(index) {
  const breadcrumb = investigationNavigationState.breadcrumb;

  if (index < 0 || index >= breadcrumb.length) {
    return;
  }

  const location = breadcrumb[index];

  /*
   * 点击旧节点后，
   * 截断后续调查路径。
   */
  investigationNavigationState.breadcrumb = breadcrumb.slice(0, index + 1);

  renderInvestigationBreadcrumb();

  /*
   * 这里视为新的 Investigation Navigation。
   */
  pushInvestigationLocation(location);

  await restoreInvestigationLocation(location);
}

function currentInvestigationLocation() {
  return (
    investigationNavigationState.history[investigationNavigationState.index] ||
    null
  );
}

function investigationSourceFromCurrent() {
  const current = currentInvestigationLocation();

  if (!current) {
    return null;
  }

  return {
    workspace: current.workspace,

    label: current.title,
  };
}

async function loadJSONWithSignal(url, signal) {
  const response = await fetch(url, {
    signal,
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }

  return response.json();
}

function debounce(fn, delay = 300) {
  let timer = null;

  return (...args) => {
    if (timer) {
      clearTimeout(timer);
    }

    timer = window.setTimeout(() => {
      timer = null;

      fn(...args);
    }, delay);
  };
}

function wireUI() {
  window.addEventListener("hashchange", handleInvestigationHashChange);
  // Timeline 按钮
  document
    .querySelector('[data-view="timeline"]')
    .addEventListener("click", openTimeline);

  byId("close-timeline").addEventListener("click", () => {
    byId("timeline-section").classList.add("hidden");
  });

  byId("timeline-apply").addEventListener("click", () => {
    timelineState.offset = 0;

    timelineState.selectedID = "";

    loadTimeline();
  });

  byId("timeline-reset").addEventListener("click", resetTimelineFilters);

  byId("timeline-prev").addEventListener("click", () => {
    timelineState.offset = Math.max(
      0,
      timelineState.offset - timelineState.limit,
    );

    timelineState.selectedID = "";

    loadTimeline();
  });

  byId("timeline-next").addEventListener("click", () => {
    if (!timelineState.hasMore) {
      return;
    }

    timelineState.offset += timelineState.limit;

    timelineState.selectedID = "";

    loadTimeline();
  });

  byId("timeline-search").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      timelineState.offset = 0;

      loadTimeline();
    }
  });

  //   Processes 按钮
  document
    .querySelector('[data-view="processes"]')
    .addEventListener("click", openProcesses);

  byId("close-processes").addEventListener("click", () => {
    byId("process-section").classList.add("hidden");
  });

  byId("process-apply").addEventListener("click", () => {
    processState.offset = 0;

    processState.selectedPID = 0;

    loadProcesses();
  });

  byId("process-reset").addEventListener("click", resetProcessFilters);

  byId("process-prev").addEventListener("click", () => {
    processState.offset = Math.max(0, processState.offset - processState.limit);

    loadProcesses();
  });

  byId("process-next").addEventListener("click", () => {
    if (!processState.hasMore) {
      return;
    }

    processState.offset += processState.limit;

    loadProcesses();
  });

  byId("process-search").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      processState.offset = 0;

      loadProcesses();
    }
  });

  //   Correlation 按钮
  document
    .querySelector('[data-view="correlation"]')
    .addEventListener("click", openCorrelation);

  byId("close-correlation").addEventListener("click", () => {
    byId("correlation-section").classList.add("hidden");
  });

  byId("correlation-tab-chains").addEventListener("click", () => {
    setCorrelationMode("chains");

    const chains = correlationState.data?.chains || [];

    if (chains.length > 0) {
      selectCorrelationChain(chains[0].id);

      return;
    }

    const graph = byId("correlation-graph");

    graph.replaceChildren();

    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent =
      "No analyzer-generated historical chains are available.";

    graph.appendChild(empty);
  });

  byId("correlation-tab-relationships").addEventListener("click", () => {
    setCorrelationMode("relationships");

    const groups = correlationState.relationshipGroups;

    if (groups.length > 0) {
      selectCorrelationRelationshipGroup(groups[0].id);

      return;
    }

    const graph = byId("correlation-graph");

    graph.replaceChildren();

    const empty = document.createElement("div");

    empty.className = "event-detail-empty";

    empty.textContent = "No correlated relationships are available.";

    graph.appendChild(empty);
  });

  byId("correlation-view-graph").addEventListener("click", () => {
    setCorrelationView("graph");
  });

  byId("correlation-view-list").addEventListener("click", () => {
    setCorrelationView("list");
  });

  byId("correlation-graph-fit").addEventListener("click", fitCorrelationGraph);

  byId("correlation-graph-zoom-in").addEventListener("click", () => {
    zoomCorrelationGraph(1.2);
  });

  byId("correlation-graph-zoom-out").addEventListener("click", () => {
    zoomCorrelationGraph(1 / 1.2);
  });

  byId("correlation-graph-reset").addEventListener(
    "click",
    resetCorrelationGraph,
  );

  // Login Investigation Card
  document
    .querySelector('.investigation-card[data-view="logins"]')
    .addEventListener("click", openLogins);

  //   network按钮
  document
    .querySelector('.investigation-card[data-view="network"]')
    .addEventListener("click", openNetwork);

  byId("network-apply")?.addEventListener("click", () => {
    networkState.offset = 0;

    loadNetwork();
  });

  byId("network-reset")?.addEventListener("click", () => {
    for (const id of [
      "network-search",
      "network-pid",
      "network-ip",
      "network-state",
    ]) {
      const input = byId(id);

      if (input) {
        input.value = "";
      }
    }

    const external = byId("network-external");

    if (external) {
      external.value = "";
    }

    networkState.offset = 0;

    loadNetwork();
  });

  byId("network-prev")?.addEventListener("click", () => {
    networkState.offset = Math.max(0, networkState.offset - networkState.limit);

    loadNetwork();
  });

  byId("network-next")?.addEventListener("click", () => {
    if (!networkState.hasMore) {
      return;
    }

    networkState.offset += networkState.limit;

    loadNetwork();
  });

  byId("close-network")?.addEventListener("click", () => {
    byId("network-section")?.classList.add("hidden");
  });

  // 文件按钮
  document
    .querySelector('.investigation-card[data-view="files"]')
    .addEventListener("click", openFiles);
  byId("file-apply")?.addEventListener("click", () => {
    fileState.offset = 0;
    loadFiles();
  });

  byId("file-reset")?.addEventListener("click", () => {
    for (const id of ["file-search", "file-owner", "file-extension"]) {
      const input = byId(id);

      if (input) {
        input.value = "";
      }
    }

    const executable = byId("file-executable");

    if (executable) {
      executable.value = "";
    }

    const finding = byId("file-finding");

    if (finding) {
      finding.value = "";
    }

    fileState.offset = 0;

    loadFiles();
  });

  byId("file-prev")?.addEventListener("click", () => {
    fileState.offset = Math.max(0, fileState.offset - fileState.limit);

    loadFiles();
  });

  byId("file-next")?.addEventListener("click", () => {
    if (!fileState.hasMore) {
      return;
    }

    fileState.offset += fileState.limit;

    loadFiles();
  });

  byId("close-files")?.addEventListener("click", () => {
    byId("file-section")?.classList.add("hidden");
  });

  // 横向按钮
  document
    .querySelector('.investigation-card[data-view="persistence"]')
    .addEventListener("click", openPersistence);

  byId("persistence-apply")?.addEventListener("click", () => {
    persistenceState.offset = 0;
    loadPersistence();
  });

  byId("persistence-reset")?.addEventListener("click", () => {
    const search = byId("persistence-search");

    if (search) {
      search.value = "";
    }

    const user = byId("persistence-user");

    if (user) {
      user.value = "";
    }

    const type = byId("persistence-type");

    if (type) {
      type.value = "";
    }

    const finding = byId("persistence-finding");

    if (finding) {
      finding.value = "";
    }

    persistenceState.offset = 0;

    loadPersistence();
  });

  byId("persistence-prev")?.addEventListener("click", () => {
    persistenceState.offset = Math.max(
      0,
      persistenceState.offset - persistenceState.limit,
    );

    loadPersistence();
  });

  byId("persistence-next")?.addEventListener("click", () => {
    if (!persistenceState.hasMore) {
      return;
    }

    persistenceState.offset += persistenceState.limit;

    loadPersistence();
  });

  byId("close-persistence")?.addEventListener("click", () => {
    byId("persistence-section")?.classList.add("hidden");
  });

  //   Search 输入绑定
  const correlationSearch = byId("correlation-search");

  if (correlationSearch) {
    correlationSearch.addEventListener("input", (event) => {
      correlationState.filters.query = event.target.value || "";

      applyCorrelationGraphFilters();
    });
  }

  //  Confidence Filter
  const correlationConfidence = byId("correlation-confidence");

  if (correlationConfidence) {
    correlationConfidence.addEventListener("change", (event) => {
      correlationState.filters.confidence = event.target.value || "all";

      applyCorrelationGraphFilters();
    });
  }

  //   Clear Filters
  const clearCorrelationFilters = byId("correlation-clear-filters");

  if (clearCorrelationFilters) {
    clearCorrelationFilters.addEventListener("click", () => {
      clearCorrelationFiltersState();
    });
  }
  // Enter 自动选中 绑定
  correlationSearch.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") {
      return;
    }

    focusUniqueCorrelationSearchResult();
  });

  /*
   * Global Investigation Search
   */

  const globalSearchButton = byId("global-search-button");

  if (globalSearchButton) {
    globalSearchButton.addEventListener("click", runGlobalSearch);
  }

  const globalSearchInput = byId("global-search-input");

  if (globalSearchInput) {
    globalSearchInput.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") {
        return;
      }

      runGlobalSearch();
    });
  }

  const globalSearchType = byId("global-search-type");

  if (globalSearchType) {
    globalSearchType.addEventListener("change", () => {
      /*
       * 如果已经输入搜索词，
       * 切换 Source 后自动重新搜索。
       */
      const input = byId("global-search-input");

      if (input && input.value.trim()) {
        runGlobalSearch();
      }
    });
  }

  const globalSearchClear = byId("global-search-clear");

  if (globalSearchClear) {
    globalSearchClear.addEventListener("click", () => {
      const input = byId("global-search-input");

      if (input) {
        input.value = "";
      }

      const typeSelect = byId("global-search-type");

      if (typeSelect) {
        typeSelect.value = "";
      }

      byId("global-search-results")?.replaceChildren();

      byId("global-search-type-stats")?.replaceChildren();

      const status = byId("global-search-status");

      if (status) {
        status.textContent = "";
      }
    });
  }

  //   Close 按钮
  const evidenceDetailClose = byId("evidence-detail-close");

  if (evidenceDetailClose) {
    evidenceDetailClose.addEventListener("click", () => {
      byId("evidence-detail-section")?.classList.add("hidden");

      byId("evidence-detail")?.replaceChildren();

      text("evidence-detail-subtitle", "");
    });
  }

  //   登陆详情页
  byId("login-apply")?.addEventListener("click", () => {
    loginState.offset = 0;

    loadLogins();
  });

  byId("login-reset")?.addEventListener("click", () => {
    for (const id of ["login-search", "login-user", "login-ip", "login-type"]) {
      const input = byId(id);

      if (input) {
        input.value = "";
      }
    }

    loginState.offset = 0;

    loadLogins();
  });

  byId("login-prev")?.addEventListener("click", () => {
    loginState.offset = Math.max(0, loginState.offset - loginState.limit);

    loadLogins();
  });

  byId("login-next")?.addEventListener("click", () => {
    if (!loginState.hasMore) {
      return;
    }

    loginState.offset += loginState.limit;

    loadLogins();
  });

  byId("close-logins")?.addEventListener("click", () => {
    byId("login-section")?.classList.add("hidden");
  });

  // 文件搜索自动搜索
  const debouncedFileSearch = debounce(() => {
    fileState.offset = 0;

    loadFiles();
  }, 300);

  byId("file-search")?.addEventListener("input", debouncedFileSearch);

  // Persistence Search
  const debouncedPersistenceSearch = debounce(() => {
    persistenceState.offset = 0;

    loadPersistence();
  }, 300);

  byId("persistence-search")?.addEventListener(
    "input",
    debouncedPersistenceSearch,
  );

  // Select Filter
  for (const id of ["file-executable", "file-finding"]) {
    byId(id)?.addEventListener("change", () => {
      fileState.offset = 0;

      loadFiles();
    });
  }

  // Persistence 过滤
  for (const id of ["persistence-type", "persistence-finding"]) {
    byId(id)?.addEventListener("change", () => {
      persistenceState.offset = 0;

      loadPersistence();
    });
  }

  // File Close
  byId("close-files")?.addEventListener("click", () => {
    fileState.requestController?.abort();

    fileState.detailController?.abort();

    byId("file-section")?.classList.add("hidden");
  });

  // Persistence close
  byId("close-persistence")?.addEventListener("click", () => {
    persistenceState.requestController?.abort();

    persistenceState.detailController?.abort();

    byId("persistence-section")?.classList.add("hidden");
  });

  // 统一导航
  byId("investigation-back")?.addEventListener(
    "click",
    navigateInvestigationBack,
  );

  byId("investigation-forward")?.addEventListener(
    "click",
    navigateInvestigationForward,
  );

  byId("investigation-copy-link")?.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
    } catch (error) {
      console.error("Copy investigation link failed:", error);
    }
  });

  window.addEventListener("popstate", handleBrowserNavigation);
}

async function main() {
  wireUI();

  const restored = await restoreInvestigationFromURL();

  if (!restored) {
    window.history.replaceState(null, "", "#/");

    pushInvestigationLocation({
      workspace: "case",

      title: "Case Overview",

      target: {},
    });
  }

  const status = byId("server-status");

  try {
    await loadJSON("/api/health");

    status.textContent = "Local";

    status.className = "status status-ok";
  } catch (error) {
    status.textContent = "Disconnected";

    status.className = "status status-error";
  }

  try {
    const caseData = await loadJSON("/api/case");

    renderCase(caseData);
  } catch (error) {
    text("case-name", `Failed to load case: ${error}`);
  }
}

main();

/* The console's UI. Plain DOM, no framework: the page is served from the same
   process that runs the audit, and it must work with nothing installed. */

const VERDICT_CLASS = {
  allowed: "allowed",
  challenged: "challenged",
  rate_limited: "rate_limited",
  blocked: "blocked",
  error: "error",
};

const VERDICT_LABEL = {
  allowed: "allowed",
  challenged: "challenged",
  rate_limited: "rate-limited",
  blocked: "blocked",
  error: "error",
};

const el = (id) => document.getElementById(id);

let pollTimer = null;

async function api(path, options) {
  const res = await fetch(path, options);
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch (err) {
    body = { error: text || res.statusText };
  }
  if (!res.ok) throw new Error(body.error || `request failed (${res.status})`);
  return body;
}

function setStatus(status) {
  const pill = el("status");
  pill.textContent = status;
  pill.className = "pill " + status;
}

function showError(message) {
  const box = el("err");
  if (!message) {
    box.hidden = true;
    box.textContent = "";
    return;
  }
  box.hidden = false;
  box.textContent = message;
}

function appendLog(event) {
  const log = el("log");
  let line;
  if (event.event === "visit") {
    const v = event.visit || {};
    line = `visit  L${v.level_id}  ${v.verdict}${
      v.http_status ? " " + v.http_status : ""
    }  ${v.reason || ""}`;
  } else if (event.event === "notice") {
    line = `notice ${event.message}`;
  } else if (event.event === "level_start") {
    line = `\n== ${event.level_name} (${event.scheduled} visitors)`;
  } else if (event.event === "level_end") {
    line = `-- ${(event.level || {}).level_name || "level"} done`;
  } else if (event.event === "error") {
    line = `ERROR  ${event.message}`;
  } else if (event.event === "end") {
    line = `\n== finished: ${event.status}`;
  } else {
    line = event.event + " " + JSON.stringify(event);
  }
  log.textContent += line + "\n";
  log.scrollTop = log.scrollHeight;
}

function renderRungs(levels) {
  const host = el("rungs");
  host.innerHTML = "";
  levels.forEach((level) => {
    const visits = level.visits || [];
    const counts = level.counts || {};
    const total = visits.length || 1;
    const wrap = document.createElement("div");
    wrap.className = "rung";

    const head = document.createElement("div");
    head.className = "rung-head";
    const name = document.createElement("div");
    name.className = "rung-name";
    name.textContent = level.level_name;
    const meta = document.createElement("div");
    meta.className = "rung-meta";
    meta.textContent =
      `${level.allowed}/${visits.length} allowed · ` +
      `${level.detected} detected · bypass ${Math.round((level.bypass_rate || 0) * 100)}%`;
    head.append(name, meta);
    wrap.append(head);
    const desc = document.createElement("div");
    desc.className = "rung-desc";
    desc.textContent = level.description || level.level_key;
    wrap.append(desc);

    const bar = document.createElement("div");
    bar.className = "bar";
    Object.keys(VERDICT_CLASS).forEach((verdict) => {
      const n = counts[verdict] || 0;
      if (!n) return;
      const span = document.createElement("span");
      span.style.width = (n / total) * 100 + "%";
      span.style.background = `var(--${verdict === "rate_limited" ? "challenge" : verdict})`;
      span.title = `${VERDICT_LABEL[verdict]}: ${n}`;
      bar.append(span);
    });
    wrap.append(bar);

    if (level.aborted) {
      const ab = document.createElement("div");
      ab.className = "isolates";
      ab.textContent = "ABORTED: " + (level.abort_reason || "");
      wrap.append(ab);
    }
    if (level.vendors && level.vendors.length) {
      const vd = document.createElement("div");
      vd.className = "isolates";
      vd.textContent = "products: " + level.vendors.join(", ");
      wrap.append(vd);
    }
    host.append(wrap);
  });
}

function renderResult(session) {
  const summary = session.summary;
  if (!summary) return;

  const findings = el("findings");
  findings.innerHTML = "";
  (summary.findings || []).forEach((f) => {
    const li = document.createElement("li");
    li.textContent = f;
    findings.append(li);
  });
  if (!(summary.findings || []).length) {
    findings.innerHTML = '<li class="empty">No findings recorded.</li>';
  }

  el("stats").textContent =
    `${summary.total_requests} requests · ${summary.total_visits} visits` +
    (session.proxy && session.proxy.configured
      ? ` · ${session.proxy.count} proxy endpoint(s)`
      : " · no proxy");
  renderRungs(summary.levels || []);

  const exports = el("exports");
  exports.hidden = false;
  exports.querySelectorAll("a").forEach((a) => {
    a.href = `/api/audits/${session.id}/report?format=${a.dataset.fmt}`;
  });
}

async function poll(sessionId, since) {
  const body = await api(`/api/audits/${sessionId}/events?since=${since}`);
  (body.events || []).forEach(appendLog);
  const next = since + (body.events || []).length;
  const session = body.session;
  setStatus(session.status);

  if (session.status === "running") {
    pollTimer = setTimeout(() => poll(sessionId, next).catch(onPollError), 600);
    return;
  }

  el("start").disabled = false;
  el("cancel").disabled = true;
  const full = await api(`/api/audits/${sessionId}`);
  renderResult(full);
  if (full.error) showError(full.error);
}

function onPollError(err) {
  showError(err.message);
  el("start").disabled = false;
  el("cancel").disabled = true;
  setStatus("failed");
}

async function start() {
  showError("");
  el("log").textContent = "";
  el("rungs").innerHTML = "";
  el("exports").hidden = true;
  el("findings").innerHTML = '<li class="empty">Audit running…</li>';
  el("start").disabled = true;
  el("cancel").disabled = false;

  const payload = {
    target_url: el("target").value,
    visitor_count: Number(el("visitors").value),
    duration_hours: Number(el("hours").value),
    max_level: Number(el("maxlevel").value),
    seed: el("seed").value === "" ? null : Number(el("seed").value),
  };
  if (el("singlelevel").checked) {
    payload.single_level = Number(el("maxlevel").value);
  }

  try {
    const session = await api("/api/audits", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setStatus(session.status);
    window.__session = session.id;
    poll(session.id, 0);
  } catch (err) {
    showError(err.message);
    el("start").disabled = false;
    el("cancel").disabled = true;
    setStatus("failed");
  }
}

async function cancel() {
  if (!window.__session) return;
  try {
    await api(`/api/audits/${window.__session}/cancel`, { method: "POST" });
    el("cancel").disabled = true;
  } catch (err) {
    showError(err.message);
  }
}

async function boot() {
  el("start").addEventListener("click", start);
  el("cancel").addEventListener("click", cancel);
  el("saveproxy").addEventListener("click", saveProxy);
  el("clearproxy").addEventListener("click", clearProxy);
  el("maxlevel").addEventListener("change", renderLevelHint);
  el("singlelevel").addEventListener("change", renderLevelHint);
  el("proxymode").addEventListener("change", () => {
    const list = el("proxymode").value === "list";
    el("listmode").hidden = !list;
    el("gatewaymode").hidden = list;
  });

  const health = await api("/api/health");
  el("target").value = health.demo_target || "";
  renderProxy(health.proxy || { configured: false });

  await refreshLevels();
  selectInitialLevel();
}

/* Which rungs can run depends on the browser being installed and on whether a
   pool is configured, so the level list is re-read after the pool changes. */
let LEVELS = [];

async function refreshLevels() {
  const body = await api("/api/levels");
  LEVELS = body.levels || [];
  const select = el("maxlevel");
  const previous = select.value;
  select.innerHTML = "";
  LEVELS.forEach((lvl) => {
    const opt = document.createElement("option");
    opt.value = lvl.id;
    opt.textContent = `${lvl.name} — ${lvl.key}`;
    if (!lvl.reachable) opt.textContent += "  (unavailable)";
    opt.disabled = !lvl.reachable;
    select.append(opt);
  });
  if (previous) select.value = previous;
  renderLevelHint();
}

function renderLevelHint() {
  const chosen = Number(el("maxlevel").value);
  const single = el("singlelevel").checked;
  el("levellabel").textContent = single ? "Rung to run" : "Highest rung to climb";
  el("visitors").disabled = single;
  if (single) el("visitors").value = 100;

  const hint = el("levelhint");
  if (single) {
    const rung = LEVELS.find((l) => l.id === chosen);
    // A single-rung run has no rung below it to compare against, so the hint
    // must not let the operator read the result as an attribution.
    hint.textContent = rung && !rung.reachable
      ? (rung.unreachable_reason || "unavailable on this host")
      : "Only this rung runs. The count is pinned to 100 so repeat runs are " +
        "comparable, and a single rung cannot attribute the defense to a control.";
    hint.className = rung && !rung.reachable ? "hint warn" : "hint";
    return;
  }

  const blocked = LEVELS.filter((l) => l.id <= chosen && !l.reachable);
  if (!blocked.length) {
    hint.textContent = "";
    hint.className = "hint";
    return;
  }
  const first = blocked[0];
  hint.textContent = first.unreachable_reason || "unavailable on this host";
  hint.className = "hint warn";
}

function selectInitialLevel() {
  const select = el("maxlevel");
  const reachable = LEVELS.filter((l) => l.reachable);
  const preferred = reachable.find((l) => l.id === 2) || reachable[reachable.length - 1];
  if (preferred) select.value = String(preferred.id);
  renderLevelHint();
}

function renderProxy(state) {
  el("proxystate").textContent = state.configured ? `${state.count} set` : "none";
  const info = el("proxyinfo");
  if (!state.configured) {
    info.textContent = "No pool configured.";
    info.className = "hint mono";
    return;
  }
  info.textContent =
    state.mode === "gateway"
      ? `gateway ${state.gateway}`
      : state.labels.join("\n");
  info.className = "hint mono ok";
}

async function saveProxy() {
  showError("");
  const mode = el("proxymode").value;
  const payload =
    mode === "gateway"
      ? { gateway: el("gateway").value.trim() }
      : { entries: el("proxyentries").value.split("\n") };
  try {
    const state = await api("/api/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    renderProxy(state);
    await refreshLevels();
    selectInitialLevel();
    el("proxybox").open = false;
  } catch (err) {
    showError(err.message);
  }
}

async function clearProxy() {
  showError("");
  try {
    const state = await api("/api/proxy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ clear: true }),
    });
    renderProxy(state);
    await refreshLevels();
    selectInitialLevel();
  } catch (err) {
    showError(err.message);
  }
}

boot().catch((err) => showError(err.message));

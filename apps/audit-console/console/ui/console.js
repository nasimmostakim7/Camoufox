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
    `${summary.total_requests} requests · ${summary.total_visits} visits`;
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

  const [health, levels] = await Promise.all([
    api("/api/health"),
    api("/api/levels"),
  ]);
  el("target").value = health.demo_target || "";
  const select = el("maxlevel");
  (levels.levels || []).forEach((lvl) => {
    const opt = document.createElement("option");
    opt.value = lvl.id;
    opt.textContent = `${lvl.name} — ${lvl.key}`;
    select.append(opt);
  });
  select.value = "2";
}

boot().catch((err) => showError(err.message));

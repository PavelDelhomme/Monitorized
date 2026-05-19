const TOKEN_KEY = "monitorized_token";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

let allTargets = [];
let targetFilter = "all";
let targetSearch = "";

function token() {
  return localStorage.getItem(TOKEN_KEY);
}

function setToken(t) {
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (token()) headers.Authorization = `Bearer ${token()}`;
  const res = await fetch(`/api/v1${path}`, { ...opts, headers });
  if (res.status === 401) {
    setToken(null);
    showLogin();
    throw new Error("session expirée");
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

function showLogin() {
  $("#login").classList.remove("hidden");
  $("#dashboard").classList.add("hidden");
}

function showDashboard() {
  $("#login").classList.add("hidden");
  $("#dashboard").classList.remove("hidden");
  refresh();
  loadCompromisePage();
}

function switchTab(name) {
  $$(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  $("#tab-overview").classList.toggle("hidden", name !== "overview");
  $("#tab-compromise").classList.toggle("hidden", name !== "compromise");
  if (name === "compromise") loadCompromisePage();
}

$$(".tab").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

function formatBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(1)} ${u[i]}`;
}

function renderHost(host) {
  const el = $("#host-metrics");
  if (!host) {
    el.innerHTML = "<p class='muted'>En attente de données…</p>";
    return;
  }
  const memPct = host.mem_total_bytes
    ? ((host.mem_used_bytes / host.mem_total_bytes) * 100).toFixed(1)
    : "—";
  el.innerHTML = `
    <div class="metric"><span>CPU</span><strong>${host.cpu_percent?.toFixed(1) ?? "—"}%</strong></div>
    <div class="metric"><span>RAM</span><strong>${memPct}%</strong></div>
    <div class="metric"><span>Load</span><strong>${host.load1?.toFixed(2) ?? "—"}</strong></div>
    <div class="metric"><span>Disque</span><strong>${formatBytes(host.disk_used_bytes)}</strong></div>
  `;
}

function renderContainers(list) {
  const el = $("#containers");
  if (!list?.length) {
    el.innerHTML = "<p class='muted'>Aucun conteneur</p>";
    return;
  }
  el.innerHTML = `<table><thead><tr><th>Nom</th><th>État</th><th>CPU</th><th>RAM</th></tr></thead><tbody>
    ${list
      .map(
        (c) => `<tr>
      <td>${escapeHtml(c.name)}</td>
      <td class="state-${c.state}">${c.state}</td>
      <td>${c.cpu_percent?.toFixed(1) ?? "—"}%</td>
      <td>${formatBytes(c.mem_usage_bytes)}</td>
    </tr>`
      )
      .join("")}
  </tbody></table>`;
}

function renderNPM(stats) {
  const el = $("#npm-stats");
  if (!stats) {
    el.innerHTML = "<p class='muted'>Logs NPM non montés ou vides</p>";
    return;
  }
  el.innerHTML = `
    <div class="metric"><span>Requêtes</span><strong>${stats.total ?? 0}</strong></div>
    <div class="metric"><span>4xx</span><strong>${stats.errors_4xx ?? 0}</strong></div>
    <div class="metric"><span>5xx</span><strong>${stats.errors_5xx ?? 0}</strong></div>
    <div class="metric"><span>Temps moy.</span><strong>${(stats.avg_request_time ?? 0).toFixed(3)}s</strong></div>
  `;
}

function renderAlerts(alerts) {
  const el = $("#alerts");
  if (!alerts?.length) {
    el.innerHTML = "<li class='muted'>Aucune alerte</li>";
    return;
  }
  el.innerHTML = alerts
    .map(
      (a) =>
        `<li class="level-${a.level}"><strong>${escapeHtml(a.source)}</strong> — ${escapeHtml(a.message)} <span class="muted">${new Date(a.ts * 1000).toLocaleString()}</span></li>`
    )
    .join("");
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

async function drawCPUChart() {
  const canvas = $("#cpu-chart");
  if (!canvas) return;
  const history = await api("/host/history?limit=60");
  const ctx = canvas.getContext("2d");
  const w = (canvas.width = canvas.offsetWidth * 2);
  const h = canvas.height * 2;
  ctx.clearRect(0, 0, w, h);
  if (!history?.length) return;
  const vals = history.map((x) => x.cpu_percent);
  const max = Math.max(...vals, 100);
  ctx.strokeStyle = "#58a6ff";
  ctx.lineWidth = 2;
  ctx.beginPath();
  vals.forEach((v, i) => {
    const x = (i / (vals.length - 1 || 1)) * w;
    const y = h - (v / max) * (h - 8) - 4;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

const kindLabel = { email: "Email", domain: "Domaine", ip: "IP" };

function renderProviders(providers) {
  const grid = $("#providers-grid");
  if (!grid || !providers) return;
  grid.innerHTML = providers
    .map(
      (p) => `
    <div class="provider-card">
      <span class="provider-free">GRATUIT</span>
      <strong>${escapeHtml(p.name)}</strong>
      <p class="muted">${escapeHtml(p.desc)}</p>
      <div class="provider-tags">${(p.targets || []).map((t) => `<span>${kindLabel[t] || t}</span>`).join("")}</div>
    </div>`
    )
    .join("");
}

function renderCompromiseSummary(summary) {
  const sumEl = $("#compromise-summary");
  if (!sumEl || !summary) return;
  const bk = summary.targets_by_kind || {};
  sumEl.innerHTML = `
    <div class="metric"><span>Total cibles</span><strong>${summary.targets_watched ?? 0}</strong></div>
    <div class="metric"><span>Emails</span><strong>${bk.email ?? 0}</strong></div>
    <div class="metric"><span>Domaines</span><strong>${bk.domain ?? 0}</strong></div>
    <div class="metric"><span>IP</span><strong>${bk.ip ?? 0}</strong></div>
    <div class="metric"><span>Critiques 7j</span><strong class="sev-critical">${summary.critical_7d ?? 0}</strong></div>
    <div class="metric"><span>Avertissements</span><strong class="sev-warning">${summary.warning_7d ?? 0}</strong></div>
  `;
  const set = (id, n) => {
    const el = document.getElementById(id);
    if (el) el.textContent = n ?? 0;
  };
  set("count-all", summary.targets_watched);
  set("count-email", bk.email);
  set("count-domain", bk.domain);
  set("count-ip", bk.ip);
}

function renderFindings(findings) {
  const listEl = $("#compromise-findings");
  if (!listEl) return;
  if (!findings?.length) {
    listEl.innerHTML = "<li class='muted'>Lance un scan après avoir ajouté tes cibles</li>";
    return;
  }
  listEl.innerHTML = findings
    .map((f) => {
      let extra = "";
      try {
        const d = JSON.parse(f.details || "{}");
        if (d.breach) extra = ` <span class="muted">[${escapeHtml(d.breach)}]</span>`;
        else if (d.lists) extra = ` <span class="muted">[${escapeHtml(d.lists.join(", "))}]</span>`;
      } catch (_) {}
      return `<li class="sev-${f.severity}">
        <span class="badge">${escapeHtml(f.provider)}</span>
        <span class="kind-tag">${kindLabel[f.target_kind] || f.target_kind}</span>
        <strong>${escapeHtml(f.target_value)}</strong> — ${escapeHtml(f.title)}${extra}
        <span class="muted">${new Date(f.ts * 1000).toLocaleString()}</span>
      </li>`;
    })
    .join("");
}

function renderTargetsTable() {
  const tbody = $("#targets-body");
  if (!tbody) return;
  let list = allTargets;
  if (targetFilter !== "all") list = list.filter((t) => t.kind === targetFilter);
  if (targetSearch) {
    const q = targetSearch.toLowerCase();
    list = list.filter((t) => t.value.toLowerCase().includes(q));
  }
  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="muted">Aucune cible — ajoute des emails, domaines ou IP ci-dessus</td></tr>`;
    return;
  }
  tbody.innerHTML = list
    .map(
      (t) => `<tr>
      <td><span class="kind-tag">${kindLabel[t.kind] || t.kind}</span></td>
      <td><code>${escapeHtml(t.value)}</code></td>
      <td class="muted">${escapeHtml(t.source)}</td>
      <td><button type="button" class="btn-del" data-id="${t.id}" title="Retirer">✕</button></td>
    </tr>`
    )
    .join("");
  tbody.querySelectorAll(".btn-del").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm("Retirer cette cible de la surveillance ?")) return;
      await api(`/compromise/targets/${btn.dataset.id}`, { method: "DELETE" });
      await loadCompromisePage();
    });
  });
}

async function loadCompromisePage() {
  if (!$("#tab-compromise")) return;
  try {
    const [providers, summary, findings, targets] = await Promise.all([
      api("/compromise/providers"),
      api("/compromise/summary"),
      api("/compromise/findings"),
      api("/compromise/targets"),
    ]);
    allTargets = targets || [];
    renderProviders(providers);
    renderCompromiseSummary(summary);
    renderFindings(findings);
    renderTargetsTable();
  } catch (e) {
    console.error(e);
  }
}

async function refresh() {
  try {
    const data = await api("/overview");
    renderHost(data.host);
    renderContainers(data.containers);
    renderNPM(data.npm_last_hour);
    renderAlerts(data.alerts);
    await drawCPUChart();
  } catch (e) {
    console.error(e);
  }
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const errEl = $("#login-error");
  errEl.classList.add("hidden");
  try {
    const res = await api("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username: fd.get("username"), password: fd.get("password") }),
    });
    setToken(res.token);
    showDashboard();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove("hidden");
  }
});

$("#logout").addEventListener("click", () => {
  setToken(null);
  showLogin();
});

$("#add-one")?.addEventListener("click", async () => {
  const kind = $("#add-kind").value;
  const value = $("#add-value").value.trim();
  if (!value) return;
  try {
    await api("/compromise/targets", {
      method: "POST",
      body: JSON.stringify({ kind, value }),
    });
    $("#add-value").value = "";
    await loadCompromisePage();
  } catch (err) {
    alert(err.message);
  }
});

$("#bulk-submit")?.addEventListener("click", async () => {
  const text = $("#bulk-import").value;
  const resEl = $("#bulk-result");
  if (!text.trim()) return;
  try {
    const res = await api("/compromise/targets/bulk", {
      method: "POST",
      body: JSON.stringify({ text }),
    });
    resEl.textContent = `${res.imported} cible(s) importée(s) sur ${res.total_lines} ligne(s) valide(s)`;
    resEl.classList.remove("hidden");
    $("#bulk-import").value = "";
    await loadCompromisePage();
  } catch (err) {
    alert(err.message);
  }
});

$$(".filter-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$(".filter-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    targetFilter = btn.dataset.filter;
    renderTargetsTable();
  });
});

$("#target-search")?.addEventListener("input", (e) => {
  targetSearch = e.target.value.trim();
  renderTargetsTable();
});

const scanBtn = $("#scan-now");
scanBtn?.addEventListener("click", async () => {
  scanBtn.disabled = true;
  scanBtn.textContent = "Scan en cours…";
  try {
    await api("/compromise/scan", { method: "POST" });
    setTimeout(loadCompromisePage, 10000);
  } catch (err) {
    alert(err.message);
  } finally {
    setTimeout(() => {
      scanBtn.textContent = "Lancer le scan";
      scanBtn.disabled = false;
    }, 10000);
  }
});

if (token()) {
  showDashboard();
  setInterval(refresh, 15000);
} else {
  showLogin();
}

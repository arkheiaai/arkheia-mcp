"""
Admin endpoints.

These are not authenticated in Phase 1 -- deploy behind network controls
(firewall, VPN) in production. Authentication layer is Phase 2.
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin")

_ADMIN_UI_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Arkheia Enterprise Proxy — Audit Dashboard</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0a0a0a;
    color: #e8e8e8;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    line-height: 1.5;
    min-height: 100vh;
  }
  a { color: #9600b3; text-decoration: none; }

  /* ── Header ── */
  header {
    background: #111;
    border-bottom: 1px solid #222;
    padding: 12px 24px;
    display: flex;
    align-items: center;
    gap: 16px;
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .header-logo {
    font-size: 17px;
    font-weight: 700;
    color: #fff;
    letter-spacing: -0.3px;
  }
  .header-logo span { color: #9600b3; }
  .header-sep { color: #444; font-size: 18px; }
  .header-host {
    font-family: 'Courier New', monospace;
    font-size: 12px;
    color: #888;
  }
  .header-right {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .refresh-badge {
    background: #1a1a1a;
    border: 1px solid #333;
    border-radius: 20px;
    padding: 4px 12px;
    font-size: 12px;
    color: #aaa;
    font-family: 'Courier New', monospace;
    min-width: 110px;
    text-align: center;
  }
  .refresh-badge.active { border-color: #9600b3; color: #bf40d6; }
  button {
    background: #9600b3;
    color: #fff;
    border: none;
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 13px;
    cursor: pointer;
    font-weight: 500;
    transition: background 0.15s;
  }
  button:hover { background: #b300d6; }
  button:active { background: #7a0091; }

  /* ── Main layout ── */
  main { padding: 24px; max-width: 1400px; margin: 0 auto; }

  /* ── Error/Info banners ── */
  .banner {
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 20px;
    font-size: 13px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .banner-error { background: #2a0a0a; border: 1px solid #5a1a1a; color: #ff8080; }
  .banner-info  { background: #0a0a1a; border: 1px solid #2a2a5a; color: #8080ff; }
  .banner-icon  { font-size: 16px; flex-shrink: 0; }

  /* ── Summary cards ── */
  .summary-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 20px;
  }
  .card {
    background: #111;
    border: 1px solid #222;
    border-radius: 10px;
    padding: 18px 20px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .card-label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-weight: 600;
    color: #666;
  }
  .card-value {
    font-size: 36px;
    font-weight: 700;
    line-height: 1;
    font-family: 'Courier New', monospace;
  }
  .card-high   { border-left: 3px solid #e53535; }
  .card-medium { border-left: 3px solid #e59900; }
  .card-low    { border-left: 3px solid #22c55e; }
  .card-unknown{ border-left: 3px solid #555; }
  .val-high    { color: #e53535; }
  .val-medium  { color: #e59900; }
  .val-low     { color: #22c55e; }
  .val-unknown { color: #888; }

  /* ── Health bar ── */
  .health-bar {
    background: #111;
    border: 1px solid #222;
    border-radius: 10px;
    padding: 14px 20px;
    display: flex;
    align-items: center;
    gap: 28px;
    margin-bottom: 20px;
    flex-wrap: wrap;
  }
  .health-item {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: #aaa;
  }
  .health-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: #22c55e;
    flex-shrink: 0;
  }
  .health-dot.warn { background: #e59900; }
  .health-dot.err  { background: #e53535; }
  .health-label { color: #555; font-size: 12px; }
  .health-value { color: #e8e8e8; font-family: 'Courier New', monospace; font-size: 12px; }

  /* ── Filter bar ── */
  .filter-bar {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
    flex-wrap: wrap;
  }
  .filter-label { color: #666; font-size: 12px; text-transform: uppercase; letter-spacing: 0.8px; }
  .filter-btn {
    background: #1a1a1a;
    border: 1px solid #333;
    color: #aaa;
    border-radius: 20px;
    padding: 4px 14px;
    font-size: 12px;
    cursor: pointer;
    transition: all 0.15s;
    font-weight: 500;
  }
  .filter-btn:hover { border-color: #9600b3; color: #bf40d6; background: #1a1a1a; }
  .filter-btn.active { background: #9600b3; border-color: #9600b3; color: #fff; }
  .filter-select {
    background: #1a1a1a;
    border: 1px solid #333;
    color: #aaa;
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
    cursor: pointer;
    outline: none;
  }
  .filter-select:focus { border-color: #9600b3; }
  .filter-sep { color: #333; }

  /* ── Table ── */
  .table-wrap {
    background: #111;
    border: 1px solid #222;
    border-radius: 10px;
    overflow: hidden;
  }
  .table-header {
    padding: 12px 20px;
    border-bottom: 1px solid #1e1e1e;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .table-title { font-size: 13px; font-weight: 600; color: #ccc; }
  .table-count { font-size: 12px; color: #666; font-family: 'Courier New', monospace; }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  thead th {
    background: #0e0e0e;
    padding: 10px 14px;
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: #555;
    border-bottom: 1px solid #1e1e1e;
    white-space: nowrap;
  }
  tbody tr {
    border-bottom: 1px solid #181818;
    cursor: pointer;
    transition: background 0.1s;
  }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: #161616; }
  tbody tr.expanded { background: #141020; }
  tbody td {
    padding: 10px 14px;
    vertical-align: middle;
    color: #ccc;
  }
  td.mono { font-family: 'Courier New', monospace; font-size: 12px; color: #aaa; }
  td.preview { color: #999; font-size: 12px; max-width: 320px; }

  /* ── Expanded row ── */
  .expand-row td {
    background: #0d0a18;
    padding: 14px 20px;
    border-bottom: 1px solid #1e1e1e;
  }
  .expand-content {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 6px 16px;
    font-size: 12px;
  }
  .expand-key { color: #666; font-weight: 600; white-space: nowrap; }
  .expand-val { font-family: 'Courier New', monospace; color: #bf40d6; word-break: break-all; }
  .expand-val.text { font-family: inherit; color: #ccc; }

  /* ── Badges ── */
  .badge {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .badge-HIGH    { background: #3a0a0a; color: #e53535; border: 1px solid #5a1a1a; }
  .badge-MEDIUM  { background: #2a1a00; color: #e59900; border: 1px solid #4a3000; }
  .badge-LOW     { background: #0a1f0a; color: #22c55e; border: 1px solid #1a3a1a; }
  .badge-UNKNOWN { background: #1a1a1a; color: #888;    border: 1px solid #333; }

  /* ── Empty state ── */
  .empty-state {
    text-align: center;
    padding: 64px 20px;
    color: #444;
  }
  .empty-state-icon { font-size: 48px; margin-bottom: 16px; }
  .empty-state-title { font-size: 16px; color: #666; font-weight: 600; margin-bottom: 8px; }
  .empty-state-sub { font-size: 13px; color: #444; }

  /* ── Confidence bar ── */
  .conf-bar-wrap { display: flex; align-items: center; gap: 8px; }
  .conf-bar {
    width: 50px; height: 4px;
    background: #222;
    border-radius: 2px;
    overflow: hidden;
    flex-shrink: 0;
  }
  .conf-bar-fill { height: 100%; border-radius: 2px; background: #9600b3; }
  .conf-num { font-family: 'Courier New', monospace; font-size: 11px; color: #888; }

  @media (max-width: 900px) {
    .summary-row { grid-template-columns: repeat(2, 1fr); }
    main { padding: 16px; }
  }
  @media (max-width: 600px) {
    .summary-row { grid-template-columns: 1fr 1fr; }
    header { flex-wrap: wrap; gap: 8px; }
  }
</style>
</head>
<body>

<header>
  <div class="header-logo"><span>Arkheia</span> Enterprise Proxy</div>
  <div class="header-sep">|</div>
  <div class="header-host">localhost:8098</div>
  <div class="header-right">
    <div class="refresh-badge" id="countdown">Refreshing...</div>
    <button onclick="refresh()">Refresh</button>
  </div>
</header>

<main>
  <div id="error-banner" class="banner banner-error" style="display:none">
    <span class="banner-icon">&#9888;</span>
    <span id="error-msg">Could not reach the proxy. Is it running on localhost:8098?</span>
  </div>

  <!-- Summary cards -->
  <div class="summary-row">
    <div class="card card-high">
      <div class="card-label">High Risk</div>
      <div class="card-value val-high" id="cnt-high">—</div>
    </div>
    <div class="card card-medium">
      <div class="card-label">Medium Risk</div>
      <div class="card-value val-medium" id="cnt-medium">—</div>
    </div>
    <div class="card card-low">
      <div class="card-label">Low Risk</div>
      <div class="card-value val-low" id="cnt-low">—</div>
    </div>
    <div class="card card-unknown">
      <div class="card-label">Unknown</div>
      <div class="card-value val-unknown" id="cnt-unknown">—</div>
    </div>
  </div>

  <!-- Health bar -->
  <div class="health-bar" id="health-bar">
    <div class="health-item">
      <div class="health-dot" id="health-dot"></div>
      <span class="health-label">Status</span>
      <span class="health-value" id="health-status">—</span>
    </div>
    <div class="health-item">
      <span class="health-label">Profiles loaded</span>
      <span class="health-value" id="health-profiles">—</span>
    </div>
    <div class="health-item">
      <span class="health-label">Last registry pull</span>
      <span class="health-value" id="health-pull">—</span>
    </div>
  </div>

  <!-- Filter bar -->
  <div class="filter-bar">
    <span class="filter-label">Risk</span>
    <button class="filter-btn active" data-risk="ALL" onclick="setRisk('ALL')">All</button>
    <button class="filter-btn badge-HIGH" data-risk="HIGH" onclick="setRisk('HIGH')">High</button>
    <button class="filter-btn badge-MEDIUM" data-risk="MEDIUM" onclick="setRisk('MEDIUM')">Medium</button>
    <button class="filter-btn badge-LOW" data-risk="LOW" onclick="setRisk('LOW')">Low</button>
    <span class="filter-sep">|</span>
    <span class="filter-label">Model</span>
    <select class="filter-select" id="model-filter" onchange="setModel(this.value)">
      <option value="ALL">All models</option>
    </select>
  </div>

  <!-- Audit table -->
  <div class="table-wrap">
    <div class="table-header">
      <span class="table-title">Audit Log</span>
      <span class="table-count" id="table-count">0 events</span>
    </div>
    <div id="table-body-wrap">
      <div class="empty-state">
        <div class="empty-state-icon">&#128274;</div>
        <div class="empty-state-title">Loading audit events&hellip;</div>
        <div class="empty-state-sub">Fetching data from localhost:8098</div>
      </div>
    </div>
  </div>
</main>

<script>
(function() {
  // ── State ──────────────────────────────────────────────────────────────
  var allEvents = [];
  var riskFilter = 'ALL';
  var modelFilter = 'ALL';
  var expandedRows = new Set();
  var refreshInterval = 30;
  var countdown = refreshInterval;
  var timer = null;
  var loaded = false;

  // ── Fetch all data ──────────────────────────────────────────────────────
  async function fetchAll() {
    try {
      var [auditResp, healthResp] = await Promise.all([
        fetch('/audit/log?limit=200'),
        fetch('/admin/health'),
      ]);

      if (!auditResp.ok || !healthResp.ok) throw new Error('Non-OK response from proxy');

      var audit  = await auditResp.json();
      var health = await healthResp.json();

      hideError();
      updateSummary(audit.summary || {});
      updateHealth(health);
      allEvents = audit.events || [];
      updateModelDropdown(allEvents);
      renderTable();
      loaded = true;
    } catch (e) {
      showError('Could not reach the proxy at localhost:8098. ' + (e.message || ''));
      if (!loaded) renderEmpty('Connection failed', 'Waiting for proxy on localhost:8098&hellip;');
    }
  }

  // ── Summary cards ───────────────────────────────────────────────────────
  function updateSummary(s) {
    document.getElementById('cnt-high').textContent    = s.HIGH    !== undefined ? s.HIGH    : '0';
    document.getElementById('cnt-medium').textContent  = s.MEDIUM  !== undefined ? s.MEDIUM  : '0';
    document.getElementById('cnt-low').textContent     = s.LOW     !== undefined ? s.LOW     : '0';
    document.getElementById('cnt-unknown').textContent = s.UNKNOWN !== undefined ? s.UNKNOWN : '0';
  }

  // ── Health bar ──────────────────────────────────────────────────────────
  function updateHealth(h) {
    var dot = document.getElementById('health-dot');
    var statusEl = document.getElementById('health-status');
    var ok = h.status === 'ok';
    dot.className = 'health-dot' + (ok ? '' : ' err');
    statusEl.textContent = h.status || 'unknown';
    document.getElementById('health-profiles').textContent =
      (h.profiles_loaded !== undefined ? h.profiles_loaded : '?') +
      (h.profile_ids && h.profile_ids.length ? ' (' + h.profile_ids.slice(0, 3).join(', ') + (h.profile_ids.length > 3 ? '…' : '') + ')' : '');
    document.getElementById('health-pull').textContent =
      h.last_registry_pull ? fmtTs(h.last_registry_pull) : 'never';
  }

  // ── Model dropdown ──────────────────────────────────────────────────────
  function updateModelDropdown(events) {
    var models = [...new Set(events.map(function(e) { return e.model_id || 'unknown'; }))].sort();
    var sel = document.getElementById('model-filter');
    var current = sel.value;
    sel.innerHTML = '<option value="ALL">All models</option>';
    models.forEach(function(m) {
      var opt = document.createElement('option');
      opt.value = m; opt.textContent = m;
      if (m === current) opt.selected = true;
      sel.appendChild(opt);
    });
  }

  // ── Table rendering ─────────────────────────────────────────────────────
  function filtered() {
    return allEvents.filter(function(e) {
      if (riskFilter !== 'ALL' && e.risk_level !== riskFilter) return false;
      if (modelFilter !== 'ALL' && (e.model_id || 'unknown') !== modelFilter) return false;
      return true;
    });
  }

  function renderTable() {
    var events = filtered();
    var wrap = document.getElementById('table-body-wrap');
    document.getElementById('table-count').textContent =
      events.length + ' event' + (events.length !== 1 ? 's' : '');

    if (!events.length) {
      if (loaded) {
        renderEmpty('No events', riskFilter !== 'ALL' || modelFilter !== 'ALL'
          ? 'No events match the current filters.'
          : 'No detection events recorded yet. Events appear as AI traffic flows through the proxy.');
      }
      return;
    }

    var html = '<table><thead><tr>' +
      '<th>Seq</th><th>Timestamp</th><th>Model</th><th>Risk</th>' +
      '<th>Confidence</th><th>Session</th><th>Prompt Preview</th>' +
      '</tr></thead><tbody>';

    events.forEach(function(e, idx) {
      var rid = 'row-' + idx;
      var isExp = expandedRows.has(e.seq || idx);
      var riskBadge = badge(e.risk_level);
      var conf = typeof e.confidence === 'number' ? e.confidence : null;
      var confHtml = conf !== null
        ? '<div class="conf-bar-wrap"><div class="conf-bar"><div class="conf-bar-fill" style="width:' + Math.round(conf * 100) + '%"></div></div><span class="conf-num">' + conf.toFixed(2) + '</span></div>'
        : '<span class="conf-num">—</span>';
      var session = e.session_id ? e.session_id.slice(0, 12) + '…' : '—';
      var preview = e.prompt_preview ? escHtml(e.prompt_preview.slice(0, 60)) + (e.prompt_preview.length > 60 ? '…' : '') : '—';
      var ts = e.ts ? fmtTs(e.ts) : '—';
      var model = escHtml(e.model_id || 'unknown');
      var seqNum = e.seq !== undefined ? e.seq : '?';

      html += '<tr class="' + (isExp ? 'expanded' : '') + '" onclick="toggleRow(' + (e.seq || idx) + ',' + idx + ')" data-rowid="' + rid + '">' +
        '<td class="mono">' + seqNum + '</td>' +
        '<td class="mono">' + ts + '</td>' +
        '<td class="mono">' + model + '</td>' +
        '<td>' + riskBadge + '</td>' +
        '<td>' + confHtml + '</td>' +
        '<td class="mono" title="' + escHtml(e.session_id || '') + '">' + session + '</td>' +
        '<td class="preview">' + preview + '</td>' +
        '</tr>';

      if (isExp) {
        html += '<tr class="expand-row"><td colspan="7"><div class="expand-content">' +
          '<span class="expand-key">Detection ID</span><span class="expand-val">' + escHtml(e.detection_id || '—') + '</span>' +
          '<span class="expand-key">Session ID</span><span class="expand-val">' + escHtml(e.session_id || '—') + '</span>' +
          '<span class="expand-key">Full prompt</span><span class="expand-val text">' + escHtml(e.prompt_preview || '—') + '</span>' +
          '<span class="expand-key">Model</span><span class="expand-val">' + escHtml(e.model_id || '—') + '</span>' +
          '<span class="expand-key">Risk level</span><span class="expand-val">' + escHtml(e.risk_level || '—') + '</span>' +
          '</div></td></tr>';
      }
    });

    html += '</tbody></table>';
    wrap.innerHTML = html;
  }

  function renderEmpty(title, sub) {
    document.getElementById('table-body-wrap').innerHTML =
      '<div class="empty-state">' +
      '<div class="empty-state-icon">&#128202;</div>' +
      '<div class="empty-state-title">' + title + '</div>' +
      '<div class="empty-state-sub">' + sub + '</div>' +
      '</div>';
  }

  // ── Row expand toggle ────────────────────────────────────────────────────
  window.toggleRow = function(seq, idx) {
    var key = seq;
    if (expandedRows.has(key)) expandedRows.delete(key);
    else expandedRows.add(key);
    renderTable();
  };

  // ── Filters ─────────────────────────────────────────────────────────────
  window.setRisk = function(r) {
    riskFilter = r;
    document.querySelectorAll('[data-risk]').forEach(function(btn) {
      btn.classList.toggle('active', btn.dataset.risk === r);
    });
    renderTable();
  };

  window.setModel = function(m) {
    modelFilter = m;
    renderTable();
  };

  // ── Error banner ────────────────────────────────────────────────────────
  function showError(msg) {
    var el = document.getElementById('error-banner');
    document.getElementById('error-msg').textContent = msg;
    el.style.display = 'flex';
  }
  function hideError() {
    document.getElementById('error-banner').style.display = 'none';
  }

  // ── Countdown timer ──────────────────────────────────────────────────────
  function startTimer() {
    countdown = refreshInterval;
    updateCountdown();
    if (timer) clearInterval(timer);
    timer = setInterval(function() {
      countdown--;
      if (countdown <= 0) {
        countdown = refreshInterval;
        fetchAll();
      }
      updateCountdown();
    }, 1000);
  }

  function updateCountdown() {
    var el = document.getElementById('countdown');
    el.textContent = 'Refresh in ' + countdown + 's';
    el.className = 'refresh-badge' + (countdown <= 5 ? ' active' : '');
  }

  window.refresh = function() {
    fetchAll();
    startTimer();
  };

  // ── Helpers ──────────────────────────────────────────────────────────────
  function badge(level) {
    var l = (level || 'UNKNOWN').toUpperCase();
    var cls = ['HIGH','MEDIUM','LOW'].includes(l) ? l : 'UNKNOWN';
    return '<span class="badge badge-' + cls + '">' + cls + '</span>';
  }

  function fmtTs(ts) {
    if (!ts) return '—';
    try {
      var d = new Date(ts);
      var pad = function(n) { return String(n).padStart(2,'0'); };
      return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate()) +
        ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    } catch(e) { return ts; }
  }

  function escHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g,'&amp;')
      .replace(/</g,'&lt;')
      .replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;');
  }

  // ── Boot ────────────────────────────────────────────────────────────────
  fetchAll();
  startTimer();
})();
</script>
</body>
</html>"""


@router.get("/health")
async def health(request: Request):
    """
    Health check. Returns loaded profile count and last registry pull timestamp.
    """
    profile_router = getattr(request.app.state, "profile_router", None)
    registry_client = getattr(request.app.state, "registry_client", None)

    profiles_loaded = profile_router.loaded_count if profile_router else 0
    profile_ids = profile_router.profile_ids if profile_router else []
    last_pull = (
        registry_client.last_pull.isoformat()
        if registry_client and registry_client.last_pull
        else None
    )

    return {
        "status": "ok",
        "profiles_loaded": profiles_loaded,
        "profile_ids": profile_ids,
        "last_registry_pull": last_pull,
    }


@router.post("/registry/pull")
async def manual_registry_pull(request: Request):
    """Trigger a manual profile registry pull."""
    registry_client = getattr(request.app.state, "registry_client", None)
    if registry_client is None:
        return {"status": "error", "detail": "registry_client not configured"}

    try:
        await registry_client.pull()
        return {"status": "ok", "message": "Registry pull completed"}
    except Exception as e:
        logger.error("Manual registry pull failed: %s", e)
        return {"status": "error", "detail": str(e)}


@router.post("/profiles/{model_id}/rollback")
async def rollback_profile(model_id: str, request: Request):
    """
    Roll back a profile to its previous version (.bak file).

    The registry client keeps a .bak of the previous version after each update.
    Rollback replaces the current YAML with the .bak and reloads the router.
    """
    settings = getattr(request.app.state, "settings", None)
    profile_router = getattr(request.app.state, "profile_router", None)

    if settings is None or profile_router is None:
        return {"status": "error", "detail": "server not fully initialized"}

    profile_dir = settings.detection.profile_dir
    path = Path(profile_dir) / f"{model_id}.yaml"
    bak = Path(str(path) + ".bak")

    if not bak.exists():
        return {"status": "error", "detail": f"no backup available for {model_id}"}

    try:
        path.write_bytes(bak.read_bytes())
        await profile_router.reload()
        return {"status": "ok", "message": f"Rolled back {model_id} from backup"}
    except Exception as e:
        logger.error("Rollback failed for %s: %s", model_id, e)
        return {"status": "error", "detail": str(e)}


@router.get("/profiles")
async def list_profiles(request: Request):
    """List all loaded profiles with their versions."""
    profile_router = getattr(request.app.state, "profile_router", None)
    if profile_router is None:
        return {"profiles": []}

    profiles = []
    for model_id, data in profile_router._profiles.items():
        version = str(
            data.get("version")
            or data.get("metadata", {}).get("version", "unknown")
        )
        profiles.append({"model_id": model_id, "version": version})

    return {"profiles": profiles, "count": len(profiles)}


@router.get("/ui", response_class=HTMLResponse)
async def admin_ui():
    """Serve the self-contained audit log dashboard HTML page."""
    return HTMLResponse(content=_ADMIN_UI_HTML)

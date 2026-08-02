"""
Admin endpoints — protected by Google OAuth + JWT session cookie.

Browser endpoint (/admin/ui) redirects unauthenticated requests to /auth/google.
JSON API endpoints (/admin/health, /admin/registry/pull, etc.) return 401.
"""

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from proxy.auth import require_auth, COOKIE_NAME, verify_jwt
from proxy.audit.decision_journal import (
    DECIDED_AT_AT_EMIT,
    PROFILE_ROLLBACK_APPLIED,
    PROFILE_ROLLBACK_BACKUP_VALIDATION_FAILED,
    PROFILE_ROLLBACK_INVALID_MODEL_ID,
    PROFILE_ROLLBACK_IO_ERROR,
    PROFILE_ROLLBACK_LIVE_VALIDATION_FAILED,
    PROFILE_ROLLBACK_MODEL_MISMATCH,
    PROFILE_ROLLBACK_NO_BACKUP,
    PROFILE_ROLLBACK_NO_LIVE,
    PROFILE_ROLLBACK_RELOAD_FAILED,
    PROFILE_ROLLBACK_SERVER_NOT_READY,
    build_profile_rollback_record,
    emit,
    stamp_decision,
)
from proxy.pathsafe import is_safe_model_id, safe_profile_write_path
from proxy.registry.validator import ProfileValidator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin")


def _profile_paths(profile_dir: str, model_id: str) -> tuple[Path, Path]:
    """Resolve the live and backup profile paths without allowing subpaths.

    ``model_id`` is a REGISTRY identifier, not a filesystem stem: real ids
    legitimately contain ``:`` and ``/`` (ollama ``qwen3:8b``, HF
    ``deepseek-ai/DeepSeek-V3.1``). Those ids are cached by the registry client
    under a percent-ENCODED single-component name, so rollback must derive the
    same name or it can never target them. Resolution therefore goes through the
    shared WRITE-side chokepoint ``proxy.pathsafe.safe_profile_write_path``:
    syntactic pre-filter (``..``/NUL/backslash/empty/oversized rejected), realpath
    containment on the RAW id (an absolute or escaping id is REJECTED, never
    silently encoded into a contained name), then encoding to a single top-level
    component.

    This REPLACES the previous ``^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`` filename-stem
    regex (which could never target a registry id containing ``:`` or ``/``); every
    stem that regex admitted still resolves identically, because such a stem
    encodes to itself. The invariant that regex existed to enforce — the resolved
    live/backup paths are direct children of the profiles root, never a subpath —
    is preserved by ``safe_profile_write_path`` AND re-asserted below, so a crafted
    id still cannot escape: ``ValueError`` -> HTTP 400, no write and no reload.
    """
    if not isinstance(model_id, str) or not is_safe_model_id(model_id):
        raise ValueError("model_id must be a safe profile identifier")
    live_path = safe_profile_write_path(profile_dir, model_id)
    if live_path is None:
        raise ValueError("profile path escaped profile_dir")
    root = Path(profile_dir).resolve()
    backup_path = Path(str(live_path) + ".bak").resolve()
    if live_path.parent != root or backup_path.parent != root:
        raise ValueError("profile path escaped profile_dir")
    return live_path, backup_path


def _profile_model_id(profile: dict) -> Optional[str]:
    model_id = profile.get("model") or profile.get("metadata", {}).get("model_id")
    return str(model_id) if model_id is not None else None


def _profile_version(profile: dict) -> Optional[str]:
    version = profile.get("version") or profile.get("metadata", {}).get("version")
    return str(version) if version is not None else None


def _admin_error(status_code: int, detail: str, **extra):
    body = {"status": "error", "detail": detail}
    body.update(extra)
    return JSONResponse(status_code=status_code, content=body)


async def _emit_rollback(
    request: Request,
    *,
    outcome: str,
    model_id: str,
    admin_email: Optional[str],
    live_model_id: Optional[str] = None,
    backup_model_id: Optional[str] = None,
    live_version: Optional[str] = None,
    backup_version: Optional[str] = None,
    error_type: Optional[str] = None,
) -> tuple[Optional[str], str]:
    """Emit a rollback governance receipt without making rollback depend on the rail."""
    record = build_profile_rollback_record(
        outcome=outcome,
        model_id=model_id,
        admin_email=admin_email,
        live_model_id=live_model_id,
        backup_model_id=backup_model_id,
        live_version=live_version,
        backup_version=backup_version,
        error_type=error_type,
    )
    record = stamp_decision(record, source=DECIDED_AT_AT_EMIT)
    writer = getattr(request.app.state, "audit_writer", None)
    receipt_status = await emit(writer, record)
    return record["decision_id"], receipt_status

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
async def health(request: Request, _: str = Depends(require_auth)):
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

    # Binary-integrity state of the compiled detection modules, published so the
    # UNVERIFIED case is VISIBLE to an operator rather than only in a startup log
    # line nobody reads. Codex finding 4: absent/unverifiable fails open, but it
    # must not fail silent. A TAMPERED engine never reaches this endpoint at all —
    # the lifespan refuses to start (proxy/main.py step 1c).
    integrity = getattr(request.app.state, "integrity", None) or {
        "status": "NOT_CHECKED",
        "verified": False,
        "startup_blocked": False,
        "detail": "the startup integrity self-check did not record a result; treat "
                  "the compiled detection modules as UNVERIFIED",
    }

    # Audit hash-chain health, read LIVE from the writer on every request (not a
    # boot-time snapshot), so a chain that degrades while the process runs shows
    # up here too. Codex adversarial review of PR #37: startup detected a broken
    # chain, logged one line, and every operator surface still said "ok" — while
    # the writer silently dropped every subsequent record. Posture is loudly
    # degraded rather than fail-closed (see proxy/main.py step 0 for why), which
    # only works if "degraded" is actually visible somewhere durable.
    writer = getattr(request.app.state, "audit_writer", None)
    if writer is not None and hasattr(writer, "chain_status"):
        audit_chain = writer.chain_status()
    else:
        audit_chain = getattr(request.app.state, "audit_chain", None) or {
            "ok": False,
            "status": "NOT_CHECKED",
            "detail": "no audit chain self-check result was recorded; treat the "
                      "audit log as UNVERIFIED",
            "startup_blocked": False,
        }

    return {
        # A corrupt audit chain must not be reportable as a healthy service.
        # Fail-open on availability (we are up and still recording), but this
        # top-level value is what a probe or a human actually reads.
        "status": "ok" if audit_chain.get("ok", False) else "degraded",
        "profiles_loaded": profiles_loaded,
        "profile_ids": profile_ids,
        "last_registry_pull": last_pull,
        "integrity": integrity,
        "audit_chain": audit_chain,
    }


@router.post("/registry/pull")
async def manual_registry_pull(request: Request, _: str = Depends(require_auth)):
    """Trigger a manual profile registry pull."""
    registry_client = getattr(request.app.state, "registry_client", None)
    if registry_client is None:
        return {"status": "error", "detail": "registry_client not configured"}

    try:
        summary = await registry_client.pull()
        if not isinstance(summary, dict):
            return {"status": "error", "detail": "registry_client returned invalid pull summary"}

        updated = list(summary.get("updated") or [])
        skipped = list(summary.get("skipped") or [])
        errors = list(summary.get("errors") or [])
        # Receipts are the caller-visible proof of the pull decision. Returning
        # only a summary leaves every refusal unreachable from the HTTP surface.
        receipts = list(summary.get("receipts") or [])

        if errors:
            status = "partial" if updated or skipped else "error"
            message = "Registry pull completed with errors"
        else:
            status = "ok"
            message = "Registry pull completed"

        return {
            "status": status,
            "message": message,
            "updated": updated,
            "skipped": skipped,
            "errors": errors,
            "receipts": receipts,
            "summary": {
                **summary,
                "updated": updated,
                "skipped": skipped,
                "errors": errors,
                "receipts": receipts,
            },
        }
    except Exception as e:
        logger.error("Manual registry pull failed: %s", e)
        return {"status": "error", "detail": str(e)}


@router.post("/profiles/{model_id}/rollback")
@router.post("/profiles/{model_id:path}/rollback")
async def rollback_profile(
    model_id: str,
    request: Request,
    admin_email: str = Depends(require_auth),
):
    """
    Roll back a profile to its previous version (.bak file).

    The registry client keeps a .bak of the previous version after each update.
    Rollback validates the live/backup pair before replacing the current YAML,
    reloads the router, and restores the live file if reload fails.

    Registered TWICE on purpose. The single-segment ``{model_id}`` route is the
    canonical shape (and the one the admin auth floor enumerates); the
    ``{model_id:path}`` alias additionally makes a slash-bearing registry id
    (``deepseek-ai/DeepSeek-V3.1``) reachable at all — the single-segment matcher
    can never target one, yet its cache/.bak DO exist, under the ENCODED
    single-component name ``_profile_paths`` derives, so rollback would otherwise
    be permanently unreachable for those ids. The alias adds no exposure:
    ``_profile_paths`` rejects traversal via the shared pre-filter + realpath
    containment and re-asserts ``parent == profiles_root`` before any write, so a
    crafted id is a fail-closed 400 with no write and no reload.
    """
    settings = getattr(request.app.state, "settings", None)
    profile_router = getattr(request.app.state, "profile_router", None)

    if settings is None or profile_router is None:
        decision_id, receipt_status = await _emit_rollback(
            request,
            outcome=PROFILE_ROLLBACK_SERVER_NOT_READY,
            model_id=model_id,
            admin_email=admin_email,
        )
        return _admin_error(
            503,
            "server not fully initialized",
            decision_id=decision_id,
            receipt_status=receipt_status,
        )

    profile_dir = settings.detection.profile_dir
    # Path-traversal hardening (F23, WRITE side): resolve model_id through the
    # shared pre-filter + realpath containment BEFORE building any write path, so
    # a crafted id ("../pwned", an absolute path) cannot write/target a file
    # outside the profiles root (nor act as a file-existence oracle / reload
    # trigger). Fail-closed 400: no write, no reload, receipted below.
    try:
        path, bak = _profile_paths(profile_dir, model_id)
    except ValueError:
        decision_id, receipt_status = await _emit_rollback(
            request,
            outcome=PROFILE_ROLLBACK_INVALID_MODEL_ID,
            model_id=model_id,
            admin_email=admin_email,
            error_type="ValueError",
        )
        return _admin_error(
            400,
            "invalid profile id",
            decision_id=decision_id,
            receipt_status=receipt_status,
        )

    if not path.exists():
        decision_id, receipt_status = await _emit_rollback(
            request,
            outcome=PROFILE_ROLLBACK_NO_LIVE,
            model_id=model_id,
            admin_email=admin_email,
        )
        return _admin_error(
            404,
            f"no live profile available for {model_id}",
            decision_id=decision_id,
            receipt_status=receipt_status,
        )

    if not bak.exists():
        decision_id, receipt_status = await _emit_rollback(
            request,
            outcome=PROFILE_ROLLBACK_NO_BACKUP,
            model_id=model_id,
            admin_email=admin_email,
        )
        return _admin_error(
            404,
            f"no backup available for {model_id}",
            decision_id=decision_id,
            receipt_status=receipt_status,
        )

    validator = ProfileValidator()
    try:
        live_bytes = path.read_bytes()
        backup_bytes = bak.read_bytes()
    except Exception as e:
        logger.error("Rollback failed to read profile files for %s: %s", model_id, e)
        decision_id, receipt_status = await _emit_rollback(
            request,
            outcome=PROFILE_ROLLBACK_IO_ERROR,
            model_id=model_id,
            admin_email=admin_email,
            error_type=type(e).__name__,
        )
        return _admin_error(
            500,
            "could not read live/backup profile files",
            decision_id=decision_id,
            receipt_status=receipt_status,
        )

    try:
        live_profile = validator.validate(live_bytes)
    except ValueError as e:
        decision_id, receipt_status = await _emit_rollback(
            request,
            outcome=PROFILE_ROLLBACK_LIVE_VALIDATION_FAILED,
            model_id=model_id,
            admin_email=admin_email,
            error_type=type(e).__name__,
        )
        return _admin_error(
            409,
            "live profile failed validation; refusing rollback",
            decision_id=decision_id,
            receipt_status=receipt_status,
        )

    live_model_id = _profile_model_id(live_profile)
    live_version = _profile_version(live_profile)

    try:
        backup_profile = validator.validate(backup_bytes)
    except ValueError as e:
        decision_id, receipt_status = await _emit_rollback(
            request,
            outcome=PROFILE_ROLLBACK_BACKUP_VALIDATION_FAILED,
            model_id=model_id,
            admin_email=admin_email,
            live_model_id=live_model_id,
            live_version=live_version,
            error_type=type(e).__name__,
        )
        return _admin_error(
            400,
            "backup profile failed validation; live profile left unchanged",
            decision_id=decision_id,
            receipt_status=receipt_status,
        )

    backup_model_id = _profile_model_id(backup_profile)
    backup_version = _profile_version(backup_profile)
    if live_model_id != backup_model_id:
        decision_id, receipt_status = await _emit_rollback(
            request,
            outcome=PROFILE_ROLLBACK_MODEL_MISMATCH,
            model_id=model_id,
            admin_email=admin_email,
            live_model_id=live_model_id,
            backup_model_id=backup_model_id,
            live_version=live_version,
            backup_version=backup_version,
        )
        return _admin_error(
            409,
            "backup profile model_id does not match live profile",
            decision_id=decision_id,
            receipt_status=receipt_status,
        )

    tmp = path.with_name(f".{path.name}.rollback.tmp")
    restore_tmp = path.with_name(f".{path.name}.rollback.restore.tmp")
    try:
        tmp.write_bytes(backup_bytes)
        tmp.replace(path)
        await profile_router.reload()
        decision_id, receipt_status = await _emit_rollback(
            request,
            outcome=PROFILE_ROLLBACK_APPLIED,
            model_id=model_id,
            admin_email=admin_email,
            live_model_id=live_model_id,
            backup_model_id=backup_model_id,
            live_version=live_version,
            backup_version=backup_version,
        )
        return {
            "status": "ok",
            "message": f"Rolled back {model_id} from backup",
            "decision_id": decision_id,
            "receipt_status": receipt_status,
            "live_version": live_version,
            "backup_version": backup_version,
        }
    except Exception as e:
        logger.error("Rollback failed for %s: %s", model_id, e)
        try:
            restore_tmp.write_bytes(live_bytes)
            restore_tmp.replace(path)
            await profile_router.reload()
        except Exception as restore_exc:
            logger.error(
                "Rollback restore failed for %s after reload error %s: %s",
                model_id,
                type(e).__name__,
                restore_exc,
            )
        decision_id, receipt_status = await _emit_rollback(
            request,
            outcome=PROFILE_ROLLBACK_RELOAD_FAILED,
            model_id=model_id,
            admin_email=admin_email,
            live_model_id=live_model_id,
            backup_model_id=backup_model_id,
            live_version=live_version,
            backup_version=backup_version,
            error_type=type(e).__name__,
        )
        return _admin_error(
            500,
            "profile rollback failed during router reload; live profile restored",
            decision_id=decision_id,
            receipt_status=receipt_status,
        )
    finally:
        tmp.unlink(missing_ok=True)
        restore_tmp.unlink(missing_ok=True)


@router.get("/profiles")
async def list_profiles(request: Request, _: str = Depends(require_auth)):
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
async def admin_ui(request: Request):
    """Serve the self-contained audit log dashboard HTML page.

    Redirects to /auth/google if the session cookie is missing or invalid.
    """
    token = request.cookies.get(COOKIE_NAME)
    if not token or not verify_jwt(token):
        return RedirectResponse(url="/auth/google", status_code=302)
    return HTMLResponse(content=_ADMIN_UI_HTML)

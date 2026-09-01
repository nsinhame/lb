//! `/nitai` admin dashboard: a single static HTML/JS page that polls `/stats`.

use axum::response::{Html, IntoResponse};

pub async fn nitai() -> impl IntoResponse {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Nitai – Load Balancer Dashboard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
  header{background:linear-gradient(135deg,#1a1f2e,#252d3d);padding:20px 32px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #2d3748}
  header h1{font-size:1.6rem;font-weight:700;color:#63b3ed;letter-spacing:.5px}
  header h1 span{color:#68d391}
  #status-bar{font-size:.8rem;color:#718096;display:flex;align-items:center;gap:8px}
  #dot{width:8px;height:8px;border-radius:50%;background:#68d391;animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
  main{padding:24px 32px;display:grid;gap:20px}
  .row{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
  .card{background:#1a1f2e;border:1px solid #2d3748;border-radius:12px;padding:20px}
  .card h2{font-size:.75rem;text-transform:uppercase;letter-spacing:1px;color:#718096;margin-bottom:12px}
  .stat-val{font-size:2rem;font-weight:700;color:#63b3ed}
  .stat-sub{font-size:.78rem;color:#718096;margin-top:4px}
  #best-cdn-val{font-size:1rem;word-break:break-all;color:#68d391;margin-top:6px;font-weight:600}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  th{text-align:left;padding:10px 12px;color:#718096;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.8px;border-bottom:1px solid #2d3748}
  td{padding:10px 12px;border-bottom:1px solid #1e2535;vertical-align:middle}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#252d3d}
  .badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:.72rem;font-weight:600}
  .online{background:#1c4532;color:#68d391}
  .offline{background:#742a2a;color:#fc8181}
  .load-bar-wrap{background:#2d3748;border-radius:4px;height:8px;width:120px;overflow:hidden}
  .load-bar{height:100%;border-radius:4px;background:linear-gradient(90deg,#63b3ed,#4299e1);transition:width .4s}
  .load-bar.warn{background:linear-gradient(90deg,#f6ad55,#ed8936)}
  .load-bar.danger{background:linear-gradient(90deg,#fc8181,#e53e3e)}
  .section-title{font-size:.95rem;font-weight:600;color:#a0aec0;margin-bottom:10px}
  .pool-heading{font-size:1.05rem;font-weight:700;color:#63b3ed;letter-spacing:.3px}
  .empty{color:#4a5568;font-style:italic;font-size:.85rem;padding:12px 0}
  .trusted-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}
  .trusted-chip{background:#1a365d;color:#90cdf4;border-radius:6px;padding:3px 10px;font-size:.78rem;font-family:monospace}
  .cdn-link{display:block;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#63b3ed;text-decoration:none;cursor:pointer}
  .cdn-link:hover{text-decoration:underline;color:#90cdf4}
  @media(max-width:600px){main{padding:16px};header{padding:16px}}
</style>
</head>
<body>
<header>
  <h1>⚡ Nitai <span>Dashboard</span></h1>
  <div id="status-bar"><div id="dot"></div><span id="last-update">Loading…</span></div>
</header>
<main>
  <div class="pool-heading">plgb</div>
  <div class="row" id="summary-cards">
    <div class="card"><h2>Total CDNs</h2><div class="stat-val" id="total-cdns">–</div><div class="stat-sub">registered</div></div>
    <div class="card"><h2>Online CDNs</h2><div class="stat-val" id="online-cdns" style="color:#68d391">–</div><div class="stat-sub">responding</div></div>
    <div class="card"><h2>Offline CDNs</h2><div class="stat-val" id="offline-cdns" style="color:#fc8181">–</div><div class="stat-sub">unreachable</div></div>
    <div class="card"><h2>Total Load</h2><div class="stat-val" id="total-load">–</div><div class="stat-sub">active connections</div></div>
    <div class="card"><h2>Best CDN</h2><div id="best-cdn-val">–</div><div class="stat-sub">current selection</div></div>
  </div>

  <div class="card">
    <div class="section-title">CDN Registry</div>
    <table>
      <thead><tr><th>URL</th><th>Status</th><th>Load</th><th>Load Bar</th><th>Fail Count</th><th>Last Updated</th></tr></thead>
      <tbody id="cdn-table-body"><tr><td colspan="6" class="empty">Loading…</td></tr></tbody>
    </table>
  </div>

  <div class="pool-heading">telethon-plgb</div>
  <div class="row" id="summary-cards-t">
    <div class="card"><h2>Total CDNs</h2><div class="stat-val" id="total-cdns-t">–</div><div class="stat-sub">registered</div></div>
    <div class="card"><h2>Online CDNs</h2><div class="stat-val" id="online-cdns-t" style="color:#68d391">–</div><div class="stat-sub">responding</div></div>
    <div class="card"><h2>Offline CDNs</h2><div class="stat-val" id="offline-cdns-t" style="color:#fc8181">–</div><div class="stat-sub">unreachable</div></div>
    <div class="card"><h2>Total Load</h2><div class="stat-val" id="total-load-t">–</div><div class="stat-sub">active connections</div></div>
    <div class="card"><h2>Best CDN</h2><div id="best-cdn-val-t">–</div><div class="stat-sub">current selection</div></div>
  </div>

  <div class="card">
    <div class="section-title">CDN Registry</div>
    <table>
      <thead><tr><th>URL</th><th>Status</th><th>Load</th><th>Load Bar</th><th>Fail Count</th><th>Last Updated</th></tr></thead>
      <tbody id="cdn-table-body-t"><tr><td colspan="6" class="empty">Loading…</td></tr></tbody>
    </table>
  </div>

  <div class="card">
    <div class="section-title">Trusted Hosts</div>
    <div class="trusted-list" id="trusted-list"></div>
  </div>
</main>

<script>
const REFRESH_MS = 5000;

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
}

function loadColor(load) {
  if (load >= 99999) return 'danger';
  if (load > 20) return 'warn';
  return '';
}

function loadBarWidth(load) {
  if (load >= 99999) return 100;
  return Math.min(100, Math.round((load / 50) * 100));
}

const ADMIN_KEY = new URLSearchParams(location.search).get('key') || '';

// If no key in URL, show a login overlay instead of silently failing
if (!ADMIN_KEY) {
  document.addEventListener('DOMContentLoaded', () => {
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;background:#0f1117;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;z-index:999';
    overlay.innerHTML = `
      <h2 style="color:#63b3ed;font-size:1.4rem">⚡ Nitai Dashboard</h2>
      <p style="color:#718096;font-size:.9rem">Enter your admin key to continue</p>
      <input id="key-input" type="password" placeholder="LB_ADMIN_KEY" style="background:#1a1f2e;border:1px solid #2d3748;color:#e2e8f0;border-radius:8px;padding:10px 16px;font-size:1rem;width:300px;outline:none">
      <button onclick="const k=document.getElementById('key-input').value;if(k)location.search='?key='+encodeURIComponent(k)" style="background:#2b6cb0;color:#fff;border:none;border-radius:8px;padding:10px 24px;font-size:1rem;cursor:pointer">Open Dashboard</button>
    `;
    document.body.appendChild(overlay);
    document.getElementById('key-input').addEventListener('keydown', e => {
      if (e.key === 'Enter') { const k = e.target.value; if(k) location.search='?key='+encodeURIComponent(k); }
    });
  });
}

async function fetchStats() {
  try {
    const r = await fetch('/stats', { headers: { 'x-admin-key': ADMIN_KEY } });
    if (r.status === 401) return { __error: 401 };
    if (!r.ok) return { __error: r.status };
    return await r.json();
  } catch(e) {
    return { __error: 0 };
  }
}

// Renders one pool's summary cards + CDN table. suffix = '' for plgb, '-t' for
// telethon; statusPath is the CDN's own health-check path ('/status' or '/').
function renderPool(cdns, best, suffix, statusPath) {
  const online = cdns.filter(c => c.last_ok === 1);
  const offline = cdns.filter(c => c.last_ok !== 1);
  const seenIps = new Set();
  const totalLoad = online.reduce((s, c) => {
    const key = c.ip || c.url;
    if (seenIps.has(key)) return s;
    seenIps.add(key);
    return s + (c.load < 99999 ? c.load : 0);
  }, 0);

  document.getElementById('total-cdns' + suffix).textContent = cdns.length;
  document.getElementById('online-cdns' + suffix).textContent = online.length;
  document.getElementById('offline-cdns' + suffix).textContent = offline.length;
  document.getElementById('total-load' + suffix).textContent = totalLoad;

  const bestEl = document.getElementById('best-cdn-val' + suffix);
  if (best) {
    const host = (() => { try { return new URL(best).hostname; } catch(e) { return best; }})();
    bestEl.textContent = host;
    bestEl.title = best;
    bestEl.style.color = '#68d391';
  } else {
    bestEl.textContent = 'None';
    bestEl.title = '';
    bestEl.style.color = '#fc8181';
  }

  const tbody = document.getElementById('cdn-table-body' + suffix);
  if (cdns.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No CDNs registered</td></tr>';
  } else {
    tbody.innerHTML = cdns.map(c => {
      const host = (() => { try { return new URL(c.url).hostname; } catch(e) { return c.url; }})();
      const statusUrl = (c.url.startsWith('http') ? c.url : 'https://' + c.url) + statusPath;
      const lc = loadColor(c.load);
      const bw = loadBarWidth(c.load);
      const loadDisp = c.load >= 99999 ? '∞' : c.load;
      return `<tr>
        <td onclick="window.open('${statusUrl}','_blank')" style="cursor:pointer;color:#63b3ed;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${statusUrl}">${host} ↗</td>
        <td><span class="badge ${c.last_ok === 1 ? 'online' : 'offline'}">${c.last_ok === 1 ? 'Online' : 'Offline'}</span>${c.last_ok !== 1 && c.error_code ? `<br><span style="font-size:.75rem;color:#fc8181">${c.error_code}</span>` : ''}</td>
        <td>${loadDisp}</td>
        <td><div class="load-bar-wrap"><div class="load-bar ${lc}" style="width:${bw}%"></div></div></td>
        <td>${c.fail_count}</td>
        <td>${fmtTime(c.updated_at)}</td>
      </tr>`;
    }).join('');
  }
}

function render(data) {
  if (!data || data.__error !== undefined) {
    const code = data && data.__error;
    const msg = code === 401 ? 'Wrong admin key – check ?key= in URL'
               : code === 0  ? 'Cannot reach server'
               : 'Server error ' + code;
    document.getElementById('last-update').textContent = msg;
    document.getElementById('dot').style.background = '#fc8181';
    return;
  }
  document.getElementById('dot').style.background = '#68d391';
  document.getElementById('last-update').textContent = 'Updated ' + new Date().toLocaleTimeString();

  renderPool(data.cdns || [], data.best_cdn, '', '/status');
  renderPool(data.cdns_telethon || [], data.best_cdn_telethon, '-t', '/');

  // Trusted hosts (plgb referer whitelist only)
  const trusted = data.trusted_hosts || [];
  document.getElementById('trusted-list').innerHTML =
    trusted.map(h => `<span class="trusted-chip">${h}</span>`).join('');
}

async function refresh() {
  const data = await fetchStats();
  try { render(data); } catch(e) { console.error('render error:', e); }
  setTimeout(refresh, REFRESH_MS);
}

refresh();
</script>
</body>
</html>"#;
    Html(html)
}

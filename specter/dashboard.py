"""Self-contained web dashboard served by the Specter server.

A single-page, dependency-free UI (vanilla JS, no build step) with tabs for
Vulnerabilities, Web Context, MCP suite, Relay, and Agents. It talks to the
existing JSON API, so it works wherever ``specter serve`` runs — including
behind the Cloudflare Tunnel for zero-open-port remote access.
"""
from __future__ import annotations

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Specter</title>
<style>
  :root{--bg:#0d0b14;--panel:#171426;--ink:#e8e6f0;--mut:#9a93b8;--mag:#c061f7;--line:#2a2540}
  *{box-sizing:border-box}body{margin:0;font:14px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto;
    background:var(--bg);color:var(--ink)}
  header{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;
    align-items:center;gap:12px}
  header h1{font-size:18px;margin:0;letter-spacing:.5px}
  header .tag{color:var(--mut);font-size:12px}
  nav{display:flex;gap:4px;padding:12px 24px;border-bottom:1px solid var(--line);flex-wrap:wrap}
  nav button{background:transparent;border:1px solid var(--line);color:var(--mut);
    padding:8px 14px;border-radius:8px;cursor:pointer}
  nav button.active{color:var(--ink);border-color:var(--mag);background:#211a36}
  main{padding:24px}section{display:none}section.active{display:block}
  table{width:100%;border-collapse:collapse;margin-top:8px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
  .sev{font-weight:700;padding:2px 8px;border-radius:999px;font-size:12px}
  .critical{background:#3a0d1a;color:#ff6b8a}.high{background:#3a230d;color:#ffae5b}
  .medium{background:#3a360d;color:#ffe45b}.low{background:#0d2a3a;color:#5bd3ff}
  .info{background:#22203a;color:#bcb6e0}
  .cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
  .card h3{margin:.1em 0 .3em}.card p{color:var(--mut);margin:.2em 0}
  .muted{color:var(--mut)}.big{font-size:28px;font-weight:700}
  a{color:var(--mag)}
</style>
</head>
<body>
<header>
  <h1>👻 SPECTER</h1>
  <span class="tag" id="ver">dashboard</span>
</header>
<nav>
  <button data-tab="overview" class="active">Overview</button>
  <button data-tab="vulns">Vulnerabilities</button>
  <button data-tab="webctx">Web Context</button>
  <button data-tab="agents">Agents</button>
  <button data-tab="mcp">MCP Suite</button>
  <button data-tab="relay">Relay</button>
</nav>
<main>
  <section id="overview" class="active">
    <div class="cards" id="ovcards"></div>
  </section>
  <section id="vulns"><table id="vt"><thead><tr>
    <th>Sev</th><th>Title</th><th>Target</th><th>Status</th><th>Conf</th></tr></thead>
    <tbody></tbody></table></section>
  <section id="webctx"><p class="muted">Identities &amp; endpoints discovered during
    proxy/HAR capture appear here when an engagement carries web-context data.</p>
    <div id="wc"></div></section>
  <section id="agents"><div class="cards" id="agcards"></div></section>
  <section id="mcp"><table id="mt"><thead><tr>
    <th>Name</th><th>Domain</th><th>Tools</th><th>Description</th></tr></thead>
    <tbody></tbody></table></section>
  <section id="relay"><p class="muted" id="relaynote"></p></section>
</main>
<script>
const J = (u)=>fetch(u).then(r=>r.json()).catch(()=>null);
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('nav button').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('section').forEach(x=>x.classList.remove('active'));
  b.classList.add('active');document.getElementById(b.dataset.tab).classList.add('active');
});
function sev(s){return `<span class="sev ${s}">${(s||'').toUpperCase()}</span>`}
async function load(){
  const h = await J('/health'); if(h) document.getElementById('ver').textContent='v'+h.version;
  const f = (await J('/findings'))||[];
  const counts={critical:0,high:0,medium:0,low:0,info:0};
  f.forEach(x=>counts[x.severity]=(counts[x.severity]||0)+1);
  document.getElementById('ovcards').innerHTML =
    Object.entries(counts).map(([k,v])=>
      `<div class="card"><p class="muted">${k}</p><div class="big">${sev(k)} ${v}</div></div>`).join('')
    + `<div class="card"><p class="muted">total findings</p><div class="big">${f.length}</div></div>`;
  document.querySelector('#vt tbody').innerHTML = f.map(x=>
    `<tr><td>${sev(x.severity)}</td><td>${x.title}</td><td>${x.target||''}</td>
     <td>${x.status||'open'}</td><td>${(x.confidence||0).toFixed?x.confidence.toFixed(2):x.confidence}</td></tr>`).join('')
    || '<tr><td colspan=5 class="muted">No findings yet. Run an engagement.</td></tr>';
  const ag = (await J('/api/agents'))||[];
  document.getElementById('agcards').innerHTML = ag.map(a=>
    `<div class="card"><h3>${a.title}</h3><p class="muted">${a.methodology}</p>
     <p>${a.description}</p><p class="muted">tools: ${(a.tools||[]).slice(0,5).join(', ')}</p></div>`).join('');
  const mcp = (await J('/api/mcp-suite'))||{servers:[]};
  document.querySelector('#mt tbody').innerHTML = (mcp.servers||[]).map(s=>
    `<tr><td>${s.name}</td><td>${s.domain}</td><td>${s.tools}</td><td>${s.description}</td></tr>`).join('');
  document.getElementById('relaynote').textContent =
    'Relay servers register at runtime. Generate keys with `specter relay keygen` and '
    + 'start a node with `specter relay serve`.';
}
load();
</script>
</body></html>"""

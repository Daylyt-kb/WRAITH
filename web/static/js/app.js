/**
 * WRAITH v2.0 — Main Application JavaScript
 * Socket.IO for real-time updates, HTTP API fallback.
 */

// ── State ──
let allFindings = [];
let missionRunning = false;
let socket = null;
let useWebSocket = true;

// ── Socket.IO Connection ──
function initSocket() {
  if (typeof io === 'undefined') {
    console.log('Socket.IO not available, using HTTP polling');
    useWebSocket = false;
    return;
  }
  socket = io();
  socket.on('connect', () => {
    console.log('WebSocket connected');
    const el = document.getElementById('ws-status');
    if (el) { el.textContent = '● Live'; el.className = 'ws-status ws-connected'; }
  });
  socket.on('disconnect', () => {
    console.log('WebSocket disconnected');
    const el = document.getElementById('ws-status');
    if (el) { el.textContent = '● Offline'; el.className = 'ws-status ws-disconnected'; }
  });
  socket.on('log', (data) => {
    log(data.msg, data.type || 'info');
  });
  socket.on('findings', (data) => {
    if (data.findings) {
      data.findings.forEach(addFinding);
      allFindings = allFindings.concat(data.findings);
      const el = document.getElementById('findings-count');
      if (el) el.textContent = `(${allFindings.length})`;
    }
  });
  socket.on('mission_complete', (data) => {
    missionRunning = false;
    const btn = document.getElementById('launch-btn');
    if (btn) { btn.disabled = false; btn.textContent = '⚡ Deploy Swarm'; }
    log('Mission complete. Report saved.', 'success');
    if (data.report) {
      const rc = document.getElementById('report-content');
      if (rc) rc.textContent = data.report;
    }
  });
  socket.on('mission_error', (data) => {
    missionRunning = false;
    const btn = document.getElementById('launch-btn');
    if (btn) { btn.disabled = false; btn.textContent = '⚡ Deploy Swarm'; }
    log('Mission error: ' + (data.error || 'unknown'), 'error');
  });
}

// ── Terminal Logging ──
function log(msg, type) {
  type = type || 'info';
  const t = document.getElementById('terminal');
  if (!t) return;
  const div = document.createElement('div');
  div.className = 'terminal-line ' + type;
  div.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg;
  t.appendChild(div);
  t.scrollTop = t.scrollHeight;
}

function clearTerminal() {
  const t = document.getElementById('terminal');
  if (t) t.innerHTML = '<div class="terminal-line muted">Terminal cleared.</div>';
}

// ── Tab Navigation ──
function showTab(name) {
  const names = ['terminal', 'findings', 'report', 'commander', 'settings'];
  document.querySelectorAll('.tab').forEach((t, i) => {
    t.classList.toggle('active', names[i] === name);
  });
  document.querySelectorAll('.tab-panel').forEach(p => {
    p.classList.remove('active');
    p.style.display = 'none';
  });
  const panel = document.getElementById('tab-' + name);
  if (panel) {
    panel.style.display = 'flex';
    panel.classList.add('active');
  }
}

// ── Agent Status ──
function setAgentActive(name, active) {
  const el = document.getElementById('agent-' + name);
  if (el) el.classList.toggle('active', active);
}

// ── Mission Control ──
async function launchMission() {
  const target = document.getElementById('target').value.trim();
  const mode = document.getElementById('mode').value;
  const authorized = document.getElementById('authorized').checked;

  if (!target) { log('Error: No target specified.', 'error'); return; }
  if (!authorized) { log('Error: You must confirm authorization before scanning.', 'error'); return; }
  if (missionRunning) { log('Mission already running...', 'warning'); return; }

  missionRunning = true;
  allFindings = [];
  const btn = document.getElementById('launch-btn');
  btn.disabled = true;
  btn.textContent = '⏳ Running...';
  const fl = document.getElementById('findings-list');
  if (fl) fl.innerHTML = '';
  const fc = document.getElementById('findings-count');
  if (fc) fc.textContent = '';

  showTab('terminal');
  log(`Mission start: ${mode.toUpperCase()} on ${target}`, 'cmd');
  log('Validating scope and authorization...', 'muted');

  const agents = {
    recon: ['ghost'], osint: ['specter'], scan: ['scanner'],
    full: ['ghost', 'specter', 'scanner'], 'ai-audit': ['mirror']
  };
  const agentList = agents[mode] || ['ghost'];
  agentList.forEach(a => setAgentActive(a, false));

  // Try WebSocket first
  if (useWebSocket && socket && socket.connected) {
    socket.emit('start_mission', { target, mode, authorized });
    return;
  }

  // Fallback: HTTP API
  try {
    const resp = await fetch('/api/mission', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({target, mode, authorized})
    });
    const data = await resp.json();
    if (data.error) {
      log('Error: ' + data.error, 'error');
      missionRunning = false;
      btn.disabled = false;
      btn.textContent = '⚡ Deploy Swarm';
    } else {
      await streamMission(data.mission_id, agentList);
    }
  } catch(e) {
    log('Connection error: ' + e.message, 'error');
    missionRunning = false;
    btn.disabled = false;
    btn.textContent = '⚡ Deploy Swarm';
  }
  agentList.forEach(a => setAgentActive(a, false));
}

async function streamMission(missionId, agentList) {
  let done = false;
  let lastLine = 0;
  agentList.forEach(a => setAgentActive(a, true));

  while (!done) {
    try {
      const resp = await fetch(`/api/mission/${missionId}/status`);
      const data = await resp.json();
      const lines = data.log || [];
      for (let i = lastLine; i < lines.length; i++) {
        log(lines[i].msg, lines[i].type || 'info');
        lastLine = i + 1;
      }
      if (data.findings && data.findings.length > allFindings.length) {
        data.findings.slice(allFindings.length).forEach(addFinding);
        allFindings = data.findings;
        const fc = document.getElementById('findings-count');
        if (fc) fc.textContent = `(${allFindings.length})`;
      }
      if (data.status === 'complete') {
        done = true;
        log(`Mission complete. ${allFindings.length} findings. Report saved.`, 'success');
        if (data.report) {
          const rc = document.getElementById('report-content');
          if (rc) rc.textContent = data.report;
        }
      } else if (data.status === 'error') {
        done = true;
        log('Mission error: ' + (data.error || 'unknown'), 'error');
      }
      if (!done) await new Promise(r => setTimeout(r, 800));
    } catch(e) { await new Promise(r => setTimeout(r, 1000)); }
  }
  missionRunning = false;
  const btn = document.getElementById('launch-btn');
  if (btn) { btn.disabled = false; btn.textContent = '⚡ Deploy Swarm'; }
  agentList.forEach(a => setAgentActive(a, false));
}

// ── Findings ──
function addFinding(f) {
  const list = document.getElementById('findings-list');
  if (!list) return;
  const sev = f.severity || 'info';
  const div = document.createElement('div');
  div.className = 'finding ' + sev;
  div.innerHTML = `
    <div class="finding-sev">${sev}</div>
    <div class="finding-title">${f.title || ''}</div>
    <div class="finding-tool">Tool: ${f.tool || 'unknown'}</div>
  `;
  list.appendChild(div);
}

// ── Commander ──
function quickSend(msg) {
  const ci = document.getElementById('chat-input');
  if (ci) ci.value = msg;
  showTab('commander');
  sendToCommander();
}

async function sendToCommander() {
  const input = document.getElementById('chat-input');
  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';
  const log_el = document.getElementById('commander-log');
  const you = document.createElement('div');
  you.className = 'terminal-line cmd';
  you.textContent = '> ' + msg;
  log_el.appendChild(you);
  try {
    const resp = await fetch('/api/commander', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message: msg})
    });
    const data = await resp.json();
    const reply = document.createElement('div');
    reply.className = 'terminal-line info';
    reply.style.whiteSpace = 'pre-wrap';
    reply.textContent = 'Commander: ' + (data.response || data.error || 'no response');
    log_el.appendChild(reply);
    log_el.scrollTop = log_el.scrollHeight;
  } catch(e) {
    const err = document.createElement('div');
    err.className = 'terminal-line error';
    err.textContent = 'Error: ' + e.message;
    log_el.appendChild(err);
  }
}

// ── AI Provider Settings ──
async function refreshAIStatus() {
  try {
    const r = await fetch('/api/ai-status');
    const d = await r.json();
    buildProviderCards(d.all_providers, d.provider);
    const statusEl = document.getElementById('ai-status');
    if (statusEl) {
      statusEl.textContent = d.configured ? d.provider_name + ' · ' + (d.model || '').split('-').slice(0,2).join('-') : 'No AI key — add in Settings';
      statusEl.style.color = d.configured ? '#5cb85c' : '#e24b4a';
    }
  } catch(e) {}
}

function buildProviderCards(providers, activeProvider) {
  const grid = document.getElementById('provider-cards');
  if (!providers || !grid) return;
  grid.innerHTML = Object.entries(providers).map(([id, info]) => `
    <div class="provider-card ${id === activeProvider ? 'active' : ''}">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
        <span style="font-weight:700;font-size:13px">${info.name}</span>
        <span class="ws-status ${info.free_tier ? 'free' : 'paid'}">${info.free_tier ? 'FREE' : 'PAID'}</span>
      </div>
      <div style="font-size:11px;color:#666;margin-bottom:8px">${(info.models || []).slice(0,3).join(', ')}</div>
      <div style="display:flex;gap:6px;margin-bottom:8px">
        <input type="password" id="key-${id}" placeholder="${info.key_prefix || 'API key'}..." style="flex:1">
        <button onclick="setKeyFor('${id}')" class="btn btn-primary" style="padding:6px 10px;font-size:11px;width:auto">Set</button>
        <button onclick="testKeyFor('${id}')" class="btn btn-secondary" style="padding:6px 10px;font-size:11px;width:auto">Test</button>
      </div>
      <div id="ps-${id}" style="font-size:11px;color:#777;font-family:monospace">${id === activeProvider ? '✓ Active' : '—'}</div>
      ${info.docs ? `<div style="font-size:10px;color:#555;margin-top:5px">Get key: <a href="${info.docs}" target="_blank" style="color:#5a9adc">${info.docs.replace('https://','')}</a></div>` : ''}
    </div>`).join('');
}

async function setKeyFor(provider) {
  const key = (document.getElementById('key-' + provider) || {}).value || '';
  if (!key) { document.getElementById('ps-' + provider).textContent = '⚠ Paste key first'; return; }
  const r = await fetch('/api/set-key', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key,provider})});
  const d = await r.json();
  document.getElementById('ps-' + provider).textContent = d.ok ? '✓ Set: ' + d.model : '✗ ' + d.error;
  document.getElementById('key-' + provider).value = '';
  refreshAIStatus();
}

async function testKeyFor(provider) {
  const key = (document.getElementById('key-' + provider) || {}).value || '';
  const el = document.getElementById('ps-' + provider);
  el.textContent = 'Testing...';
  const r = await fetch('/api/test-key', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:key||null,provider})});
  const d = await r.json();
  el.textContent = d.ok ? '✓ Working: ' + (d.response || '').slice(0,35) : '✗ ' + d.error;
}

async function setRawKey() {
  const key = document.getElementById('raw-key').value.trim();
  if (!key) return;
  const r = await fetch('/api/set-key', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key})});
  const d = await r.json();
  document.getElementById('raw-status').textContent = d.ok ? '✓ ' + d.provider_name + ' detected — using ' + d.model : '✗ ' + d.error;
  document.getElementById('raw-key').value = '';
  refreshAIStatus();
}

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  initSocket();
  refreshAIStatus();
  setInterval(refreshAIStatus, 20000);
});

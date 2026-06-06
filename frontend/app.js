(() => {
  'use strict';

  window.reconSession = {};

  let ws = null;
  let scanning = false;

  const $ = id => document.getElementById(id);

  const btnScan    = $('btn-scan');
  const inputTarget = $('target-input');
  const selectType = $('target-type');
  const termLog    = $('terminal-log');
  const emptyState = $('empty-state');
  const reportPanel = $('report-panel');
  const termTitle  = $('terminal-title');

  // ── Module state ──────────────────────────────────────────────────────────

  const MODULE_NAMES = ['whois', 'dns', 'crt', 'geo', 'otx', 'rep'];

  function resetModules() {
    MODULE_NAMES.forEach(name => {
      setModuleState(name, 'idle');
      const cnt = $(`cnt-${name}`);
      if (cnt) cnt.textContent = '—';
    });
  }

  function setModuleState(name, state) {
    const el = $(`mod-${name}`);
    if (!el) return;
    el.classList.remove('running', 'done', 'error');
    if (state !== 'idle') el.classList.add(state);
  }

  function bumpModuleCount(name) {
    const cnt = $(`cnt-${name}`);
    if (!cnt) return;
    const cur = parseInt(cnt.textContent, 10);
    cnt.textContent = isNaN(cur) ? 1 : cur + 1;
  }

  // ── Terminal log ──────────────────────────────────────────────────────────

  function createLogLine(tag, module, message) {
    const line = document.createElement('div');
    line.className = `log-line tag-${tag}`;

    const tagEl = document.createElement('span');
    tagEl.className = 'log-tag';
    tagEl.textContent = tag;

    const modEl = document.createElement('span');
    modEl.className = 'log-module';
    modEl.textContent = module;

    const msgEl = document.createElement('span');
    msgEl.className = 'log-msg';
    msgEl.textContent = message;

    line.appendChild(tagEl);
    line.appendChild(modEl);
    line.appendChild(msgEl);
    return line;
  }

  function appendLog(tag, module, message) {
    if (emptyState) emptyState.remove();
    const line = createLogLine(tag, module, message);
    termLog.appendChild(line);
    termLog.scrollTop = termLog.scrollHeight;
  }

  function clearLog() {
    termLog.innerHTML = '';
  }

  // ── Report rendering ──────────────────────────────────────────────────────

  function renderReport(report) {
    const titleEl   = $('report-title');
    const badgeEl   = $('risk-badge');
    const metaEl    = $('report-meta');
    const container = $('findings-container');

    titleEl.textContent = `${report.target} — ${report.target_type}`;

    badgeEl.textContent = report.risk_level;
    badgeEl.className = `risk-badge risk-${report.risk_level}`;

    const ts = new Date(report.timestamp).toLocaleString();
    metaEl.textContent = `Scanned ${ts}`;

    container.innerHTML = '';

    if (!report.findings || report.findings.length === 0) {
      const p = document.createElement('p');
      p.className = 'no-findings';
      p.textContent = '✓ No significant findings';
      container.appendChild(p);
    } else {
      const table = document.createElement('table');
      table.className = 'findings-table';
      table.innerHTML = `
        <thead><tr>
          <th>Severity</th><th>Title</th><th>Detail</th>
        </tr></thead>`;
      const tbody = document.createElement('tbody');

      const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
      const sorted = [...report.findings].sort(
        (a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9)
      );

      sorted.forEach(f => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><span class="sev-badge sev-${f.severity}">${f.severity}</span></td>
          <td>${escHtml(f.title)}</td>
          <td>${escHtml(f.detail)}</td>`;
        tbody.appendChild(tr);
      });

      table.appendChild(tbody);
      container.appendChild(table);
    }

    reportPanel.classList.add('visible');
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── WebSocket ─────────────────────────────────────────────────────────────

  function connect(target, targetType) {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const url   = `${proto}://${location.host}/ws/recon`;

    ws = new WebSocket(url);

    ws.onopen = () => {
      ws.send(JSON.stringify({ target, target_type: targetType }));
    };

    ws.onmessage = ({ data }) => {
      let event;
      try { event = JSON.parse(data); } catch { return; }

      const { tag, module, message, data: evData } = event;

      if (tag === 'RUN') {
        setModuleState(module, 'running');
        appendLog(tag, module, message);
      } else if (tag === 'OK') {
        // Only show non-"complete" OK lines in terminal
        if (!message.endsWith('complete')) {
          appendLog(tag, module, message);
        }
      } else if (tag === 'WARN') {
        appendLog(tag, module, message);
        bumpModuleCount(module);
        setModuleState(module, 'done');
      } else if (tag === 'ERR') {
        appendLog(tag, module, message);
        setModuleState(module, 'error');
      } else if (tag === 'DONE') {
        appendLog(tag, 'engine', 'Pipeline complete — report ready');
        window.reconSession = evData;
        renderReport(evData);
        finishScan();
      }

      // Mark module done on final OK (the "complete" message)
      if (tag === 'OK' && message.endsWith('complete')) {
        setModuleState(module, 'done');
        const cnt = $(`cnt-${module}`);
        if (cnt && cnt.textContent === '—') cnt.textContent = '0';
      }
    };

    ws.onerror = () => {
      appendLog('ERR', 'ws', 'WebSocket error');
      finishScan();
    };

    ws.onclose = () => {
      if (scanning) finishScan();
    };
  }

  function finishScan() {
    scanning = false;
    btnScan.disabled = false;
    btnScan.textContent = 'Run Scan';
    termTitle.textContent = `ghostnet — ${inputTarget.value} done`;
  }

  // ── Scan trigger ──────────────────────────────────────────────────────────

  function startScan() {
    const target = inputTarget.value.trim();
    const targetType = selectType.value;
    if (!target || scanning) return;

    scanning = true;
    btnScan.disabled = true;
    btnScan.textContent = 'Scanning…';

    clearLog();
    reportPanel.classList.remove('visible');
    resetModules();
    window.reconSession = {};

    termTitle.textContent = `ghostnet — scanning ${target}`;
    appendLog('RUN', 'init', `Target: ${target} (${targetType})`);

    if (ws && ws.readyState === WebSocket.OPEN) ws.close();
    connect(target, targetType);
  }

  btnScan.addEventListener('click', startScan);
  inputTarget.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });
})();

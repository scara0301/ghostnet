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
  const btnAnalyst = $('btn-analyst');
  const analystPanel = $('analyst-panel');

  // ── Module state ──────────────────────────────────────────────────────────

  const MODULE_NAMES = ['email', 'whois', 'dns', 'crt', 'geo', 'otx', 'rep'];

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
    btnAnalyst.disabled = false;
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
    btnAnalyst.disabled = true;
    btnScan.textContent = 'Scanning…';

    clearLog();
    reportPanel.classList.remove('visible');
    analystPanel.classList.remove('visible');
    resetModules();
    window.reconSession = {};

    termTitle.textContent = `ghostnet — scanning ${target}`;
    appendLog('RUN', 'init', `Target: ${target} (${targetType})`);

    if (ws && ws.readyState === WebSocket.OPEN) ws.close();
    connect(target, targetType);
  }

  btnScan.addEventListener('click', startScan);
  inputTarget.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });

  // ════════════════════════════════════════════════════════════════════════
  //  ANALYST MODE  —  /ws/analyst  →  full intelligence product
  // ════════════════════════════════════════════════════════════════════════

  const pct = v => Math.round((Number(v) || 0) * 100) + '%';
  const num = (v, d = 2) => (Number(v) || 0).toFixed(d);

  function startAnalysis() {
    const target = inputTarget.value.trim();
    const targetType = selectType.value;
    if (!target || scanning) return;

    scanning = true;
    btnScan.disabled = true;
    btnAnalyst.disabled = true;
    btnAnalyst.textContent = 'Analyzing…';

    clearLog();
    reportPanel.classList.remove('visible');
    analystPanel.classList.remove('visible');
    resetModules();
    window.analystReport = {};

    termTitle.textContent = `ghostnet/analyst — investigating ${target}`;
    appendLog('RUN', 'analyst', `Autonomous investigation: ${target} (${targetType})`);

    if (ws && ws.readyState === WebSocket.OPEN) ws.close();
    connectAnalyst(target, targetType);
  }

  function finishAnalysis() {
    scanning = false;
    btnScan.disabled = false;
    btnAnalyst.disabled = false;
    btnAnalyst.innerHTML = '<i class="ti ti-brain"></i> Run Analyst';
    termTitle.textContent = `ghostnet/analyst — ${inputTarget.value} done`;
  }

  function connectAnalyst(target, targetType) {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws/analyst`);

    ws.onopen = () => ws.send(JSON.stringify({ target, target_type: targetType }));

    ws.onmessage = ({ data }) => {
      let event;
      try { event = JSON.parse(data); } catch { return; }
      const { tag, module, message, data: evData } = event;

      if (module === 'analyst' && tag !== 'DONE') {
        // A planning decision (run / stop / escalate).
        appendLog(tag, 'analyst', message);
        return;
      }

      if (tag === 'RUN') {
        setModuleState(module, 'running');
        appendLog(tag, module, message);
      } else if (tag === 'OK') {
        setModuleState(module, 'done');
        bumpModuleCount(module);
        appendLog(tag, module, message);
      } else if (tag === 'ERR') {
        setModuleState(module, 'error');
        appendLog(tag, module, message);
      } else if (tag === 'DONE') {
        appendLog('DONE', 'analyst', 'Investigation complete — intelligence ready');
        if (evData && evData.target) {
          window.analystReport = evData;
          renderAnalystReport(evData);
        }
        finishAnalysis();
      }
    };

    ws.onerror = () => { appendLog('ERR', 'ws', 'WebSocket error'); finishAnalysis(); };
    ws.onclose = () => { if (scanning) finishAnalysis(); };
  }

  // ── Report renderer ───────────────────────────────────────────────────────

  function renderAnalystReport(r) {
    renderSummary(r);
    renderHypotheses(r.hypotheses || []);
    renderPosture(r.posture);
    renderAttack(r.attack_paths || []);
    renderForecasts(r.forecasts || []);
    renderClusters(r.clusters || []);
    renderActors(r.actor_matches || [], r.predicted_edges || []);
    renderDecisions(r.decisions || []);
    analystPanel.classList.add('visible');
    renderTwinGraph(r.graph || { nodes: [], edges: [] });   // after panel is visible (needs width)
  }

  function renderSummary(r) {
    const theta = r.posture ? r.posture.theta_mean : 0;
    const confirmed = (r.hypotheses || []).filter(h => h.status === 'confirmed').length;
    const chips = ns => ns.map(n => `<span class="run-chip">${escHtml(n)}</span>`).join('');
    const skip = (r.modules_skipped || []).map(n =>
      `<span class="run-chip skip">${escHtml(n)}</span>`).join('');
    $('intel-summary').innerHTML = `
      <div class="sum-head">
        <h2>${escHtml(r.target)} <span class="sum-type">${escHtml(r.target_type)}</span></h2>
        <span class="sum-time">${new Date(r.timestamp).toLocaleString()}</span>
      </div>
      <div class="sum-theta">
        <span class="theta-label">Security maturity θ</span>
        <div class="theta-bar"><div class="theta-fill" style="width:${pct(theta)}"></div></div>
        <span class="theta-val">${num(theta)}</span>
      </div>
      <div class="sum-stats">
        <span><b>${confirmed}</b>/${(r.hypotheses || []).length} hypotheses confirmed</span>
        <span><b>${(r.attack_paths || []).length}</b> attack paths</span>
        <span><b>${(r.forecasts || []).length}</b> forecasts</span>
        <span><b>${(r.predicted_edges || []).length}</b> inferred links</span>
      </div>
      <div class="sum-modules">
        <span class="sum-lbl">collected</span> ${chips(r.modules_run || []) || '—'}
        ${skip ? `<span class="sum-lbl">declined</span> ${skip}` : ''}
      </div>`;
  }

  function probBar(posterior, prior) {
    const tick = prior != null
      ? `<span class="prior-tick" style="left:${pct(prior)}" title="prior ${num(prior)}"></span>` : '';
    return `<div class="prob-bar"><div class="prob-fill" style="width:${pct(posterior)}"></div>${tick}</div>`;
  }

  function renderHypotheses(hyps) {
    const order = { confirmed: 0, needs_evidence: 1, open: 2, rejected: 3 };
    const sorted = [...hyps].sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9));
    $('intel-hypotheses').innerHTML = sorted.map(h => `
      <div class="hyp hyp-${h.status}">
        <div class="hyp-top">
          <span class="hyp-id">${escHtml(h.id)}</span>
          <span class="hyp-stmt">${escHtml(h.statement)}</span>
          <span class="chip chip-${h.status}">${h.status.replace('_', ' ')}</span>
        </div>
        ${probBar(h.posterior, h.prior)}
        <div class="hyp-meta">prior ${num(h.prior)} → posterior <b>${num(h.posterior)}</b></div>
        ${(h.evidence || []).length ? `<div class="hyp-ev">${h.evidence.map(escHtml).join(' · ')}</div>` : ''}
      </div>`).join('') || '<p class="empty">No hypotheses seeded.</p>';
  }

  function renderPosture(posture) {
    if (!posture) { $('intel-posture').innerHTML = '<p class="empty">No posture estimate.</p>'; return; }
    const gaps = posture.controls.filter(c => c.observed === false && c.severity !== 'INFO');
    const stateIcon = o => o === true ? '<span class="cs present">✓</span>'
      : o === false ? '<span class="cs absent">✗</span>' : '<span class="cs unknown">?</span>';
    const gapHtml = gaps.length ? `
      <div class="gap-head">Bayesian recon gaps (${gaps.length})</div>
      ${gaps.map(c => `
        <div class="gap" title="${escHtml(c.rationale)}">
          <span class="sev-badge sev-${c.severity}">${c.severity}</span>
          <span class="gap-name">${escHtml(c.control)}</span>
          <span class="gap-exp">expected ${pct(c.expected_presence)}</span>
        </div>`).join('')}` : '<div class="gap-head ok">No anomalous gaps for this maturity ✓</div>';
    const ladder = posture.controls.map(c => `
      <div class="ctrl">
        ${stateIcon(c.observed)}
        <span class="ctrl-name">${escHtml(c.control)}</span>
        <div class="exp-bar"><div class="exp-fill" style="width:${pct(c.expected_presence)}"></div></div>
      </div>`).join('');
    $('intel-posture').innerHTML = gapHtml + `<div class="ctrl-ladder">${ladder}</div>`;
  }

  function renderAttack(paths) {
    if (!paths.length) { $('intel-attack').innerHTML = '<p class="empty">No attack paths to crown-jewel assets.</p>'; return; }
    $('intel-attack').innerHTML = paths.map(p => `
      <div class="apath">
        <div class="apath-head">
          <span class="chip impact-${p.impact}">${p.impact}</span>
          <span class="apath-obj">internet → ${escHtml(p.objective)}</span>
          <span class="apath-conf">${pct(p.path_confidence)}</span>
        </div>
        <div class="apath-steps">${p.steps.map(s => `
          <div class="astep">
            <span class="astep-edge">${escHtml(s.src.replace('internet:0.0.0.0/0', 'internet'))} → ${escHtml(s.dst)}</span>
            <span class="astep-tech">${escHtml(s.technique)}</span>
            <span class="astep-conf">${pct(s.confidence)}</span>
          </div>`).join('')}</div>
      </div>`).join('');
  }

  const FC_LABEL = {
    subdomain_emergence: 'New subdomains', domain_expiry: 'Domain lapse risk',
    cert_anomaly: 'Certificate anomaly', infra_migration: 'Infrastructure migration',
    phishing_campaign: 'Phishing campaign',
  };

  function renderForecasts(fcs) {
    if (!fcs.length) { $('intel-forecasts').innerHTML = '<p class="empty">No temporal history yet — run again later to forecast.</p>'; return; }
    $('intel-forecasts').innerHTML = fcs.map(f => `
      <div class="fc">
        <div class="fc-top">
          <span class="fc-kind">${escHtml(FC_LABEL[f.kind] || f.kind)} <span class="fc-h">${f.horizon_days}d</span></span>
          <span class="fc-prob">${pct(f.probability)}</span>
        </div>
        <div class="prob-bar"><div class="prob-fill fc-fill" style="width:${pct(f.probability)}"></div></div>
        <div class="fc-detail">${escHtml(f.detail)}${f.expected_count ? ` · ~${num(f.expected_count, 1)} expected` : ''}</div>
      </div>`).join('');
  }

  function renderClusters(clusters) {
    if (!clusters.length) { $('intel-clusters').innerHTML = '<p class="empty">No multi-asset clusters inferred.</p>'; return; }
    $('intel-clusters').innerHTML = clusters.map(c => `
      <div class="cluster">
        <div class="cluster-top">
          <span class="chip clabel-${c.label}">${c.label}</span>
          <span class="cluster-meta">${c.members.length} assets · ${pct(c.confidence)} conf</span>
        </div>
        <div class="cmembers">${c.members.map(escHtml).join(', ')}</div>
        ${(c.evidence || []).length ? `<div class="cev">${c.evidence.map(escHtml).join(' · ')}</div>` : ''}
      </div>`).join('');
  }

  function renderActors(actors, predicted) {
    const inferred = predicted.length
      ? `<div class="pred-note"><i class="ti ti-line-dashed"></i> ${predicted.length} inferred relationship(s) shown dashed in the twin</div>` : '';
    if (!actors.length) {
      $('intel-actors').innerHTML = '<p class="empty">No behavioural actor match above threshold.</p>' + inferred;
      return;
    }
    $('intel-actors').innerHTML = actors.map(a => `
      <div class="actor">
        <div class="actor-top"><span class="actor-name">${escHtml(a.actor)}</span><span class="actor-score">${num(a.score)}</span></div>
        <div class="prob-bar"><div class="prob-fill actor-fill" style="width:${pct(a.score)}"></div></div>
        ${(a.matched_features || []).length ? `<div class="actor-feats">${a.matched_features.map(escHtml).join(' · ')}</div>` : ''}
      </div>`).join('') + inferred;
  }

  function renderDecisions(decisions) {
    $('intel-decisions').innerHTML = decisions.map(d => {
      const label = d.action === 'run_module' ? `run ${escHtml(d.module)}`
        : d.action === 'request_collection' ? 'request collection'
        : d.action;
      return `
      <div class="dec dec-${d.action}">
        <span class="dec-step">${d.step}</span>
        <span class="dec-action">${label}</span>
        <span class="dec-voi">VoI ${num(d.expected_value)}</span>
        <span class="dec-reason">${escHtml(d.reason)}</span>
      </div>`;
    }).join('') || '<p class="empty">No decisions recorded.</p>';
  }

  // ── Digital Twin force-directed graph (canvas, no deps) ────────────────────

  const NODE_COLOR = {
    domain: '#58a6ff', subdomain: '#79c0ff', ip: '#3fb950', asn: '#6e7681',
    cert: '#d29922', nameserver: '#a371f7', mx: '#bc8cff', org: '#ec8cff',
    netblock: '#3fb950', internet: '#f85149', email: '#79c0ff', tech: '#56d4dd',
    breach: '#ff6b6b', cloud_asset: '#56d4dd',
  };
  const NODE_R = { domain: 7, internet: 8, ip: 5, asn: 6, org: 6 };
  let twinRaf = null;

  function renderTwinGraph(graph) {
    if (twinRaf) { cancelAnimationFrame(twinRaf); twinRaf = null; }
    const canvas = $('twin-canvas');
    const ctx = canvas.getContext('2d');
    const W = canvas.width = canvas.parentElement.clientWidth || 600;
    const H = canvas.height = 340;

    const raw = (graph.nodes || []).slice(0, 160);
    const idset = new Set(raw.map(n => n.id));
    const nodes = raw.map(n => ({
      id: n.id, type: n.type, label: n.label || n.id,
      x: W / 2 + (Math.random() - 0.5) * W * 0.55,
      y: H / 2 + (Math.random() - 0.5) * H * 0.55, vx: 0, vy: 0, fixed: false,
    }));
    const byId = {}; nodes.forEach(n => byId[n.id] = n);
    const edges = (graph.edges || [])
      .filter(e => byId[e.src] && byId[e.dst])
      .map(e => ({ a: byId[e.src], b: byId[e.dst], predicted: e.type === 'predicted', conf: e.confidence }));

    // legend
    const present = [...new Set(nodes.map(n => n.type))];
    $('graph-legend').innerHTML = present.map(t =>
      `<span class="lg"><i style="background:${NODE_COLOR[t] || '#888'}"></i>${t}</span>`).join('');

    if (!nodes.length) {
      ctx.fillStyle = '#6e7681'; ctx.font = '13px monospace';
      ctx.fillText('No graph data', 16, 28); return;
    }

    const labelSubs = nodes.length <= 45;
    let tick = 0;
    const maxTicks = nodes.length > 90 ? 220 : 380;

    function step() {
      // repulsion (O(n^2), capped node count keeps this cheap)
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          let dx = a.x - b.x, dy = a.y - b.y;
          let d2 = dx * dx + dy * dy || 0.01;
          const f = 900 / d2;
          const d = Math.sqrt(d2);
          const ux = dx / d, uy = dy / d;
          a.vx += ux * f; a.vy += uy * f; b.vx -= ux * f; b.vy -= uy * f;
        }
      }
      // springs
      edges.forEach(e => {
        let dx = e.b.x - e.a.x, dy = e.b.y - e.a.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const f = (d - 64) * 0.015;
        const ux = dx / d, uy = dy / d;
        e.a.vx += ux * f; e.a.vy += uy * f; e.b.vx -= ux * f; e.b.vy -= uy * f;
      });
      // gravity + integrate
      nodes.forEach(n => {
        if (n.fixed) { n.vx = n.vy = 0; return; }
        n.vx += (W / 2 - n.x) * 0.004; n.vy += (H / 2 - n.y) * 0.004;
        n.vx *= 0.82; n.vy *= 0.82;
        n.x += Math.max(-12, Math.min(12, n.vx));
        n.y += Math.max(-12, Math.min(12, n.vy));
        n.x = Math.max(14, Math.min(W - 14, n.x));
        n.y = Math.max(14, Math.min(H - 14, n.y));
      });
      draw();
      if (++tick < maxTicks) twinRaf = requestAnimationFrame(step);
    }

    function draw() {
      ctx.clearRect(0, 0, W, H);
      edges.forEach(e => {
        ctx.beginPath();
        ctx.moveTo(e.a.x, e.a.y); ctx.lineTo(e.b.x, e.b.y);
        if (e.predicted) {
          ctx.strokeStyle = 'rgba(88,166,255,0.30)'; ctx.setLineDash([4, 4]); ctx.lineWidth = 1;
        } else {
          ctx.strokeStyle = 'rgba(110,118,129,0.45)'; ctx.setLineDash([]); ctx.lineWidth = 1;
        }
        ctx.stroke();
      });
      ctx.setLineDash([]);
      nodes.forEach(n => {
        const r = NODE_R[n.type] || 4;
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = NODE_COLOR[n.type] || '#8b949e'; ctx.fill();
        if (n.type !== 'subdomain' || labelSubs) {
          ctx.fillStyle = '#8b949e'; ctx.font = '9px "Share Tech Mono", monospace';
          const lbl = n.label.length > 22 ? n.label.slice(0, 21) + '…' : n.label;
          ctx.fillText(lbl, n.x + r + 2, n.y + 3);
        }
      });
    }

    // drag to reposition (pins node)
    let drag = null;
    canvas.onmousedown = ev => {
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
      drag = nodes.find(n => (n.x - mx) ** 2 + (n.y - my) ** 2 < 100) || null;
      if (drag) drag.fixed = true;
    };
    canvas.onmousemove = ev => {
      if (!drag) return;
      const rect = canvas.getBoundingClientRect();
      drag.x = ev.clientX - rect.left; drag.y = ev.clientY - rect.top;
      if (tick >= maxTicks) draw();
    };
    canvas.onmouseup = canvas.onmouseleave = () => { drag = null; };

    step();
  }

  btnAnalyst.addEventListener('click', startAnalysis);
})();

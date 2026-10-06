// SmartOps SOC console: pick an alert, build its context contract, run the whole
// pipeline with one /api/run call, and render it as a five-stage ledger with the
// case (verdict, scores, tasks, run totals) pinned in the right rail.

const $ = id => document.getElementById(id);
const FIELDS = ['rule', 'src', 'dest', 'user', 'hash', 'domain', 'mitre', 'sig', 'spl'];
const STAGES = ['context', 'plan', 'broker', 'findings', 'synthesis'];

let lastImportedRaw = {};
let lastImportedTime = null;
let run = null;   // {es, started, lastEvent, timer, contract, id}
let state = {};   // per run: stage times, tasks, totals, plan -- what the rail shows

async function getJSON(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(url + ' answered HTTP ' + res.status);
  return res.json();
}
const postJSON = (url, body) =>
  getJSON(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

function toast(msg, bad) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast' + (bad ? ' bad' : '');
  t.hidden = false;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => { t.hidden = true; }, 5000);
}

function setConn(text, cls) {
  const c = $('conn');
  c.textContent = text;
  c.className = 'conn' + (cls ? ' ' + cls : '');
}

// "Threat - sama- ESCU - Malicious PowerShell Process - Encoded Command - Rule"
//   -> "Malicious PowerShell Process - Encoded Command"
function shortRule(name) {
  let s = String(name || '');
  while (/^(Threat|sama|ESCU|Custom|Endpoint|Network|Identity|Access)\s*-\s*/i.test(s)) s = s.replace(/^[^-]*-\s*/, '');
  return s.replace(/(\s*-\s*Rule)+\s*$/i, '') || String(name || '');
}

// ── Incident queue ─────────────────────────────────────────────────────────

async function loadQueue() {
  const list = $('queueList');
  list.setAttribute('aria-busy', 'true');
  list.innerHTML = '<li class="skel"></li><li class="skel"></li><li class="skel"></li>';
  try {
    const data = await getJSON('/api/incident-queue');
    if (data.status === 'error') throw new Error(data.message);
    const events = data.events || [];
    list.innerHTML = events.length ? events.map(ev => {
      const t = String(ev.time || '');
      return '<li><button type="button" data-index="' + Number(ev.index) + '" title="' + _esc(ev.rule_name + '\n' + t) + '">' +
        '<span class="q-rule">' + _esc(shortRule(ev.rule_name) || 'Unnamed rule') + '</span>' +
        '<span class="q-time">' + _esc(t.slice(11, 19) || t) + '</span>' +
        '<span class="q-who">' + (ev.urgency ? '<span class="q-urg">' + _esc(ev.urgency) + '</span> ' : '') +
          _esc([ev.dest, ev.user, ev.src].filter(Boolean).join(', ')) + '</span>' +
      '</button></li>';
    }).join('')
      : '<li class="q-state">No notable events in the last 30 days. You can still fill the alert fields by hand.</li>';
  } catch (e) {
    list.innerHTML = '<li class="q-state bad">Could not reach Splunk: ' + _esc(e.message) +
      '<br>Check the Splunk MCP connection, then Refresh.</li>';
  } finally {
    list.setAttribute('aria-busy', 'false');
  }
}

// ── Alert strip ────────────────────────────────────────────────────────────

function showForm(open) {
  $('alertForm').hidden = !open;
  $('alertEdit').setAttribute('aria-expanded', String(open));
  $('alertEdit').textContent = open ? 'Hide fields' : 'Edit fields';
}

function _sha256(h) { const m = /SHA256=([0-9A-Fa-f]{64})/.exec(h || ''); return m ? m[1] : (h || ''); }

function showFacts(data) {
  const r = data.raw_event_data || {};
  const one = v => Array.isArray(v) ? v[0] : v;
  const facts = [
    ['Host', data.dest], ['User', data.user], ['Source IP', data.src],
    ['Event time (UTC)', data.event_time], ['Notable created', one(r._time)], ['Urgency', data.urgency],
    ['Parent process', one(r.parent_process_path) || one(r.parent_process), 'm wide'],
    ['Integrity', one(r.process_integrity_level)], ['MITRE', one(r['annotations.mitre_attack'])],
    ['Command line', one(r.process) || data.sig, 'm wide'],
    ['SHA256', _sha256(one(r.process_hash) || data.file_hash), 'm wide'],
  ].filter(f => f[1]);
  $('alertFacts').innerHTML = facts.map(([k, v, c]) =>
    '<div class="' + (c && c.includes('wide') ? 'wide' : '') + '"><dt>' + _esc(k) + '</dt><dd' + (c && c.includes('m') ? ' class="m"' : '') + '>' + _esc(v) + '</dd></div>').join('');
  $('alertFacts').hidden = !facts.length;
}

// ponytail: the queue and the import both take "sort -_time | head", so a notable that
// lands between the two calls shifts the index by one. Import by rule_id/_time if that bites.
async function importAlert(index, btn) {
  if (run) { toast('A run is in progress. Wait for it to finish.', true); return; }
  document.querySelectorAll('#queueList button').forEach(b => b.removeAttribute('aria-current'));
  btn.setAttribute('aria-current', 'true');
  $('alertNote').textContent = 'Importing the alert from Splunk ES...';
  try {
    const data = await getJSON('/api/import-from-splunk?index=' + index);
    if (data.status !== 'ok') throw new Error(data.message || 'No alert returned');
    const map = { rule: data.rule_name, src: data.src, dest: data.dest, user: data.user, hash: data.file_hash,
                  domain: data.domain, mitre: data.mitre, sig: data.sig, spl: data.deployed_spl };
    FIELDS.forEach(k => { $('f_' + k).value = map[k] || ''; });
    lastImportedRaw = data.raw_event_data || {};
    lastImportedTime = data.event_time || null;
    $('alertTitle').textContent = shortRule(data.rule_name);
    $('alertTitle').title = data.rule_name || '';
    $('alertNote').textContent = data.deployed_spl ? 'Imported, with the deployed SPL. Investigate when ready.'
      : 'Imported, but no deployed SPL was found for this rule. Paste it under Edit fields for the SPL comparison.';
    showFacts(data);
    $('formError').textContent = '';
  } catch (e) {
    $('alertNote').textContent = 'Import failed: ' + e.message;
    toast('Import failed: ' + e.message, true);
  }
}

// ── Context contract (data logic unchanged from the previous page) ─────────

async function buildContract(f, raw) {
  const { rule_name, src_ip, dest, user, hash, domain, signature, deployed_spl } = f;

  // Auto-extract observables (non-empty cti fields only)
  const url = raw.url || raw.uri || "";
  const email = raw.email || raw.recipient || raw.sender || "";
  const file_name = raw.file_name || raw.process_name || raw.app || "";

  let splunk_mitre = [];
  if (raw['annotations.mitre_attack']) splunk_mitre = raw['annotations.mitre_attack'].split(';');
  let splunk_story = [];
  if (raw['annotations.analytic_story']) splunk_story = raw['annotations.analytic_story'].split(';');

  const observables = [src_ip, hash, domain, url, email, file_name, ...splunk_mitre, ...splunk_story].filter(v => v && v.length > 0);

  const [escuData, ctiData] = await Promise.all([
    postJSON('/api/escu', { rule_name }),
    postJSON('/api/opencti', { observables }),
  ]);

  const raw_event = Object.keys(raw).length > 0 ? { ...raw } : {
    orig_time: Math.floor(Date.now() / 1000).toString(),
    rule_title: rule_name || "Unknown Alert",
    severity_level: "High",
    src: src_ip || "0.0.0.0",
    dest_host: dest || "Unknown",
    user_name: user || "N/A",
    proc_name: "unknown.exe",
    proc_cmd: signature || "N/A",
    file_hash: hash || "N/A",
    domain_query: domain || "N/A",
    index: "win_sysmon",
    sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    _raw_spl: deployed_spl || undefined
  };

  const normalized_seed = {
    event_id: "evt-" + Math.floor(Math.random() * 1000000),
    // The alert's own time, in UTC. It was the browser's "now", which sent
    // run cecd266a searching 3 hours after a +03:00 alert; then the notable's _time,
    // which sent run 600721d3 74 minutes late. The import resolves it from firstTime.
    event_time: (() => { const d = new Date(lastImportedTime || [].concat(raw._time)[0] || NaN); return isNaN(d) ? null : d.toISOString(); })(),
    ingest_time: new Date().toISOString(),
    detection: { detection_id: null, name: rule_name || null, severity: "high", security_domain: null, category: null, type: null, source: null },
    source_context: { siem: "Splunk ES", index: "win_sysmon", sourcetype: "XmlWinEventLog", source: null, host: null },
    entities: {
      host: null, hostname: dest || null, device_id: null, asset_id: null,
      user: user || null, user_id: null, account_name: null, account_domain: null,
      src_ip: src_ip || null, src_host: null, src_port: null,
      dest_ip: null, dest_host: null, dest_port: null
    },
    authentication: { action: null, status: null, authentication_method: null, logon_type: null, failure_reason: null, session_id: null, source_user: null, target_user: null },
    process: {
      process_name: raw.process_name || signature || null, process_path: raw.process_path || null, process_id: raw.process_id || null,
      process_guid: raw.process_guid || null, command_line: raw.process || null,
      parent_process_name: raw.parent_process_name || null, parent_process_path: raw.parent_process_path || null,
      parent_process_id: raw.parent_process_id || null, parent_command_line: null,
      child_process_name: null, child_process_id: null
    },
    file: { file_name: null, file_path: null, file_extension: null, file_size: null, md5: null, sha1: null, sha256: hash || null, file_action: null, file_owner: null, file_signature: null },
    registry: { registry_path: null, registry_key: null, registry_value_name: null, registry_value_data: null, registry_action: null },
    network: { src_ip: null, src_port: null, dest_ip: null, dest_port: null, protocol: null, transport_protocol: null, application_protocol: null, direction: null, action: null, bytes_in: null, bytes_out: null, bytes_total: null, packets_in: null, packets_out: null, connection_count: null },
    dns: { query: null, query_type: null, query_length: null, response: null, response_code: null, record_type: null, resolved_ip: null },
    http: { url: null, uri: null, domain: domain || null, hostname: null, http_method: null, status_code: null, user_agent: null, referrer: null, request_size: null, response_size: null, content_type: null },
    email: { sender: null, recipient: null, cc: [], subject: null, message_id: null, attachment_names: [], attachment_hashes: [], urls: [], domains: [] },
    opencti_observables: {
      ip_addresses: src_ip ? [src_ip] : [],
      domains: domain ? [domain] : [],
      urls: url ? [url] : [],
      file_hashes: hash ? [hash] : [],
      email_addresses: email ? [email] : [],
      file_names: file_name ? [file_name] : [],
      mitre_techniques: splunk_mitre,
      analytic_stories: splunk_story
    },
    endpoint: { device_name: null, device_id: null, os: null, os_version: null, agent_id: null, agent_version: null, action: null, status: null },
    cloud: { cloud_provider: null, account_id: null, subscription_id: null, tenant_id: null, region: null, resource_id: null, resource_type: null, resource_name: null, service: null, operation: null },
    identity: { user: null, user_id: null, user_type: null, role: null, privilege: null, source_identity: null, target_identity: null },
    geo: { src_country: null, src_city: null, dest_country: null, dest_city: null, latitude: null, longitude: null },
    event: { event_code: null, event_type: null, event_category: null, event_action: null, event_status: null, message: null },
    tags: [],
    additional_fields: {},
    finding: raw_event
  };

  // Recursively remove nulls, empty arrays, and empty objects
  (function cleanObject(obj) {
    for (const key in obj) {
      if (obj[key] === null) delete obj[key];
      else if (Array.isArray(obj[key])) { if (obj[key].length === 0) delete obj[key]; }
      else if (typeof obj[key] === 'object') {
        cleanObject(obj[key]);
        if (Object.keys(obj[key]).length === 0) delete obj[key];
      }
    }
  })(normalized_seed);

  let mitre_techniques = [], analytic_story = [], data_sources = ["Simulated Data Source"], known_false_positives = [];
  let reference_spl = "No SPL returned from ESCU.";
  let description = "Detection logic and context mapped from ESCU bm25 corpus.";
  let full_metadata = {};
  if (escuData.matches && escuData.matches.length > 0) {
    const match = escuData.matches[0];
    full_metadata = match;
    if (match.data) {
      mitre_techniques = match.data.mitre_attack_id || match.data.mitre || [];
      analytic_story = match.data.analytic_story || [];
      reference_spl = match.data.spl || match.data.search || "SPL missing in ESCU definition";
      data_sources = match.data.data_source || [];
      known_false_positives = match.data.known_false_positives || [];
      description = match.data.description || description;
    }
  }
  const arr = v => Array.isArray(v) ? v : [v];

  const contract = {
    normalized_seed,
    rule_intent: {
      intent: "To be determined by LLM (Rule Intent Interpreter) via semantic comparison of both SPLs.",
      semantic_alignment: "ALIGNED | NOT_ALIGNED",
      deployed_spl: deployed_spl || "Not provided — paste the SPL from Splunk ES here.",
      reference_spl
    },
    escu_context: {
      description,
      mitre_techniques: arr(mitre_techniques),
      data_sources: arr(data_sources),
      known_false_positives: arr(known_false_positives),
      analytic_story: arr(analytic_story),
      reference_spl,
      full_metadata
    },
    opencti_threat_intelligence: {
      indicators: Object.keys(ctiData.results || {}).map(key => ({ observable: key, type: ctiData.results[key]._queried_as })),
      malware: [], threat_actors: [], campaigns: [], relationships: [],
      _raw_intel_dump: ctiData.results
    }
  };
  return { contract, escuData, ctiData };
}

// ── Run ────────────────────────────────────────────────────────────────────

const _li = name => $('stream').querySelector('.stg[data-stage="' + name + '"]');
const _secs = ms => { const s = Math.round(ms / 1000); return s < 60 ? s + 's' : Math.floor(s / 60) + 'm ' + String(s % 60).padStart(2, '0') + 's'; };

// One stage active at a time; earlier ones done. A finished stage folds to its line once;
// after that it stays however the reader left it.
function setStage(name, st) {
  const at = STAGES.indexOf(name);
  const now = Date.now();
  STAGES.forEach((s, i) => {
    const li = _li(s), t = state.t[s] = state.t[s] || {};
    const was = li.className.replace('stg', '').trim();
    const cls = i < at ? 'done' : i === at ? (st || 'active') : (was === 'done' || was === 'active' ? 'done' : '');
    if (i === at && !t.start) t.start = now;
    if (cls !== 'active' && t.start && !t.end) t.end = now;
    if (cls === 'active') t.end = null;
    li.className = 'stg' + (cls ? ' ' + cls : '');
    const d = li.querySelector('details');
    if (cls === 'active' || cls === 'failed') d.open = true;
    else if (was === 'active') d.open = false;
    li.querySelector('.stg-time').textContent = t.start ? _secs((t.end || now) - t.start) : '';
  });
}
function setSum(name, text) { _li(name).querySelector('.stg-sum').textContent = text; }

function resetLedger() {
  STAGES.forEach(s => {
    const li = _li(s);
    li.className = 'stg';
    li.querySelector('details').open = false;
    li.querySelector('.stg-body').innerHTML = '';
    li.querySelector('.stg-sum').textContent = '';
    li.querySelector('.stg-time').textContent = '';
  });
}

function endRun(text, cls) {
  if (!run) return;
  run.es && run.es.close();
  clearInterval(run.timer);
  state.ended = Date.now();
  state.status = cls === 'bad' ? text.replace(/^Run \S+ /, '').replace(/^./, c => c.toUpperCase()) : (state.status === 'Running' ? 'Complete' : state.status);
  run = null;
  renderMeta();
  setConn(text, cls);
  $('runBtn').disabled = false;
  $('runBtn').textContent = 'Investigate';
  document.querySelectorAll('#queueList button').forEach(b => { b.disabled = false; b.classList.remove('running'); });
}

function tick() {
  if (!run) return;
  const cur = STAGES.find(s => _li(s).classList.contains('active'));
  if (cur && state.t[cur] && state.t[cur].start) _li(cur).querySelector('.stg-time').textContent = _secs(Date.now() - state.t[cur].start);
  renderMeta();
}

async function investigate(ev) {
  ev.preventDefault();
  if (run) return;
  const v = k => $('f_' + k).value.trim();
  const f = { rule_name: v('rule'), src_ip: v('src'), dest: v('dest'), user: v('user'), hash: v('hash'),
              domain: v('domain'), mitre: v('mitre'), signature: v('sig'), deployed_spl: v('spl') };
  if (!f.rule_name) {
    $('formError').textContent = 'Pick an alert from the queue, or open Edit fields and enter the detection rule name.';
    showForm(true);
    $('f_rule').focus();
    return;
  }
  $('formError').textContent = '';
  if (!$('alertFacts').innerHTML) { $('alertTitle').textContent = shortRule(f.rule_name); }

  run = { started: Date.now(), lastEvent: Date.now(), timer: setInterval(tick, 1000) };
  state = { started: Date.now(), t: {}, tasks: [], plan: null, spend: 0, tokIn: 0, tokOut: 0, loops: 0, status: 'Building context' };
  showForm(false);
  $('runBtn').disabled = true;
  $('runBtn').textContent = 'Running...';
  document.querySelectorAll('#queueList button').forEach(b => { b.disabled = true; if (b.getAttribute('aria-current') === 'true') b.classList.add('running'); });
  resetLedger();
  railReset();
  setStage('context');
  setSum('context', 'Matching ESCU and asking OpenCTI');
  setConn('Building context', 'live');
  tick();

  try {
    const { contract, escuData, ctiData } = await buildContract(f, lastImportedRaw);
    run.contract = contract;
    _add(_contextCard(contract, escuData, ctiData), 'context');

    const { run_id } = await postJSON('/api/run', { context_contract: contract });
    if (!run_id) throw new Error('The server did not return a run id.');
    run.id = state.id = run_id;
    setStage('plan');
    setSum('plan', 'Analyst is planning. A cold model can take a few minutes.');
    setConn('Run ' + run_id + ' connecting', 'warn');
    state.status = 'Running';

    const es = new EventSource('/api/run/stream/' + encodeURIComponent(run_id));
    run.es = es;
    es.onopen = () => setConn('Run ' + run_id + ' live', 'live');
    es.onmessage = e => {
      if (!run) return;
      run.lastEvent = Date.now();
      const msg = JSON.parse(e.data);
      handleSSE(msg);
      if (msg.type === 'done') endRun('Run ' + run_id + ' complete', 'live');
      else if (msg.type === 'error') endRun('Run ' + run_id + ' failed', 'bad');
    };
    // EventSource reconnects by itself and the server keeps the run's queue, so a
    // dropped connection resumes. CLOSED means it gave up (e.g. the server restarted).
    es.onerror = () => {
      if (!run) return;
      if (es.readyState === EventSource.CLOSED) {
        _fail('Lost the live stream for run ' + run_id + '. The server may have restarted; the run cannot be resumed.');
        endRun('Stream lost', 'bad');
      } else {
        setConn('Run ' + run_id + ' reconnecting', 'warn');
      }
    };
  } catch (e) {
    _fail(e.message);
    endRun('Failed before the run started', 'bad');
  }
}

function currentStage() {
  return STAGES.find(s => /active|failed/.test(_li(s).className)) || 'context';
}

// ── Stream rendering ───────────────────────────────────────────────────────
// Every value below comes from alerts, logs or model output (attacker-influenced
// text), so it is escaped before it touches innerHTML.
function _esc(v) {
  return String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
const _short = id => String(id || '').replace(/^.*-(L\d+-)?(?=T\d+$)/, '');

function handleSSE(ev) {
  const loop = ev.loop || 1;
  const data = ev.data || {};
  if (ev.type === 'analyst') {
    setStage('plan');
    if (!Object.keys(data).length) return;
    _addTokens(ev.tokens);
    state.plan = data;
    const tasks = data.tasks || [];
    if (!tasks.length && data.status === 'VERDICT_REACHED') {
      _add(_analystCard(data, ev.tokens), 'plan');
      setSum('plan', 'Verdict reached while planning, no evidence fetched');
      return;
    }
    // A plan without tasks reaches the broker as nothing: say so here, where it went wrong.
    if (!tasks.length) {
      setStage('plan', 'failed');
      setSum('plan', 'No usable plan: nothing to send to the Tool Broker');
      _add(_card('a', 'Plans the investigation', _tok(ev.tokens),
        '<div class="xr-p bad">The Analyst answered without a usable plan (no tasks' + (data.hypotheses ? '' : ', no hypotheses, no JSON') + '), so there is nothing to send to the Tool Broker.</div>' +
        _details('What the model said', data.reasoning ? '<div class="xr-p dim">' + _esc(data.reasoning) + '</div>' : '', true)), 'plan');
      return;
    }
    _add(_analystCard(data, ev.tokens), 'plan');
    const al = data.semantic_alignment ? (data.semantic_alignment === 'ALIGNED' ? ', deployed SPL aligned' : ', deployed SPL not aligned') : '';
    setSum('plan', (data.hypotheses || []).length + ' hypotheses, ' + tasks.length + ' tasks' + al);
    renderScores({});
  } else if (ev.type === 'handoff') {
    setStage('broker');
    state.loops = loop;
    const tasks = data.tasks || [];
    const lost = (data.dropped || []).filter(d => !d.sent).length;
    state.tasks = tasks.map(t => ({ id: t.task_id, q: t.question, steps: null, rows: null, spend: 0, rejected: 0, dom: {} }));
    renderTasks();
    if (loop > 2) _add('<div class="loop-h">Loop ' + (loop - 1) + '</div>', 'broker');
    _add(_handoffCard(loop, data), 'broker');
    setSum('broker', tasks.length + ' task' + (tasks.length === 1 ? '' : 's') + ' sent' + (lost ? ', ' + lost + ' not sent' : '') + ', fetching');
  } else if (ev.type === 'broker_log') {
    setStage('broker');
    if (!$('bk-' + loop)) _add(_brokerShell(loop), 'broker');
    const term = $('bk-term-' + loop);
    if (!term) return;
    const txt = data.line || '';
    const span = document.createElement('span');
    span.className = /\[ok|success/i.test(txt) ? 'l-ok' : /\[rejected|\[error|ERROR/i.test(txt) ? 'l-bad'
      : /task|\[T\d/i.test(txt) ? 'l-task' : /subagent|agent/i.test(txt) ? 'l-agent' : '';
    span.textContent = txt + '\n';
    const atBottom = term.scrollHeight - term.scrollTop - term.clientHeight < 24;
    term.appendChild(span);
    if (atBottom) term.scrollTop = term.scrollHeight;
    const last = $('bk-last-' + loop);
    if (last && txt.trim()) last.textContent = txt.trim().slice(0, 90);
  } else if (ev.type === 'broker') {
    if (!$('bk-' + loop)) _add(_brokerShell(loop), 'broker');
    const st = $('bk-st-' + loop);
    if (st) st.textContent = 'Done';
    const fd = $('bk-fd-' + loop);
    const runs = data.runs || [];
    if (fd) { fd.hidden = false; fd.innerHTML = _brokerSteps(runs); }
    _add(_handshake(data.handshake), 'broker');
    let done = 0, all = 0, spend = 0;
    runs.forEach(r => {
      const steps = r.steps || [];
      done += steps.filter(s => s.completed).length; all += steps.length; spend += r.spend_micro_usd || 0;
      const t = state.tasks.find(x => x.id === r.task_id);
      if (t) Object.assign(t, { steps: steps.filter(s => s.completed).length + '/' + steps.length,
        rows: steps.reduce((n, s) => n + (s.rows_retrieved || 0), 0), spend: r.spend_micro_usd || 0,
        rejected: steps.filter(s => s.status === 'rejected').length, noRun: !r.run_dir });
    });
    state.spend += spend;
    const h = data.handshake || {};
    const broken = (h.not_fetched || []).length + (h.not_returned || []).length + (h.unexpected || []).length;
    setSum('broker', (h.returned || []).length + ' of ' + (h.sent || []).length + ' tasks returned, ' + done + '/' + all + ' steps complete, $' + (spend / 1e6).toFixed(2) +
      (broken ? ', handshake broken' : ''));
    if (broken) setStage('broker', 'failed');
    renderTasks(); renderMeta();
  } else if (ev.type === 'payload') {
    setStage('findings');
    if (loop > 2) _add('<div class="loop-h">Loop ' + (loop - 1) + '</div>', 'findings');
    _add(_payloadCard(data), 'findings');
    let described = 0, failed = 0;
    (data.payloads || []).forEach(p => {
      const t = state.tasks.find(x => x.id === p.task_id);
      (p.findings || []).forEach(f => {
        const s = _domState(f);
        if (s === 'ok') described++; else if (s === 'bad') failed++;
        if (t) t.dom[f.domain] = s;
      });
    });
    setSum('findings', (data.payloads || []).length + ' finding sets, ' + described + ' domain descriptions' + (failed ? ', ' + failed + ' failed to parse' : ''));
    renderTasks();
  } else if (ev.type === 'synthesis') {
    setStage('synthesis');
    if (!data.status) { setSum('synthesis', 'Analyst is weighing the findings'); return; }
    _addTokens(ev.tokens);
    if (loop > 2) _add('<div class="loop-h">Loop ' + (loop - 1) + '</div>', 'synthesis');
    _add(_synthCard(data, ev.reasoning, ev.tokens), 'synthesis');
    const top = Object.entries(data.hypothesis_scores || {}).sort((a, b) => b[1] - a[1])[0];
    setSum('synthesis', (top ? top[0] + ' scores ' + top[1] + ', ' : '') + (data.status === 'VERDICT_REACHED' ? 'verdict reached' : 'needs another loop'));
    renderScores(data.hypothesis_scores || {});
  } else if (ev.type === 'verdict') {
    const decided = data.status === 'VERDICT_REACHED';
    if (_li('synthesis').className.includes('active')) setStage('synthesis', decided ? 'done' : 'undecided');
    else STAGES.forEach(s => { const li = _li(s); if (li.className === 'stg active') setStage(s, 'done'); });
    // The run's last word stays open, so the decision fills the ledger rather than blank space.
    const last = [...STAGES].reverse().find(s => _li(s).querySelector('.stg-body').children.length);
    if (last) _li(last).querySelector('details').open = true;
    _verdict(data, ev.message);
  } else if (ev.type === 'error') {
    const st = $('bk-st-' + loop);
    if (st) st.textContent = 'Failed';
    _fail(ev.message || 'The pipeline stopped with an error.');
  }
}

function _add(html, stage) { _li(stage).querySelector('.stg-body').insertAdjacentHTML('beforeend', html); }
function _addTokens(t) { if (t) { state.tokIn += t.prompt_tokens || 0; state.tokOut += t.generation_tokens || 0; } }
function _fail(msg) {
  state.failed = true;
  renderTasks();
  const stage = currentStage();
  setStage(stage, 'failed');
  setSum(stage, msg);
  const why = _explain(msg);
  _add('<div class="xr-stamp bad" role="alert">' + _esc(msg) + (why ? '<small>' + why + '</small>' : '') + '</div>', stage);
  const b = $('verdict');
  b.style.setProperty('--v', 'var(--bad)');
  b.innerHTML = '<div class="v-label">Run failed</div><div class="v-conf">' + _esc(msg) + '</div>';
}

// What an error means and where to look. First match wins; order is specific to general.
const _ERRORS = [
  [/no task could be converted/i, 'The Analyst handed the Tool Broker nothing it can search: no plan came back, or every task was dropped (an entity type the broker does not know, or a time window whose start is not before its end). The Plan and Evidence stages say which.'],
  [/broker timed out/i, 'The Tool Broker ran for more than 30 minutes and was stopped. Usually a slow Splunk search or a model stuck retrying. The engine log in the Evidence stage shows where it was.'],
  [/broker exited 2\b/i, 'The Tool Broker refused to start, so nothing was fetched: a configuration problem (MCP config, a task file it rejected, or model credentials). The quoted error line names it; fix .env and run again.'],
  [/broker exited/i, 'The Tool Broker crashed part-way through. The quoted lines and the end of the engine log show the exception.'],
  [/no analyst payload/i, 'The Tool Broker fetched evidence but the sub-analysts wrote no findings. Check SMARTOPS_ANALYST_MODEL_ARN and SMARTOPS_ANALYST_API_KEY in .env, and the end of the engine log.'],
  [/FS8B_MODEL_ARN|FS8B_API_KEY/, 'The Analyst model is not configured. Set FS8B_MODEL_ARN and FS8B_API_KEY in .env and restart the server.'],
  [/Bedrock (unreachable|call failed|failed)|HTTP (401|403)/i, 'The call to the Analyst model on Bedrock failed: network, an expired or wrong API key, or the imported model not reachable in that region.'],
  [/\/api\/(escu|opencti)/i, 'Building the context failed before the pipeline started (ESCU match or OpenCTI lookup). Check the server console.'],
  [/\/api\/run\b|run id/i, 'The server would not start a run. Check the server console.'],
  [/Lost the live stream/i, 'The browser lost the run. If the server restarted (for example a --reload after a file change), the run is gone; start it again.'],
  [/Failed to fetch|NetworkError/i, 'The browser cannot reach the server. Is uvicorn still running?'],
];
function _explain(msg) {
  const hit = _ERRORS.find(([re]) => re.test(msg || ''));
  const runDir = run && run.id ? ' Everything for this run is in .smartops/runs/' + _esc(run.id) + '/.' : '';
  return (hit ? hit[1] : 'An unexpected error. The server console has the traceback.') + runDir;
}

function _card(lane, title, meta, body, id) {
  return '<div class="card ' + lane + '"' + (id ? ' id="' + id + '"' : '') + '><div class="card-title"><span class="actor">' + (lane === 'a' ? 'Analyst' : 'Tool Broker') + '</span>' +
    title + (meta ? '<span class="card-meta">' + meta + '</span>' : '') + '</div>' + body + '</div>';
}
function _details(label, inner, open) { return inner ? '<details' + (open ? ' open' : '') + '><summary>' + label + '</summary>' + inner + '</details>' : ''; }
function _tok(t) { return t ? _esc(t.prompt_tokens || 0) + ' in / ' + _esc(t.generation_tokens || 0) + ' out' : ''; }
const _list = (xs) => (xs || []).filter(Boolean).map(x => '<span class="chip">' + _esc(x) + '</span>').join('');

const _VERDICT = { TRUE_POSITIVE: 'var(--bad)', FALSE_POSITIVE: 'var(--ok)', BENIGN: 'var(--ok)' };

function _contextCard(c, escu, cti) {
  const ec = c.escu_context || {};
  const matches = (escu.matches || []).map(m => '<div class="xr-p">' + _esc(m.rule) + ' <span class="dim">score ' + Number(m.score).toFixed(1) + '</span></div>').join('');
  const res = cti.results || {};
  const keys = Object.keys(res);
  const failed = keys.filter(k => JSON.stringify(res[k]).includes('"error"'));
  const seed = c.normalized_seed || {};
  const fps = (ec.known_false_positives || []).filter(Boolean);
  setSum('context', ((escu.matches || [])[0] ? 'ESCU: ' + escu.matches[0].rule : 'No ESCU match') + ', OpenCTI ' +
    (keys.length ? (keys.length - failed.length) + ' of ' + keys.length + ' lookups answered' : 'not asked') +
    (seed.event_time ? ', event at ' + seed.event_time.slice(11, 19) + ' UTC' : ''));
  return _card('a', 'Builds the alert context', '',
    '<div class="xr-h">ESCU matches</div>' + (matches || '<div class="xr-p dim">No ESCU rule matched this name.</div>') +
    (ec.description ? '<div class="xr-p dim">' + _esc(ec.description) + '</div>' : '') +
    ((ec.mitre_techniques || []).length ? '<div class="xr-h">MITRE</div><div class="chips">' + _list(ec.mitre_techniques) + '</div>' : '') +
    ((ec.analytic_story || []).length ? '<div class="xr-h">Analytic stories</div><div class="chips">' + _list(ec.analytic_story) + '</div>' : '') +
    ((ec.data_sources || []).length ? '<div class="xr-h">Data sources</div><div class="chips">' + _list(ec.data_sources) + '</div>' : '') +
    (fps.length ? '<div class="xr-h">Known false positives (ESCU)</div>' + fps.map(f => '<div class="xr-p">' + _esc(f) + '</div>').join('') : '') +
    '<div class="xr-h">OpenCTI</div><div class="xr-p ' + (failed.length ? 'bad' : '') + '">' +
      (keys.length ? (failed.length ? failed.length + ' of ' + keys.length + ' lookups failed (OpenCTI unreachable or timing out)' : keys.length + ' lookups answered') : 'No observables to look up') + '</div>' +
    '<details class="raw"><summary>Raw context sent to the pipeline</summary>' +
      '<div class="xr-h">Context contract</div><pre id="contractOut">' + _esc(JSON.stringify(c, null, 2)) + '</pre>' +
      '<div class="xr-h">ESCU match</div><pre id="escuOut">' + _esc(JSON.stringify(escu, null, 2)) + '</pre>' +
      '<div class="xr-h">OpenCTI lookup</div><pre id="ctiOut">' + _esc(JSON.stringify(cti, null, 2)) + '</pre></details>');
}

function _alignment(plan) {
  if (!plan.semantic_alignment) return '';
  const ok = plan.semantic_alignment === 'ALIGNED';
  const ri = (run && run.contract && run.contract.rule_intent) || {};
  return '<div class="xr-h">Deployed SPL vs ESCU reference</div>' +
    '<div class="xr-p ' + (ok ? 'ok' : 'bad') + '"><b>' + (ok ? 'Aligned' : 'Not aligned') + '</b></div>' +
    (plan.alignment_reasoning ? '<div class="xr-p dim">' + _esc(plan.alignment_reasoning) + '</div>' : '') +
    _details('Compare the two SPLs', '<div class="xr-spl"><div><div class="xr-h">Deployed</div><pre>' + _esc(ri.deployed_spl) +
      '</pre></div><div><div class="xr-h">Reference</div><pre>' + _esc(ri.reference_spl) + '</pre></div></div>');
}

function _analystCard(data, tokens) {
  const hyps = (data.hypotheses || []).map(h =>
    '<div class="xr-p"><b style="color:' + (_VERDICT[h.verdict] || 'inherit') + '">' + _esc(h.id) + ' ' + _esc(String(h.verdict || '').replace(/_/g, ' ').toLowerCase()) + '</b> ' + _esc(h.description) + '</div>'
  ).join('') || '<div class="xr-p dim">No hypotheses in the plan.</div>';
  return _card('a', 'Plans the investigation', _tok(tokens),
    (data.model_reasoning ? '<div class="xr-p dim">' + _esc(data.model_reasoning) + '</div>' : '') +
    '<div class="xr-h">Hypotheses</div>' + hyps + _alignment(data) +
    _details('Full reasoning', data.reasoning ? '<div class="xr-p dim">' + _esc(data.reasoning) + '</div>' : ''));
}

function _handoffCard(loop, data) {
  const tasks = data.tasks || [];
  // `dropped` also carries notes on tasks that were sent changed (narrowed, or re-scoped to the alert).
  const notes = (data.dropped || []).filter(d => d.sent);
  const dropped = (data.dropped || []).filter(d => !d.sent);
  const list = tasks.map(t =>
    '<div class="xr-p" style="margin-top:6px"><b>' + _esc(_short(t.task_id)) + '</b> ' + _esc(t.question) + '</div>' +
    '<div class="xr-mono">' + (t.entity || []).map(e => _esc(e.type) + '=' + _esc(e.value)).join('  ') + '   ' +
      _esc((t.time_window || {}).start) + ' to ' + _esc((t.time_window || {}).end) + '</div>'
  ).join('');
  const changed = notes.map(d => '<div class="xr-p dim"><b>' + _esc(_short(d.task_id) || 'Task') + '</b> sent changed: ' + _esc(d.why) + '</div>').join('');
  const lost = dropped.map(d => '<div class="xr-p bad"><b>' + _esc(_short(d.task_id) || 'Task') + '</b> not sent: ' + _esc(d.why) + '</div>' +
    (d.question ? '<div class="xr-p dim">' + _esc(d.question) + '</div>' : '')).join('');
  return _card('b', 'Receives ' + tasks.length + ' task' + (tasks.length === 1 ? '' : 's'), dropped.length ? dropped.length + ' not sent' : '',
    (list || '<div class="xr-p bad">Nothing arrived: no task could be converted.</div>') + changed + lost +
    '<div class="xr-mono" style="margin-top:8px">' + _esc(data.task_file) + '</div>');
}

function _brokerShell(loop) {
  return _card('b', 'Fetches the evidence', '<span id="bk-st-' + loop + '">Running</span>',
    '<details><summary>Engine log<span class="log-last" id="bk-last-' + loop + '"></span></summary><div class="xr-log xr-mono" id="bk-term-' + loop + '"></div></details>' +
    '<div id="bk-fd-' + loop + '" hidden></div>', 'bk-' + loop);
}

function _stepLine(s) {
  const mk = s.completed ? '<span class="mk ok">done</span>' : (s.status ? '<span class="mk no">' + (s.status === 'rejected' ? 'rejected' : 'failed') + '</span>' : '<span class="mk wait">skipped</span>');
  const got = s.confirmed_empty ? 'looked, found nothing' : (s.rows_retrieved != null ? s.rows_retrieved + ' rows' : 'not run');
  const cats = (s.categories || []).length ? ' for ' + s.categories.map(_esc).join(', ') : '';
  return '<div class="xr-step">' + mk + '<div><b>' + _esc(s.family) + '</b>' + cats + ': ' + got + (s.status && !s.completed ? ' (' + _esc(s.status) + ')' : '') + '</div>' +
    '<div class="sub">' + _esc(s.objective) + (s.reason ? '<br>' + _esc(s.reason) : '') + '</div></div>';
}

function _brokerSteps(runs) {
  return runs.map(r => {
    if (!r.run_dir) return '<details class="task" id="task-' + _esc(r.task_id) + '"><summary><b>' + _esc(_short(r.task_id)) + '</b> <span class="xr-p bad">no run recorded</span></summary></details>';
    const queries = (r.results || []).map(x =>
      '<div class="xr-p">' + _esc(x.family) + ': ' + _esc(x.status) + ', ' + (x.queries || []).length + ' quer' + ((x.queries || []).length === 1 ? 'y' : 'ies') +
        ((x.blocked || []).length ? ', <span class="xr-p bad">' + x.blocked.length + ' blocked</span>' : '') +
        ((x.gaps || []).length ? ', suggests ' + x.gaps.map(_esc).join(', ') : '') + '</div>' +
      (x.reason ? '<div class="xr-p dim">' + _esc(x.reason) + '</div>' : '') +
      (x.error ? '<div class="xr-p bad">error: ' + _esc(x.error) + '</div>' : '') +
      '<div class="xr-mono">' + (x.queries || []).map(_esc).join('\n') +
        ((x.blocked || []).length ? '\n' + x.blocked.map(q => 'blocked: ' + _esc(q)).join('\n') : '') + '</div>'
    ).join('');
    const steps = r.steps || [];
    const done = steps.filter(s => s.completed).length;
    return '<details class="task" id="task-' + _esc(r.task_id) + '"><summary><b>' + _esc(_short(r.task_id)) + '</b> ' + done + '/' + steps.length + ' step' + (steps.length === 1 ? '' : 's') + ' complete' +
        (r.spend_micro_usd != null ? ', $' + (r.spend_micro_usd / 1e6).toFixed(2) : '') +
        ((r.results || []).some(x => x.error || x.status === 'error') ? ', <span class="xr-p bad">errors</span>' : '') + '</summary>' +
      (r.plan_rationale ? '<div class="xr-p dim">' + _esc(r.plan_rationale) + '</div>' : '') +
      (r.plan_repairs && r.plan_repairs.length ? '<div class="xr-p dim">Guards repaired the plan: ' + r.plan_repairs.map(x => _esc(typeof x === 'string' ? x : JSON.stringify(x))).join('; ') + '</div>' : '') +
      steps.map(_stepLine).join('') +
      _details('Why these tools', r.classification ? '<div class="xr-p dim">' + _esc(r.classification) + '</div>' : '') +
      _details('Queries run (' + (r.dispatched || []).map(_esc).join(', ') + ')', queries) +
      '<div class="xr-mono" style="margin-top:6px">trace ' + _esc(r.trace_id || 'none') + '\n' + _esc(r.run_dir) + '</div></details>';
  }).join('');
}

function _handshake(h) {
  if (!h) return '';
  const miss = [
    (h.not_fetched || []).length ? 'never fetched: ' + h.not_fetched.map(_esc).join(', ') : '',
    (h.not_returned || []).length ? 'no findings came back for: ' + h.not_returned.map(_esc).join(', ') : '',
    (h.unexpected || []).length ? 'came back but was never sent: ' + h.unexpected.map(_esc).join(', ') : '',
  ].filter(Boolean);
  const n = k => (h[k] || []).length;
  return '<div class="xr-stamp ' + (miss.length ? 'bad' : 'ok') + '" role="status">' +
    (miss.length ? 'Handshake broken' : 'Handshake held') + ': ' + n('sent') + ' sent, ' + n('fetched') + ' fetched, ' + n('returned') + ' returned' +
    (miss.length ? '<small>' + miss.join('<br>') + '</small>' : '') + '</div>';
}

// A finding's narrative is the model's prose, then code-written blocks that open with a
// known header and list `~` lines. The prose is shown whole; the code lines stand apart.
const _CODE_HEADERS = /\n\s*\n(?=(Names in this narrative|Encoded commands in these rows)[^\n]*:)/;
function _domState(f) {
  const narr = String(f.narrative || '');
  if (/produced no parseable/i.test(narr)) return 'bad';
  return narr.trim() ? 'ok' : 'none';
}
// "described identity, network; failed endpoint": which sub-analysts had something to say.
function _domLine(pairs) {
  const by = { ok: [], bad: [], none: [] };
  pairs.forEach(([d, s]) => (by[s] || by.none).push(_esc(d)));
  return [by.ok.length ? 'described ' + by.ok.join(', ') : '',
          by.bad.length ? '<span class="bad">failed ' + by.bad.join(', ') + '</span>' : ''].filter(Boolean).join('; ') || 'nothing to describe';
}
function _finding(f) {
  const narr = String(f.narrative || '').trim();
  const obs = f.observations || [], sums = f.summaries || [];
  const st = _domState(f);
  if (st === 'none') return '<div class="dom none"><b>' + _esc(f.domain) + '</b><span class="xr-p dim">nothing to describe</span></div>';
  const parts = narr.split(_CODE_HEADERS);
  const prose = parts[0].trim();
  const code = narr.slice(prose.length).trim();
  return '<div class="dom"><b>' + _esc(f.domain) + '</b><div>' +
    '<div class="xr-p' + (st === 'bad' ? ' bad' : '') + '">' + _esc(prose) + '</div>' +
    (code ? '<div class="code-lines" title="Computed by code from the rows, not written by the model">' + _esc(code) + '</div>' : '') +
    _details('Observations (' + obs.length + ') and row summaries (' + sums.length + ')',
      (obs.length ? '<div class="xr-mono">' + obs.map(_esc).join('\n') + '</div>' : '') +
      (sums.length ? '<div class="code-lines">' + sums.map(_esc).join('\n\n') + '</div>' : '')) +
    '</div></div>';
}
function _payloadCard(data) {
  const ps = data.payloads || [];
  const body = ps.map(p => {
    const doms = (p.findings || []);
    const mark = _domLine(doms.map(f => [f.domain, _domState(f)]));
    return '<details class="task" id="fd-' + _esc(p.task_id) + '"><summary><b>' + _esc(_short(p.task_id)) + '</b> ' + _esc(p.hypothesis || '') +
      ' <span class="dim dom-line">' + mark + '</span></summary>' +
      (doms.map(_finding).join('') || '<div class="xr-p dim">No domain had evidence to describe.</div>') + '</details>';
  }).join('') || '<div class="xr-p dim">No findings.</div>';
  return _card('b', 'Sub-analysts describe the evidence', ps.length + ' finding set' + (ps.length === 1 ? '' : 's'), body);
}

function _synthCard(data, reasoning, tokens) {
  const gaps = (data.evidence_gaps || []).map(g => '<div class="xr-p">' + _esc(g) + '</div>').join('');
  const fups = (data.follow_up_tasks || []).map(t => '<div class="xr-p">' + _esc(t.question || JSON.stringify(t)) + '</div>').join('');
  const done = data.status === 'VERDICT_REACHED';
  const scores = Object.entries(data.hypothesis_scores || {}).map(([k, v]) => _esc(k) + ' ' + _esc(v)).join(', ');
  return _card('a', 'Weighs the hypotheses', _tok(tokens),
    '<div class="xr-p ' + (done ? 'ok' : '') + '" style="font-weight:650">' + (done ? 'Verdict reached' : 'Needs another loop') + (scores ? ' <span class="dim">(' + scores + ')</span>' : '') + '</div>' +
    (data.verdict_reasoning ? '<div class="xr-h">Why</div><div class="xr-p">' + _esc(data.verdict_reasoning) + '</div>' : '') +
    ((data.evidence_refs || []).length ? '<div class="xr-h">Evidence cited</div><div class="chips">' + _list(data.evidence_refs) + '</div>' : '') +
    (gaps ? '<div class="xr-h">Still missing</div>' + gaps : '') +
    (fups ? '<div class="xr-h">Follow-up tasks asked for</div>' + fups : '') +
    _details('Full reasoning', reasoning ? '<div class="xr-p dim">' + _esc(reasoning) + '</div>' : ''));
}

// ── Rail ───────────────────────────────────────────────────────────────────

function railReset() {
  const b = $('verdict');
  b.style.removeProperty('--v');
  b.classList.remove('landed');
  b.innerHTML = '<div class="v-label">Investigating</div><div class="v-conf">The verdict lands here when synthesis finishes.</div><div id="scores"></div>';
  state.tasks = [];
  renderTasks();
  renderMeta();
}

function renderScores(scores) {
  const el = $('scores');
  if (!el) return;
  const hyps = (state.plan && state.plan.hypotheses) || [];
  const ids = hyps.length ? hyps.map(h => h.id) : Object.keys(scores);
  const top = Math.max(...ids.map(id => Number(scores[id]) || 0));
  el.innerHTML = ids.length ? '<div class="v-h">Hypotheses</div>' + ids.map(id => {
    const h = hyps.find(x => x.id === id) || {};
    const has = scores[id] != null, v = Math.max(0, Math.min(100, Number(scores[id]) || 0));
    return '<div class="score' + (has && v === top ? ' top' : '') + '" title="' + _esc((h.verdict || '') + ': ' + (h.description || '')) + '">' +
      '<b>' + _esc(id) + '</b><span class="bar"><i style="width:' + v + '%;--c:' + (_VERDICT[h.verdict] || 'var(--warn)') + '"></i></span>' +
      '<span class="n">' + (has ? _esc(scores[id]) : '') + '</span></div>';
  }).join('') : '';
}

function renderTasks() {
  const el = $('taskBoard');
  if (!state.tasks || !state.tasks.length) {
    el.innerHTML = '<li class="dim">The plan\'s tasks appear here once the Analyst sends them.</li>';
    return;
  }
  el.innerHTML = state.tasks.map(t => {
    const bad = t.noRun || Object.values(t.dom).includes('bad');
    const st = t.steps == null ? (state.failed ? '<span class="tst bad">stopped</span>' : '<span class="tst">fetching</span>')
      : '<span class="tst ' + (bad ? 'bad' : t.rejected ? 'warn' : 'ok') + '">' + _esc(t.steps) + ' steps, ' + t.rows + ' rows</span>';
    const dom = Object.keys(t.dom).length ? _domLine(Object.entries(t.dom)) : '';
    return '<li><button type="button" data-task="' + _esc(t.id) + '" title="' + _esc(t.q) + '"><span class="tid">' + _esc(_short(t.id)) + '</span>' +
      '<span class="tq">' + _esc(t.q) + '</span>' + st +
      (dom || t.rejected ? '<span class="tdom">' + dom + (t.rejected ? (dom ? '; ' : '') + t.rejected + ' step rejected' : '') + '</span>' : '') +
      '</button></li>';
  }).join('');
}

function renderMeta() {
  const now = state.ended || Date.now();
  const rows = [
    ['Status', state.status || 'Idle'],
    state.id ? ['Run', state.id] : null,
    state.started ? ['Elapsed', _secs(now - state.started)] : null,
    run ? ['Last event', _secs(Date.now() - run.lastEvent) + ' ago'] : null,
    state.spend ? ['Broker spend', '$' + (state.spend / 1e6).toFixed(2)] : null,
    state.tokIn ? ['Analyst tokens', state.tokIn + ' in, ' + state.tokOut + ' out'] : null,
    state.loops ? ['Broker rounds', String(state.loops - 1)] : null,
    state.id ? ['Files', '.smartops/runs/' + state.id + '/'] : null,
  ].filter(Boolean);
  $('runMeta').innerHTML = rows.map(([k, v]) => '<dt>' + _esc(k) + '</dt><dd>' + _esc(v) + '</dd>').join('');
}

function _verdict(data, why) {
  // The server sends a verdict event both when the gate passed and when the loop
  // simply ran out (max loops, no follow-ups). Only the first is a decision.
  const decided = data.status === 'VERDICT_REACHED';
  const v = String(data.verdict || 'UNKNOWN').toUpperCase();
  const conf = data.verdict_confidence ?? data.confidence;
  const b = $('verdict');
  const scores = data.hypothesis_scores || {};
  b.style.setProperty('--v', decided ? (_VERDICT[v] || 'var(--warn)') : 'var(--warn)');
  const li = (h, xs) => (xs || []).length ? '<div class="v-h">' + h + '</div><ul class="v-list">' + xs.map(x => '<li>' + _esc(x) + '</li>').join('') + '</ul>' : '';
  b.innerHTML = '<div class="v-label">' + (decided ? _esc(v.replace(/_/g, ' ').toLowerCase().replace(/^./, c => c.toUpperCase())) : 'No verdict') + '</div>' +
    '<div class="v-conf">' + (decided ? '' : 'Leaning ' + _esc(v.replace(/_/g, ' ').toLowerCase()) + ', but the evidence gate did not pass. Stopped: ' + _esc(why || 'unknown') + '. ') +
      (conf != null ? 'Confidence ' + _esc(conf) + '%' : '') + '</div>' +
    '<div id="scores"></div>' +
    '<div class="v-h">Why</div><div class="v-sum">' + _esc(data.verdict_reasoning || data.reasoning || data.executive_summary || 'The model gave no reasoning for this verdict.') + '</div>' +
    li('Evidence cited', data.evidence_refs) + li('Still missing', data.evidence_gaps);
  renderScores(scores);
  b.classList.remove('landed'); void b.offsetWidth; b.classList.add('landed');
  state.status = decided ? 'Verdict reached' : 'Stopped without a verdict';
  renderMeta();
}

// ── Wire up ────────────────────────────────────────────────────────────────

$('alertForm').addEventListener('submit', investigate);
$('queueRefresh').addEventListener('click', loadQueue);
$('alertEdit').addEventListener('click', () => { const open = $('alertForm').hidden; showForm(open); if (open) $('f_rule').focus(); });
$('queueList').addEventListener('click', e => {
  const btn = e.target.closest('button[data-index]');
  if (btn) importAlert(Number(btn.dataset.index), btn);
});
// A task in the rail opens its findings (or, before they arrive, its evidence run).
$('taskBoard').addEventListener('click', e => {
  const btn = e.target.closest('button[data-task]');
  if (!btn) return;
  const id = btn.dataset.task;
  const el = document.getElementById('fd-' + id) || document.getElementById('task-' + id);
  if (!el) return;
  for (let p = el; p; p = p.parentElement) if (p.tagName === 'DETAILS') p.open = true;
  el.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  el.querySelector('summary').focus({ preventScroll: true });
});
loadQueue();

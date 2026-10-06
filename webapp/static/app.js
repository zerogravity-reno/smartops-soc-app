// SmartOps SOC console: pick an alert, build its context contract, run the whole
// pipeline with one /api/run call and render the Analyst <-> Tool Broker stream live.

const $ = id => document.getElementById(id);
const FIELDS = ['rule', 'src', 'dest', 'user', 'hash', 'domain', 'mitre', 'sig', 'spl'];

let lastImportedRaw = {};
let lastImportedTime = null;
let run = null;   // {es, started, lastEvent, timer, contract}
let stats = {};   // per loop: sent, dropped, handshake, top, status -- the folded summary

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

// ── Incident queue ─────────────────────────────────────────────────────────

async function loadQueue() {
  const list = $('queueList');
  list.setAttribute('aria-busy', 'true');
  list.innerHTML = '<li class="skel"></li><li class="skel"></li><li class="skel"></li>';
  try {
    const data = await getJSON('/api/incident-queue');
    if (data.status === 'error') throw new Error(data.message);
    const events = data.events || [];
    list.innerHTML = events.length ? events.map(ev =>
      '<li><button type="button" data-index="' + Number(ev.index) + '">' +
        '<div class="q-rule">' + _esc(ev.rule_name || 'Unnamed rule') + '</div>' +
        '<div class="q-meta">' + [
          ev.urgency ? '<span class="q-urg ' + _esc(String(ev.urgency).toLowerCase()) + '">' + _esc(ev.urgency) + '</span>' : '',
          _esc(ev.time || ''),
        ].filter(Boolean).join(' &middot; ') + '</div>' +
        '<div class="q-meta">' + _esc([ev.src, ev.dest, ev.user].filter(Boolean).join('  ')) + '</div>' +
      '</button></li>').join('')
      : '<li class="q-state">No notable events in the last 30 days. You can still fill the alert fields by hand.</li>';
  } catch (e) {
    list.innerHTML = '<li class="q-state bad">Could not reach Splunk: ' + _esc(e.message) +
      '<br>Check the Splunk MCP connection, then Refresh.</li>';
  } finally {
    list.setAttribute('aria-busy', 'false');
  }
}

// ponytail: the queue and the import both take "sort -_time | head", so a notable that
// lands between the two calls shifts the index by one. Import by rule_id/_time if that bites.
async function importAlert(index, btn) {
  if (run) { toast('A run is in progress. Wait for it to finish.', true); return; }
  document.querySelectorAll('#queueList button').forEach(b => b.removeAttribute('aria-current'));
  btn.setAttribute('aria-current', 'true');
  foldAlert(false);
  $('alertNote').textContent = 'Importing alert from Splunk ES...';
  try {
    const data = await getJSON('/api/import-from-splunk?index=' + index);
    if (data.status !== 'ok') throw new Error(data.message || 'No alert returned');
    const map = { rule: data.rule_name, src: data.src, dest: data.dest, user: data.user, hash: data.file_hash,
                  domain: data.domain, mitre: data.mitre, sig: data.sig, spl: data.deployed_spl };
    FIELDS.forEach(k => { $('f_' + k).value = map[k] || ''; });
    lastImportedRaw = data.raw_event_data || {};
    lastImportedTime = data.event_time || null;
    $('alertNote').textContent = 'Imported the alert' + (data.event_time ? ' from ' + data.event_time : '') +
      (data.urgency ? ' (urgency ' + data.urgency + ')' : '') + '. Review the fields, then Investigate.';
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

function setStage(name, state) {
  const items = [...$('stages').children];
  const at = items.findIndex(li => li.dataset.stage === name);
  items.forEach((li, i) => {
    li.className = i < at ? 'done' : i === at ? (state || 'active') : '';
  });
}

function endRun(text, cls) {
  if (!run) return;
  run.es && run.es.close();
  clearInterval(run.timer);
  $('runClock').textContent = 'Finished after ' + Math.round((Date.now() - run.started) / 1000) + 's';
  run = null;
  setConn(text, cls);
  $('runBtn').disabled = false;
  $('runBtn').textContent = 'Investigate';
  document.querySelectorAll('#queueList button').forEach(b => { b.disabled = false; });
}

function tick() {
  if (!run) return;
  const s = n => Math.round((Date.now() - n) / 1000) + 's';
  $('runClock').textContent = 'Running ' + s(run.started) + ', last event ' + s(run.lastEvent) + ' ago';
}

async function investigate(ev) {
  ev.preventDefault();
  if (run) return;
  const v = k => $('f_' + k).value.trim();
  const f = { rule_name: v('rule'), src_ip: v('src'), dest: v('dest'), user: v('user'), hash: v('hash'),
              domain: v('domain'), mitre: v('mitre'), signature: v('sig'), deployed_spl: v('spl') };
  if (!f.rule_name) {
    $('formError').textContent = 'Pick an alert from the queue or enter the detection rule name.';
    $('f_rule').focus();
    return;
  }
  $('formError').textContent = '';

  run = { started: Date.now(), lastEvent: Date.now(), timer: setInterval(tick, 1000) };
  stats = {};
  foldAlert(true, [f.rule_name, f.dest, f.user].filter(Boolean).join('  /  '));
  $('runBtn').disabled = true;
  $('runBtn').textContent = 'Running...';
  document.querySelectorAll('#queueList button').forEach(b => { b.disabled = true; });
  $('stream').innerHTML = '';
  $('verdict').hidden = true;
  $('contextBox').hidden = true;
  setStage('context');
  setConn('Building context', 'live');
  tick();

  try {
    const { contract, escuData, ctiData } = await buildContract(f, lastImportedRaw);
    run.contract = contract;
    $('contractOut').textContent = JSON.stringify(contract, null, 2);
    $('escuOut').textContent = JSON.stringify(escuData, null, 2);
    $('ctiOut').textContent = JSON.stringify(ctiData, null, 2);
    $('contextBox').hidden = false;

    const { run_id } = await postJSON('/api/run', { context_contract: contract });
    if (!run_id) throw new Error('The server did not return a run id.');
    run.id = run_id;
    setStage('plan');
    setConn('Run ' + run_id + ' connecting', 'warn');

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
        _stampError('Lost the live stream for run ' + run_id + '. The server may have restarted; the run cannot be resumed.');
        setStage(currentStage(), 'failed');
        endRun('Stream lost', 'bad');
      } else {
        setConn('Run ' + run_id + ' reconnecting', 'warn');
      }
    };
  } catch (e) {
    _stampError(e.message);
    setStage(currentStage(), 'failed');
    endRun('Failed before the run started', 'bad');
  }
}

function currentStage() {
  const li = $('stages').querySelector('.active, .failed');
  return li ? li.dataset.stage : 'context';
}

// ── Stream rendering ───────────────────────────────────────────────────────
// Every value below comes from alerts, logs or model output (attacker-influenced
// text), so it is escaped before it touches innerHTML.
function _esc(v) {
  return String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function handleSSE(ev) {
  const loop = ev.loop || 1;
  const data = ev.data || {};
  if (ev.type === 'analyst') {
    setStage('plan');
    if (!Object.keys(data).length) { _add('<div class="xr-loop">Loop 1</div>' + _waiting('a', 'Plans the investigation', 'Analyst is planning. A cold model can take a few minutes.', 'wait-plan'), 'plan'); return; }
    _drop('wait-plan');
    // A plan without tasks reaches the broker as nothing: say so here, where it went wrong.
    if (!(data.tasks || []).length) {
      setStage('plan', 'failed');
      _add(_block('a', 'Plans the investigation', _tok(ev.tokens),
        '<div class="xr-p bad">The Analyst answered without a usable plan (no tasks' + (data.hypotheses ? '' : ', no hypotheses, no JSON') + '), so there is nothing to send to the Tool Broker.</div>' +
        _details('What the model said', data.reasoning ? '<div class="xr-p dim">' + _esc(data.reasoning) + '</div>' : '', true)), 'plan');
      return;
    }
    _add(_analystCard(data, ev.tokens), 'plan');
  } else if (ev.type === 'handoff') {
    if ((data.tasks || []).length) setStage('broker');
    if (loop > 2) _foldLoop(loop - 1);
    stats[loop] = { sent: (data.tasks || []).length, dropped: (data.dropped || []).filter(d => !d.sent).length };
    _add(_handoffCard(loop, data), 'broker');
  } else if (ev.type === 'broker_log') {
    setStage('broker');
    if (!$('bk-' + loop)) _add(_brokerShell(loop));
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
    if (!$('bk-' + loop)) _add(_brokerShell(loop));
    const st = $('bk-st-' + loop);
    if (st) st.textContent = 'Done';
    const fd = $('bk-fd-' + loop);
    if (fd) { fd.hidden = false; fd.innerHTML = _brokerSteps(data.runs || []); }
    _add(_handshake(data.handshake));
    const h = data.handshake;
    if (h) (stats[loop] = stats[loop] || {}).handshake =
      (h.not_fetched || []).length + (h.not_returned || []).length + (h.unexpected || []).length ? 'handshake broken' : 'handshake held';
  } else if (ev.type === 'payload') {
    _add(_payloadCard(data));
  } else if (ev.type === 'synthesis') {
    setStage('synthesis');
    if (!data.status) { _add(_waiting('a', 'Weighs the hypotheses', 'Analyst is weighing the findings.', 'wait-syn-' + loop), 'synthesis'); return; }
    _drop('wait-syn-' + loop);
    _add(_synthCard(data, ev.reasoning, ev.tokens), 'synthesis');
    const top = Object.entries(data.hypothesis_scores || {}).sort((a, b) => b[1] - a[1])[0];
    Object.assign(stats[loop] = stats[loop] || {}, {
      top: top ? top[0] + ' ' + top[1] : '', status: data.status === 'VERDICT_REACHED' ? 'verdict reached' : 'needs another loop' });
  } else if (ev.type === 'verdict') {
    setStage('verdict', data.status === 'VERDICT_REACHED' ? 'done' : 'undecided');
    _verdict(data, ev.message);
  } else if (ev.type === 'error') {
    const st = $('bk-st-' + loop);
    if (st) st.textContent = 'Failed';
    setStage(currentStage(), 'failed');
    _stampError(ev.message || 'The pipeline stopped with an error.');
  }
}

// Each loop renders into its own lanes; a finished loop folds into one summary line.
function _lanes() {
  let l = $('stream').querySelector(':scope > .xr-lanes');
  if (!l) {
    $('stream').insertAdjacentHTML('beforeend', '<div class="xr-lanes"><div class="xr-head a">Analyst</div><div class="xr-head b">Tool Broker</div></div>');
    l = $('stream').querySelector(':scope > .xr-lanes');
  }
  return l;
}
// `stage` marks the first card of that stage in this loop, for the stage bar to jump to.
function _add(html, stage) {
  const l = _lanes();
  const first = l.children.length;
  l.insertAdjacentHTML('beforeend', html);
  if (stage && !l.querySelector('[data-anchor="' + stage + '"]') && l.children[first]) l.children[first].dataset.anchor = stage;
}
function _foldLoop(loop) {
  const l = $('stream').querySelector(':scope > .xr-lanes');
  if (!l) return;
  const s = stats[loop] || {};
  const d = document.createElement('details');
  d.className = 'loop-fold';
  d.innerHTML = '<summary>' + _esc('Loop ' + loop + ': ' + [
    s.sent != null ? s.sent + ' sent' + (s.dropped ? ', ' + s.dropped + ' not sent' : '') : '',
    s.handshake || '',
    s.top ? 'top ' + s.top : '',
    s.status || '',
  ].filter(Boolean).join(', ')) + '</summary>';
  l.replaceWith(d);
  d.appendChild(l);
}
function _jump(stage) {
  const el = stage === 'verdict' ? $('verdict') : stage === 'context' ? $('contextBox')
    : [...document.querySelectorAll('[data-anchor="' + stage + '"]')].pop();
  if (!el || el.hidden) return;
  for (let p = el.parentElement; p; p = p.parentElement) if (p.tagName === 'DETAILS') p.open = true;
  el.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
}
function _drop(id) { const el = $(id); if (el) el.remove(); }
function _stampError(msg) {
  const why = _explain(msg);
  _add('<div class="xr-stamp bad" role="alert">' + _esc(msg) + (why ? '<small>' + why + '</small>' : '') + '</div>');
}

// What an error means and where to look. First match wins; order is specific to general.
const _ERRORS = [
  [/no task could be converted/i, 'The Analyst handed the Tool Broker nothing it can search: no plan came back, or every task was dropped (an entity type the broker does not know, or a time window whose start is not before its end). The Plan and "Receives the tasks" cards above say which.'],
  [/broker timed out/i, 'The Tool Broker ran for more than 30 minutes and was stopped. Usually a slow Splunk search or a model stuck retrying. The engine log above shows where it was.'],
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

function _block(lane, title, meta, body, id) {
  return '<div class="xr-block ' + lane + '"' + (id ? ' id="' + id + '"' : '') + '><div class="xr-tag">' + (lane === 'a' ? 'Analyst' : 'Tool Broker') + '</div>' +
    '<div class="xr-title">' + title + (meta ? '<span class="xr-meta">' + meta + '</span>' : '') + '</div>' + body + '</div>';
}
function _waiting(lane, title, text, id) { return _block(lane, title, '', '<div class="xr-waiting">' + text + '</div>', id); }
function _cross(dir, from, to) {
  return '<div class="xr-cross ' + dir + '"><div class="from">' + from + '</div><div class="arrow" aria-hidden="true"></div><div class="to">' + to + '</div></div>';
}
function _details(label, inner, open) { return inner ? '<details' + (open ? ' open' : '') + '><summary>' + label + '</summary>' + inner + '</details>' : ''; }
function _tok(t) { return t ? _esc(t.prompt_tokens || 0) + ' in / ' + _esc(t.generation_tokens || 0) + ' out' : ''; }

const _VERDICT = { TRUE_POSITIVE: 'var(--bad)', FALSE_POSITIVE: 'var(--ok)', BENIGN: 'var(--ok)' };

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
    '<div class="xr-p"><b style="color:' + (_VERDICT[h.verdict] || 'inherit') + '">' + _esc(h.id) + ' ' + _esc(h.verdict) + '</b> ' + _esc(h.description) + '</div>'
  ).join('') || '<div class="xr-p dim">No hypotheses in the plan.</div>';
  return _block('a', 'Plans the investigation', _tok(tokens),
    '<div class="xr-h">Hypotheses</div>' + hyps + _alignment(data) +
    _details('Reasoning', data.reasoning ? '<div class="xr-p dim">' + _esc(data.reasoning) + '</div>' : ''));
}

function _handoffCard(loop, data) {
  const tasks = data.tasks || [];
  // `dropped` also carries notes on tasks that were sent changed (narrowed, or re-scoped to the alert).
  const notes = (data.dropped || []).filter(d => d.sent);
  const dropped = (data.dropped || []).filter(d => !d.sent);
  const list = tasks.map(t =>
    '<div class="xr-p"><b>' + _esc(t.task_id) + '</b> ' + _esc(t.question) + '</div>' +
    '<div class="xr-mono">' + (t.entity || []).map(e => _esc(e.type) + '=' + _esc(e.value)).join('  ') + '\n' +
      _esc((t.time_window || {}).start) + ' to ' + _esc((t.time_window || {}).end) + '</div>'
  ).join('');
  const changed = notes.map(d => '<div class="xr-p dim"><b>' + _esc(d.task_id || 'Task') + '</b> sent changed: ' + _esc(d.why) + '</div>').join('');
  const lost = dropped.map(d => '<div class="xr-p bad"><b>' + _esc(d.task_id || 'Task') + '</b> not sent: ' + _esc(d.why) + '</div>' +
    (d.question ? '<div class="xr-p dim">' + _esc(d.question) + '</div>' : '')).join('');
  return (loop > 2 ? '<div class="xr-loop">Loop ' + loop + '</div>' : '') +
    _cross('ab', '<b>' + tasks.length + ' task' + (tasks.length === 1 ? '' : 's') + '</b> sent' + (dropped.length ? ', ' + dropped.length + ' not sent' : ''),
                 'received as a task file') +
    _block('b', 'Receives the tasks', '', (list || '<div class="xr-p bad">Nothing arrived: no task could be converted.</div>') + changed + lost +
      '<div class="xr-mono" style="margin-top:8px">' + _esc(data.task_file) + '</div>');
}

function _brokerShell(loop) {
  return _block('b', 'Fetches the evidence', '<span id="bk-st-' + loop + '">Running</span>',
    '<details><summary>Engine log<span class="log-last" id="bk-last-' + loop + '"></span></summary><div class="xr-log xr-mono" id="bk-term-' + loop + '"></div></details>' +
    '<div id="bk-fd-' + loop + '" hidden></div>', 'bk-' + loop);
}

function _stepLine(s) {
  const mk = s.completed ? '<span class="mk ok">✓</span>' : (s.status ? '<span class="mk no">✗</span>' : '<span class="mk wait">-</span>');
  const got = s.confirmed_empty ? 'looked, found nothing' : (s.rows_retrieved != null ? s.rows_retrieved + ' rows' : 'not run');
  const cats = (s.categories || []).length ? ' for ' + s.categories.map(_esc).join(', ') : '';
  return '<div class="xr-step">' + mk + '<div><b>' + _esc(s.family) + '</b>' + cats + ': ' + got + (s.status && !s.completed ? ' (' + _esc(s.status) + ')' : '') + '</div>' +
    '<div class="sub">' + _esc(s.objective) + (s.reason ? '<br>' + _esc(s.reason) : '') + '</div></div>';
}

function _brokerSteps(runs) {
  return runs.map(r => {
    if (!r.run_dir) return '<div class="xr-h">' + _esc(r.task_id) + '</div><div class="xr-p bad">The broker recorded no run for this task.</div>';
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
    return '<details class="task"><summary><b>' + _esc(r.task_id) + '</b> ' + done + '/' + steps.length + ' step' + (steps.length === 1 ? '' : 's') + ' complete' +
        ((r.results || []).some(x => x.error || x.status === 'error') ? ', <span class="xr-p bad">errors</span>' : '') + '</summary>' +
      (r.plan_rationale ? '<div class="xr-p dim">' + _esc(r.plan_rationale) + '</div>' : '') +
      (r.plan_repairs && r.plan_repairs.length ? '<div class="xr-p dim">Guards repaired the plan: ' + r.plan_repairs.map(x => _esc(typeof x === 'string' ? x : JSON.stringify(x))).join('; ') + '</div>' : '') +
      (r.steps || []).map(_stepLine).join('') +
      _details('Why these tools', r.classification ? '<div class="xr-p dim">' + _esc(r.classification) + '</div>' : '') +
      _details('Queries run (' + (r.dispatched || []).map(_esc).join(', ') + ')', queries) +
      (r.spend_micro_usd != null ? '<div class="xr-mono">spend $' + (r.spend_micro_usd / 1e6).toFixed(2) + '</div>' : '') +
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

function _payloadCard(data) {
  const ps = data.payloads || [];
  const body = ps.map(p =>
    '<div class="xr-h">' + _esc(p.task_id) + '</div>' + (p.hypothesis ? '<div class="xr-p dim">' + _esc(p.hypothesis) + '</div>' : '') +
    ((p.findings || []).map(f => {
      const narr = String(f.narrative || '').trim();
      const obs = f.observations || [];
      if (!narr) return '<div class="xr-p dim" style="margin-top:6px"><b>' + _esc(f.domain) + '</b> nothing to describe</div>';
      const first = narr.split(/(?<=[.!?])\s+/)[0];
      const rest = narr.slice(first.length).trim();
      return '<div class="xr-p" style="margin-top:6px"><b>' + _esc(f.domain) + '</b> ' + _esc(first) + '</div>' +
        _details('More (' + obs.length + ' observation' + (obs.length === 1 ? '' : 's') + ')',
          (rest ? '<div class="xr-p dim">' + _esc(rest) + '</div>' : '') +
          (obs.length ? '<div class="xr-mono">' + obs.map(o => '• ' + _esc(o)).join('\n') + '</div>' : ''));
    }).join('') || '<div class="xr-p dim">No domain had evidence to describe.</div>')
  ).join('') || '<div class="xr-p dim">No findings.</div>';
  return _cross('ba', 'sub-analysts send <b>' + ps.length + ' finding set' + (ps.length === 1 ? '' : 's') + '</b>', 'received') +
    _block('a', 'Reads the findings', '', body);
}

function _synthCard(data, reasoning, tokens) {
  const scores = Object.entries(data.hypothesis_scores || {}).map(([id, s]) => {
    const v = Math.max(0, Math.min(100, Number(s) || 0));
    return '<div class="xr-score"><span>' + _esc(id) + '</span><i style="width:' + v + '%"></i><span>' + _esc(s) + '</span></div>';
  }).join('') || '<div class="xr-p dim">No scores.</div>';
  const gaps = (data.evidence_gaps || []).map(g => '<div class="xr-p">' + _esc(g) + '</div>').join('');
  const done = data.status === 'VERDICT_REACHED';
  return _block('a', 'Weighs the hypotheses', _tok(tokens),
    scores +
    '<div class="xr-p ' + (done ? 'ok' : '') + '" style="margin-top:8px;font-weight:650">' + (done ? 'Verdict reached' : 'Needs another loop') + '</div>' +
    (data.verdict_reasoning ? '<div class="xr-h">Why</div><div class="xr-p">' + _esc(data.verdict_reasoning) + '</div>' : '') +
    ((data.evidence_refs || []).length ? '<div class="xr-mono">evidence cited: ' + data.evidence_refs.map(_esc).join(', ') + '</div>' : '') +
    (gaps ? '<div class="xr-h">Still missing</div>' + gaps : '') +
    _details('Reasoning', reasoning ? '<div class="xr-p dim">' + _esc(reasoning) + '</div>' : ''));
}

function _verdict(data, why) {
  // The server sends a verdict event both when the gate passed and when the loop
  // simply ran out (max loops, no follow-ups). Only the first is a decision.
  const decided = data.status === 'VERDICT_REACHED';
  const v = String(data.verdict || 'UNKNOWN').toUpperCase();
  const conf = data.verdict_confidence ?? data.confidence;
  const b = $('verdict');
  b.style.setProperty('--v', decided ? (_VERDICT[v] || 'var(--warn)') : 'var(--warn)');
  b.innerHTML = '<div class="v-label">' + (decided ? _esc(v.replace(/_/g, ' ')) : 'No verdict') + '</div>' +
    '<div class="v-conf">' + (decided ? '' : 'Leaning ' + _esc(v.replace(/_/g, ' ')) + ', but the evidence gate did not pass. Stopped: ' + _esc(why || 'unknown') + '. ') +
      (conf != null ? 'Confidence ' + _esc(conf) + '%' : '') + '</div>' +
    '<div class="v-sum">' + _esc(data.verdict_reasoning || data.reasoning || data.executive_summary || 'The model gave no reasoning for this verdict.') + '</div>';
  b.hidden = false;
  b.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'nearest' });
}

function foldAlert(fold, text) {
  $('alertPanel').classList.toggle('folded', fold);
  $('alertSummary').hidden = !fold;
  if (text != null) $('alertSummaryText').textContent = text;
}

// ── Wire up ────────────────────────────────────────────────────────────────

$('alertForm').addEventListener('submit', investigate);
$('queueRefresh').addEventListener('click', loadQueue);
$('alertEdit').addEventListener('click', () => { foldAlert(false); $('f_rule').focus(); });
$('stages').addEventListener('click', e => { const li = e.target.closest('li[data-stage]'); if (li) _jump(li.dataset.stage); });
$('queueList').addEventListener('click', e => {
  const btn = e.target.closest('button[data-index]');
  if (btn) importAlert(Number(btn.dataset.index), btn);
});
loadQueue();

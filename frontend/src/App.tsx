// SmartOps SOC console: pick an alert, build its context contract, run the whole
// pipeline with one /api/run call, and render it as a five-stage ledger with the
// case (verdict, scores, tasks, run totals) pinned in the right rail.
import { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import { api } from './api';
import { buildContract, observables, type AlertFields } from './contract';
import { shortRule } from './format';
import { outcomeTag, reduce, type RunState, type StageName } from './run';
import type { ImportedAlert, QueueEvent, QueueGroup, StreamEvent } from './types';
import { AlertStrip, type Controls } from './components/AlertStrip';
import { DEV_MAX, DevPanel, devLine, eventLine, type DevLine } from './components/DevPanel';
import { Ledger } from './components/Ledger';
import { eventKey, Overview, Queue, type Seen } from './components/Queue';
import { Meta, Scores, Tasks, Verdict, verdictColor } from './components/Rail';

const EMPTY: AlertFields = { rule_name: '', src_ip: '', dest: '', user: '', hash: '', domain: '', mitre: '', signature: '', deployed_spl: '' };
const POLL_MS = 60_000; // ponytail: fixed poll, each one a Splunk search; push from the server if that load matters

export default function App() {
  // Queue
  const [groups, setGroups] = useState<QueueGroup[] | null>(null);
  const [queueError, setQueueError] = useState<string | null>(null);
  const [intro, setIntro] = useState(true);
  const [openGroup, setOpenGroup] = useState<{ id: string } | null>(null);
  // ponytail: verdicts this session only, lost on reload; persist when a run-history endpoint exists.
  const [seen, setSeen] = useState<Seen>({});
  const [currentKey, setCurrentKey] = useState<string | null>(null);
  // Alert
  const [fields, setFields] = useState<AlertFields>(EMPTY);
  const [imported, setImported] = useState<ImportedAlert | null>(null);
  const [note, setNote] = useState('Select an alert, or enter its fields by hand.');
  // Run
  const [run, dispatch] = useReducer(reduce, null);
  const runRef = useRef<RunState | null>(null);
  runRef.current = run;
  const es = useRef<EventSource | null>(null);
  const lastEvent = useRef<number | null>(null);
  const stopAsked = useRef(false);
  const restartAsked = useRef(false);
  const [stopping, setStopping] = useState(false);
  const [now, setNow] = useState(Date.now());
  // Chrome
  const [conn, setConn] = useState<[string, string]>(['Idle', '']);
  const [devOpen, setDevOpen] = useState(() => { try { return !!localStorage.getItem('devOpen'); } catch { return false; } });
  const [devLines, setDevLines] = useState<DevLine[]>([]);
  const devSearch = useRef<HTMLInputElement>(null);
  const devToggleRef = useRef<HTMLButtonElement>(null);
  const [toastMsg, setToastMsg] = useState<[string, boolean] | null>(null);
  const toastTimer = useRef<number>(0);

  const toast = useCallback((msg: string, bad = false) => {
    setToastMsg([msg, bad]);
    clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToastMsg(null), 5000);
  }, []);
  const log = (l: DevLine) => setDevLines(ls => (ls.length >= DEV_MAX ? [...ls.slice(1), l] : [...ls, l]));
  const ui = (text: string, cls: DevLine['cls'] = '', json?: unknown) => log(devLine('ui', text, runRef.current, cls, json));

  const live = !!run && run.mode !== 'ended';
  const controls: Controls = !run ? 'idle' : run.mode === 'ended' ? 'ended' : stopping ? 'stopping' : run.mode;

  // ── Queue ──
  const loadQueue = useCallback(async (poll = false) => {
    if (!poll) { setGroups(null); setQueueError(null); }
    try {
      const g = await api.queue();
      setGroups(g); setQueueError(null); setIntro(!poll);
    } catch (e) {
      if (!poll) setQueueError((e as Error).message);  // a failed poll keeps the list it has
    }
  }, []);
  useEffect(() => {
    loadQueue();
    const t = setInterval(() => { if (!document.hidden) loadQueue(true); }, POLL_MS);
    return () => clearInterval(t);
  }, [loadQueue]);

  // ponytail: the queue and the import both take "sort -_time | head", so a notable that
  // lands between the two calls shifts the index by one. Import by rule_id/_time if that bites.
  async function importAlert(ev: QueueEvent) {
    if (live) { toast('A run is in progress. Wait for it to finish.', true); return; }
    setCurrentKey(eventKey(ev));
    setNote('Importing the alert from Splunk ES...');
    try {
      const d = await api.importAlert(ev.index);
      setFields({ rule_name: d.rule_name || '', src_ip: d.src || '', dest: d.dest || '', user: d.user || '', hash: d.file_hash || '',
        domain: d.domain || '', mitre: d.mitre || '', signature: d.sig || '', deployed_spl: d.deployed_spl || '' });
      setImported(d);
      setNote(d.deployed_spl ? 'Imported, with the deployed SPL. Investigate when ready.'
        : 'Imported, but no deployed SPL was found for this rule. Paste it under Edit fields for the SPL comparison.');
    } catch (e) {
      setNote('Import failed: ' + (e as Error).message);
      toast('Import failed: ' + (e as Error).message, true);
    }
  }

  // ── Run ──
  function end(text: string, cls: 'live' | 'bad' | 'warn') {
    es.current?.close();
    es.current = null;
    dispatch({ type: 'end', at: Date.now(), text, bad: cls === 'bad' });
    setStopping(false);
    setConn([text, cls]);
    ui(text, cls === 'bad' ? 'bad' : cls === 'warn' ? 'warn' : 'ok');
  }

  async function investigate() {
    if (runRef.current && runRef.current.mode !== 'ended') return;
    const f = Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, v.trim()])) as unknown as AlertFields;
    const raw = (imported?.raw_event_data || {}) as Record<string, any>;
    stopAsked.current = false;
    setStopping(false);
    setDevLines([]);
    dispatch({ type: 'start', at: Date.now(), key: currentKey });
    lastEvent.current = Date.now();
    setConn(['Building context', 'live']);
    ui('Building context: ESCU match and OpenCTI lookup for ' + shortRule(f.rule_name));
    try {
      const [escu, cti] = await Promise.all([api.escu(f.rule_name), api.opencti(observables(f, raw))]);
      const contract = buildContract(f, raw, imported?.event_time || null, escu, cti);
      dispatch({ type: 'context', at: Date.now(), contract, escu, cti });
      ui('Context built', '', { escu, opencti: cti });
      if (stopAsked.current) {
        dispatch({ type: 'event', at: Date.now(), ev: { type: 'stopped', message: '' } });
        return end('Stopped before the run started', 'warn');
      }
      const { run_id } = await api.startRun(contract);
      if (!run_id) throw new Error('The server did not return a run id.');
      dispatch({ type: 'runId', at: Date.now(), id: run_id });
      ui('Run ' + run_id + ' started. Files in .smartops/runs/' + run_id + '/');
      setConn(['Run ' + run_id + ' connecting', 'warn']);
      const source = new EventSource(api.streamUrl(run_id));
      es.current = source;
      source.onopen = () => { setConn(['Run ' + run_id + ' live', 'live']); ui('Live stream connected'); };
      source.onmessage = e => {
        if (es.current !== source) return;
        lastEvent.current = Date.now();
        const msg = JSON.parse(e.data) as StreamEvent;
        log(eventLine(msg, runRef.current));
        dispatch({ type: 'event', at: Date.now(), ev: msg });
        if (msg.type === 'paused') setConn(['Run ' + run_id + ' paused', 'warn']);
        else if (msg.type === 'resumed') setConn(['Run ' + run_id + ' live', 'live']);
        else if (msg.type === 'done') end('Run ' + run_id + ' complete', 'live');
        else if (msg.type === 'error') end('Run ' + run_id + ' failed', 'bad');
        else if (msg.type === 'stopped') end('Run ' + run_id + ' stopped', 'warn');
      };
      // EventSource reconnects by itself and the server keeps the run's queue, so a
      // dropped connection resumes. CLOSED means it gave up (e.g. the server restarted).
      source.onerror = () => {
        if (es.current !== source) return;
        if (source.readyState === EventSource.CLOSED) {
          dispatch({ type: 'fail', at: Date.now(), msg: 'Lost the live stream for run ' + run_id + '. The server may have restarted; the run cannot be resumed.' });
          end('Stream lost', 'bad');
        } else {
          setConn(['Run ' + run_id + ' reconnecting', 'warn']);
          ui('Stream dropped, reconnecting', 'warn');
        }
      };
    } catch (e) {
      dispatch({ type: 'fail', at: Date.now(), msg: (e as Error).message });
      end('Failed before the run started', 'bad');
    }
  }

  async function control(action: 'stop' | 'pause' | 'resume') {
    const id = runRef.current?.id;
    if (!id) return false;
    try { await api.control(id, action); return true; } catch (e) {
      toast('Could not ' + action + ' the run: ' + (e as Error).message, true);
      ui(action + ' failed: ' + (e as Error).message, 'bad');
      return false;
    }
  }

  async function pauseOrResume() {
    if (!run) return;
    if (run.mode === 'paused' || run.mode === 'pausing') {
      ui('Resume requested');
      if (await control('resume')) dispatch({ type: 'mode', mode: 'running', now: 'Resuming' });
    } else {
      ui('Pause requested: holds at the next stage boundary');
      if (await control('pause')) dispatch({ type: 'mode', mode: 'pausing', now: 'Pausing after this step. A model call or broker round in flight finishes first.' });
    }
  }

  async function stop() {
    if (!run) return;
    setStopping(true);
    ui('Stop requested: kills the broker now, or lands when the current model call returns', 'warn');
    dispatch({ type: 'mode', mode: run.mode, now: 'Stopping. A model call in flight finishes first.' });
    if (!run.id) { stopAsked.current = true; return; } // still building context: stops before the run starts
    if (!(await control('stop'))) setStopping(false);
  }

  function restart() {
    ui('Restart requested');
    if (live) { restartAsked.current = true; stop(); return; }
    investigate();
  }

  function reset() {
    if (live) return;
    dispatch({ type: 'reset' });
    setConn(['Idle', '']);
    setIntro(false);
    ui('View reset');
  }

  // A finished (or failed, or stopped) run tags its alert in the queue.
  useEffect(() => {
    const tag = run && outcomeTag(run);
    if (tag && run!.key) setSeen(s => (s[run!.key!]?.tag === tag.tag ? s : { ...s, [run!.key!]: tag }));
  }, [run]);

  // A restart waits for the stop to land, then starts again.
  useEffect(() => {
    if (run?.mode === 'ended' && restartAsked.current) { restartAsked.current = false; investigate(); }
  }, [run?.mode]);

  // The clock: stage timers and "last event" tick while a run is live.
  useEffect(() => {
    if (!live) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [live]);

  // The verdict colours the page (`--v` on body); dev mode reserves the bottom of the page.
  useEffect(() => {
    const c = verdictColor(run);
    if (c) document.body.style.setProperty('--v', c); else document.body.style.removeProperty('--v');
  }, [run?.verdict, run?.failed, run === null]);
  useEffect(() => {
    document.body.classList.toggle('dev-open', devOpen);
    try { localStorage.setItem('devOpen', devOpen ? '1' : ''); } catch { /* storage blocked: not remembered */ }
  }, [devOpen]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey && !e.shiftKey && !e.altKey && !e.metaKey && e.key.toLowerCase() === 'd') { e.preventDefault(); setDevOpen(o => !o); return; }
      if (!devOpen) return;
      if (e.key === 'Escape') { setDevOpen(false); devToggleRef.current?.focus(); }
      else if (e.key === '/' && !/INPUT|TEXTAREA/.test((document.activeElement as HTMLElement)?.tagName)) { e.preventDefault(); devSearch.current?.focus(); }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [devOpen]);

  return <>
    <header className="topbar">
      <h1 className="brand"><i className="ph-bold ph-shield-chevron" aria-hidden="true" />SmartOps SOC</h1>
      <span className="topbar-sub">Alert investigation</span>
      <span className={'conn' + (conn[1] ? ' ' + conn[1] : '')} role="status" aria-live="polite">{conn[0]}</span>
      <button ref={devToggleRef} className="dev-btn" type="button" title="Dev mode: the run's live log" onClick={() => setDevOpen(o => !o)}>
        <i className="ph ph-terminal-window" aria-hidden="true" />Dev<kbd>Ctrl D</kbd>
      </button>
    </header>

    <div className="shell">
      <Queue groups={groups} error={queueError} intro={intro} seen={seen} current={currentKey} running={live}
        openGroup={openGroup} onPick={importAlert} onRefresh={() => loadQueue()} />

      <AlertStrip fields={fields} setFields={setFields} imported={imported} note={note} controls={controls}
        onInvestigate={investigate} onPause={pauseOrResume} onStop={stop} onRestart={restart} onReset={reset} toast={toast} />

      <Verdict run={run} />

      <main className="ledger-wrap" aria-label="Investigation">
        {run
          ? <Ledger run={run} now={now} onToggle={(stage: StageName, open: boolean) => dispatch({ type: 'toggle', stage, open })} />
          : groups?.length ? <Overview groups={groups} seen={seen} intro={intro} onGroup={id => setOpenGroup({ id })} onPick={importAlert} /> : null}
      </main>

      <aside className="rail" aria-label="Case summary">
        <section className="rail-sec" aria-labelledby="scoresTitle"><h2 id="scoresTitle">Hypotheses</h2><Scores run={run} /></section>
        <section className="rail-sec" aria-labelledby="tasksTitle"><h2 id="tasksTitle">Tasks</h2><Tasks run={run} now={now} /></section>
        <section className="rail-sec" aria-labelledby="runTitle"><h2 id="runTitle">Run</h2><Meta run={run} now={now} lastEvent={lastEvent.current} /></section>
      </aside>
    </div>

    {devOpen ? <DevPanel lines={devLines} run={run} now={now} onClose={() => setDevOpen(false)} toast={toast} searchRef={devSearch} /> : null}
    {toastMsg ? <div className={'toast' + (toastMsg[1] ? ' bad' : '')} role="status">{toastMsg[0]}</div> : null}
  </>;
}

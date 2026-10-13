// One investigation's state, driven by actions: the UI's own steps (start, context
// built, run id) and every SSE event from /api/run/stream. Pure: `at` is passed in.
import type { Contract } from './contract';
import { domState, plural, shortId, VERDICT_COLOR, VERDICT_TAG, type DomState } from './format';
import type {
  BrokerRun, CtiResult, CutOff, EscuResult, Handoff, Handshake, Plan, PayloadBatch, StreamEvent, Synthesis, Tokens,
} from './types';

export const STAGES = ['context', 'plan', 'broker', 'findings', 'synthesis'] as const;
export type StageName = (typeof STAGES)[number];
export const STAGE_LABEL: Record<StageName, string> = { context: 'Context', plan: 'Plan', broker: 'Evidence', findings: 'Findings', synthesis: 'Synthesis' };
export type StageStatus = '' | 'active' | 'done' | 'failed' | 'undecided';

export type Item =
  | { kind: 'context'; contract: Contract; escu: EscuResult; cti: CtiResult }
  | { kind: 'plan'; plan: Plan; tokens?: Tokens; usable: boolean }
  | { kind: 'loop'; n: number }
  | { kind: 'handoff'; loop: number; data: Handoff }
  | { kind: 'broker'; loop: number; lines: string[]; runs?: BrokerRun[]; state: 'Running' | 'Done' | 'Failed' }
  | { kind: 'handshake'; h: Handshake }
  | { kind: 'payload'; data: PayloadBatch }
  | { kind: 'synthesis'; data: Synthesis; reasoning?: string; tokens?: Tokens }
  | { kind: 'error'; msg: string };

export interface Stage { status: StageStatus; start?: number; end?: number; sum: string; items: Item[]; open: boolean }
// What the Broker log says about one tool result while the round is still running.
export interface LiveResult { family: string; status: string; rows: number; queries: number }
export type TaskPhase = 'queued' | 'fetching' | 'fetched' | 'failed';
export interface TaskRow {
  id: string; q: string; steps: string | null; rows: number | null; spend: number; rejected: number;
  dom: Record<string, DomState>; noRun?: boolean;
  phase: TaskPhase; startedAt?: number; live: LiveResult[];
}
export type Mode = 'running' | 'pausing' | 'paused' | 'ended';

export interface RunState {
  key: string | null; id?: string; started: number; ended?: number; mode: Mode; status: string;
  stages: Record<StageName, Stage>; current: StageName; now: string;
  contract?: Contract; plan?: Plan; tasks: TaskRow[];
  spend: number; tokIn: number; tokOut: number; loops: number;
  prevScores: Record<string, number | string>; curScores: Record<string, number | string>;
  verdict?: { data: Synthesis; why: string; decided: boolean };
  failed?: string; stopped?: boolean; cutOff?: CutOff;
}

export type Action =
  | { type: 'start'; at: number; key: string | null }
  | { type: 'context'; at: number; contract: Contract; escu: EscuResult; cti: CtiResult }
  | { type: 'runId'; at: number; id: string }
  | { type: 'event'; at: number; ev: StreamEvent }
  | { type: 'fail'; at: number; msg: string }
  | { type: 'mode'; mode: Mode; now?: string }
  | { type: 'end'; at: number; text: string; bad: boolean }
  | { type: 'toggle'; stage: StageName; open: boolean } // the reader opened or folded a stage
  | { type: 'reset' };

const emptyStage = (): Stage => ({ status: '', sum: '', items: [], open: false });

export function newRun(at: number, key: string | null): RunState {
  const stages = Object.fromEntries(STAGES.map(s => [s, emptyStage()])) as Record<StageName, Stage>;
  return {
    key, started: at, mode: 'running', status: 'Building context', stages, current: 'context', now: '',
    tasks: [], spend: 0, tokIn: 0, tokOut: 0, loops: 0, prevScores: {}, curScores: {},
  };
}

// One stage active at a time; earlier ones done. The active stage opens; nothing folds
// on its own, so the page never shifts under the reader.
function setStage(r: RunState, name: StageName, at: number, st?: StageStatus): RunState {
  const idx = STAGES.indexOf(name);
  const stages = { ...r.stages };
  STAGES.forEach((s, i) => {
    const old = stages[s];
    const status: StageStatus = i < idx ? 'done' : i === idx ? (st || 'active') : (old.status === 'done' || old.status === 'active' ? 'done' : '');
    const start = i === idx && !old.start ? at : old.start;
    const end = status === 'active' ? undefined : start && !old.end ? at : old.end;
    stages[s] = { ...old, status, start, end, open: old.open || status === 'active' || status === 'failed' };
  });
  return { ...r, stages, current: name };
}

function setSum(r: RunState, name: StageName, sum: string): RunState {
  const st = r.stages[name];
  const live = r.mode !== 'ended' && (st.status === 'active' || st.status === 'failed');
  return { ...r, stages: { ...r.stages, [name]: { ...st, sum } }, now: live ? sum : r.now, current: live ? name : r.current };
}

const add = (r: RunState, name: StageName, ...items: Item[]): RunState =>
  ({ ...r, stages: { ...r.stages, [name]: { ...r.stages[name], items: [...r.stages[name].items, ...items] } } });

const loopHeader = (loop: number): Item[] => (loop > 2 ? [{ kind: 'loop', n: loop - 1 }] : []);

const addTokens = (r: RunState, t?: Tokens): RunState =>
  t ? { ...r, tokIn: r.tokIn + (t.prompt_tokens || 0), tokOut: r.tokOut + (t.generation_tokens || 0) } : r;

// The open broker card of a loop, created on first use.
function withBroker(r: RunState, loop: number, f: (b: Extract<Item, { kind: 'broker' }>) => Item): RunState {
  const items = r.stages.broker.items;
  const i = items.findIndex(x => x.kind === 'broker' && x.loop === loop);
  const b = (i >= 0 ? items[i] : { kind: 'broker', loop, lines: [], state: 'Running' }) as Extract<Item, { kind: 'broker' }>;
  const next = i >= 0 ? items.map((x, j) => (j === i ? f(b) : x)) : [...items, f(b)];
  return { ...r, stages: { ...r.stages, broker: { ...r.stages.broker, items: next } } };
}

export function fail(r: RunState, msg: string, at: number): RunState {
  const stage = r.current;
  r = setStage({ ...r, failed: msg }, stage, at, 'failed');
  r = setSum(r, stage, msg);
  return add(r, stage, { kind: 'error', msg });
}

// The Broker CLI's progress markers (smartops/main.py `_run_round`): a task starting, each tool
// result, a task's spend line, the sub-analysts starting. Everything else stays in the engine log.
const FETCHING = /^fetching (\d+)\/(\d+): (\S+)/;
const RESULT = /^\s*\[(\w+)\s*\]\s+(\w+)\s+(.*?)\s*(?:\((\d+) quer(?:y|ies)\))?\s*$/;
const SPENT = /^this task: (\d+) micro-USD/;
const ANALYSING = /^analysing (\d+) task\(s\)/;

function brokerLine(r: RunState, line: string, at: number): RunState {
  const tasks = r.tasks;
  const active = tasks.find(t => t.phase === 'fetching');
  const patch = (id: string | undefined, f: (t: TaskRow) => TaskRow) => tasks.map(t => (t.id === id ? f(t) : t));
  let m: RegExpExecArray | null;
  if ((m = FETCHING.exec(line))) {
    const id = m[3];
    const next = tasks.map(t => t.id === id ? { ...t, phase: 'fetching' as const, startedAt: at } : t.phase === 'fetching' ? { ...t, phase: 'fetched' as const } : t);
    const q = next.find(t => t.id === id)?.q || '';
    return { ...r, tasks: next, current: 'broker', now: 'Fetching ' + shortId(id) + ' (' + m[1] + ' of ' + m[2] + '): ' + q };
  }
  if (active && (m = RESULT.exec(line))) {
    // "connections:27 processes:4 discovery:1": discovery is the index probe, not evidence.
    const rows = [...m[3].matchAll(/(\w+):(\d+)/g)].filter(x => x[1] !== 'discovery').reduce((n, x) => n + Number(x[2]), 0);
    const res: LiveResult = { family: m[2], status: m[1], rows, queries: Number(m[4] || 0) };
    return { ...r, tasks: patch(active.id, t => ({ ...t, live: [...t.live, res] })) };
  }
  if (active && (m = SPENT.exec(line))) return { ...r, tasks: patch(active.id, t => ({ ...t, phase: 'fetched', spend: Number(m![1]) })) };
  if (active && /^error: the investigation failed/.test(line)) return { ...r, tasks: patch(active.id, t => ({ ...t, phase: 'failed' })) };
  if ((m = ANALYSING.exec(line))) {
    r = setStage({ ...r, tasks: tasks.map(t => (t.phase === 'fetching' ? { ...t, phase: 'fetched' as const } : t)) }, 'findings', at);
    return setSum(r, 'findings', 'Sub-analysts are describing the evidence for ' + plural(Number(m[1]), 'task'));
  }
  return r;
}

function onEvent(r: RunState, ev: StreamEvent, at: number): RunState {
  const loop = 'loop' in ev ? ev.loop || 1 : 1;
  switch (ev.type) {
    case 'analyst': {
      r = setStage(r, 'plan', at);
      const plan = ev.data || {};
      if (!Object.keys(plan).length) return r;
      r = addTokens({ ...r, plan }, ev.tokens);
      const tasks = plan.tasks || [];
      if (!tasks.length && plan.status === 'VERDICT_REACHED') {
        return setSum(add(r, 'plan', { kind: 'plan', plan, tokens: ev.tokens, usable: true }), 'plan', 'Verdict reached while planning, no evidence fetched');
      }
      // A plan without tasks reaches the broker as nothing: say so here, where it went wrong.
      if (!tasks.length) {
        r = setStage(r, 'plan', at, 'failed');
        return setSum(add(r, 'plan', { kind: 'plan', plan, tokens: ev.tokens, usable: false }), 'plan', 'No usable plan: nothing to send to the Tool Broker');
      }
      const al = plan.semantic_alignment ? (plan.semantic_alignment === 'ALIGNED' ? ', deployed SPL aligned' : ', deployed SPL not aligned') : '';
      return setSum(add(r, 'plan', { kind: 'plan', plan, tokens: ev.tokens, usable: true }), 'plan',
        plural((plan.hypotheses || []).length, 'hypothesis', 'hypotheses') + ', ' + plural(tasks.length, 'task') + al);
    }
    case 'handoff': {
      r = setStage(r, 'broker', at);
      const tasks = ev.data.tasks || [];
      const lost = (ev.data.dropped || []).filter(d => !d.sent).length;
      // A one-task round prints no "fetching 1/1" line, so its task is fetching from the start.
      const solo = tasks.length === 1;
      r = { ...r, loops: loop, tasks: tasks.map(t => ({ id: t.task_id, q: t.question, steps: null, rows: null, spend: 0, rejected: 0, dom: {},
        phase: solo ? 'fetching' as const : 'queued' as const, startedAt: solo ? at : undefined, live: [] })) };
      r = add(r, 'broker', ...loopHeader(loop), { kind: 'handoff', loop, data: ev.data });
      r = setSum(r, 'broker', plural(tasks.length, 'task') + ' sent' + (lost ? ', ' + lost + ' not sent' : '') + ', fetching');
      return solo ? { ...r, now: 'Fetching ' + shortId(tasks[0].task_id) + ': ' + tasks[0].question } : r;
    }
    case 'broker_log': {
      // The log keeps flowing while the sub-analysts work: never step back from Findings.
      if (r.current !== 'findings') r = setStage(r, 'broker', at);
      // ponytail: copies the loop's line array per line; fine for a few thousand lines per round.
      r = withBroker(r, loop, b => ({ ...b, lines: [...b.lines, ev.data.line || ''] }));
      return brokerLine(r, ev.data.line || '', at);
    }
    case 'broker': {
      const runs = ev.data.runs || [];
      const h = ev.data.handshake;
      r = withBroker(r, loop, b => ({ ...b, runs, state: 'Done' }));
      if (h) r = add(r, 'broker', { kind: 'handshake', h });
      let done = 0, all = 0, spend = 0;
      const tasks = r.tasks.map(t => ({ ...t }));
      runs.forEach(run => {
        const steps = run.steps || [];
        done += steps.filter(s => s.completed).length; all += steps.length; spend += run.spend_micro_usd || 0;
        const t = tasks.find(x => x.id === run.task_id);
        if (t) Object.assign(t, {
          steps: steps.filter(s => s.completed).length + '/' + steps.length,
          rows: steps.reduce((n, s) => n + (s.rows_retrieved || 0), 0), spend: run.spend_micro_usd || 0,
          rejected: steps.filter(s => s.status === 'rejected').length, noRun: !run.run_dir,
        });
      });
      r = { ...r, tasks, spend: r.spend + spend };
      const broken = h ? h.not_fetched.length + h.not_returned.length + h.unexpected.length : 0;
      r = setSum(r, 'broker', (h?.returned || []).length + ' of ' + (h?.sent || []).length + ' tasks returned, ' + done + '/' + all +
        ' steps complete, $' + (spend / 1e6).toFixed(2) + (broken ? ', handshake broken' : ''));
      return broken ? setStage(r, 'broker', at, 'failed') : r;
    }
    case 'payload': {
      r = setStage(r, 'findings', at);
      r = add(r, 'findings', ...loopHeader(loop), { kind: 'payload', data: ev.data });
      let described = 0, failed = 0;
      const tasks = r.tasks.map(t => ({ ...t, dom: { ...t.dom } }));
      (ev.data.payloads || []).forEach(p => {
        const t = tasks.find(x => x.id === p.task_id);
        (p.findings || []).forEach(f => {
          const s = domState(f);
          if (s === 'ok') described++; else if (s === 'bad') failed++;
          if (t) t.dom[f.domain] = s;
        });
      });
      return setSum({ ...r, tasks }, 'findings', plural((ev.data.payloads || []).length, 'finding set') + ', ' +
        plural(described, 'domain description') + (failed ? ', ' + failed + ' failed to parse' : ''));
    }
    case 'synthesis': {
      r = setStage(r, 'synthesis', at);
      const d = ev.data || {};
      if (!d.status) return setSum(r, 'synthesis', 'Analyst is weighing the findings');
      r = addTokens(r, ev.tokens);
      r = add(r, 'synthesis', ...loopHeader(loop), { kind: 'synthesis', data: d, reasoning: ev.reasoning, tokens: ev.tokens });
      const top = Object.entries(d.hypothesis_scores || {}).sort((a, b) => Number(b[1]) - Number(a[1]))[0];
      r = { ...r, prevScores: r.curScores, curScores: d.hypothesis_scores || {} };
      return setSum(r, 'synthesis', (top ? top[0] + ' scores ' + top[1] + ', ' : '') + (d.status === 'VERDICT_REACHED' ? 'verdict reached' : 'needs another loop'));
    }
    case 'verdict': {
      // Sent both when the gate passed and when the loop ran out: only the first is a decision.
      const decided = ev.data.status === 'VERDICT_REACHED';
      if (r.stages.synthesis.status === 'active') r = setStage(r, 'synthesis', at, decided ? 'done' : 'undecided');
      else STAGES.forEach(s => { if (r.stages[s].status === 'active') r = setStage(r, s, at, 'done'); });
      // The banner now carries the case, so the ledger folds to the run's last word.
      const last = [...STAGES].reverse().find(s => r.stages[s].items.length);
      const stages = { ...r.stages };
      STAGES.forEach(s => { stages[s] = { ...stages[s], open: s === last || stages[s].status === 'failed' }; });
      return {
        ...r, stages, verdict: { data: ev.data, why: ev.message, decided },
        curScores: ev.data.hypothesis_scores || r.curScores,
        status: decided ? 'Verdict reached' : 'Stopped without a verdict',
      };
    }
    case 'paused': return { ...r, mode: 'paused', status: 'Paused', now: 'Paused. Resume to continue, or Stop.' };
    case 'resumed': return { ...r, mode: 'running', status: 'Running', now: 'Resumed' };
    case 'stopped': {
      r = setStage({ ...r, stopped: true, status: 'Stopped' }, r.current, at, 'undecided');
      return setSum(r, r.current, 'Stopped by the analyst');
    }
    case 'error': {
      // A broker card still running stops saying so. The error event has no `loop`, so match by state.
      const items = r.stages.broker.items.map(x => (x.kind === 'broker' && x.state === 'Running' ? { ...x, state: 'Failed' as const } : x));
      r = { ...r, stages: { ...r.stages, broker: { ...r.stages.broker, items } }, cutOff: ev.cut_off };
      return fail(r, ev.message || 'The pipeline stopped with an error.', at);
    }
    default: return r;
  }
}

export function reduce(r: RunState | null, a: Action): RunState | null {
  if (a.type === 'start') {
    const s = setStage(newRun(a.at, a.key), 'context', a.at);
    return setSum(s, 'context', 'Matching ESCU and asking OpenCTI');
  }
  if (!r || a.type === 'reset') return null;
  switch (a.type) {
    case 'context': {
      const n = Object.keys(a.cti.results || {});
      const failed = n.filter(k => JSON.stringify(a.cti.results![k]).includes('"error"'));
      const top = a.escu.matches?.[0];
      const t = a.contract.normalized_seed.event_time as string | undefined;
      const sum = (top ? 'ESCU: ' + top.rule : 'No ESCU match') + ', OpenCTI ' +
        (a.cti.status === 'unavailable' ? 'unavailable' : n.length ? (n.length - failed.length) + ' of ' + n.length + ' lookups answered' : 'not asked') +
        (t ? ', event at ' + t.slice(11, 19) + ' UTC' : '');
      return setSum(add({ ...r, contract: a.contract }, 'context', { kind: 'context', contract: a.contract, escu: a.escu, cti: a.cti }), 'context', sum);
    }
    case 'runId': {
      const s = setStage({ ...r, id: a.id, status: 'Running' }, 'plan', a.at);
      return setSum(s, 'plan', 'Analyst is planning. A cold model can take a few minutes.');
    }
    case 'event': return onEvent(r, a.ev, a.at);
    case 'fail': return fail(r, a.msg, a.at);
    case 'mode': return { ...r, mode: a.mode, now: a.now ?? r.now };
    case 'toggle': return { ...r, stages: { ...r.stages, [a.stage]: { ...r.stages[a.stage], open: a.open } } };
    case 'end': {
      const status = a.bad ? a.text.replace(/^Run \S+ /, '').replace(/^./, c => c.toUpperCase()) : r.status === 'Running' ? 'Complete' : r.status;
      return { ...r, mode: 'ended', ended: a.at, status, now: a.bad || r.stopped ? a.text : 'Finished in ' + Math.round((a.at - r.started) / 1000) + 's' };
    }
  }
  return r;
}

// The queue tag a finished run leaves on its alert: verdict, NO VERDICT, STOPPED or FAILED.
export function outcomeTag(r: RunState): { tag: string; color: string } | null {
  if (r.verdict) {
    const v = String(r.verdict.data.verdict || 'UNKNOWN').toUpperCase();
    const color = r.verdict.decided ? VERDICT_COLOR[v] || 'var(--warn)' : 'var(--warn)';
    return { tag: r.verdict.decided ? VERDICT_TAG[v] || v : 'NO VERDICT', color };
  }
  if (r.stopped) return { tag: 'STOPPED', color: 'var(--faint)' };
  if (r.cutOff) return { tag: 'CUT OFF', color: 'var(--bad)' };
  if (r.failed) return { tag: 'FAILED', color: 'var(--faint)' };
  return null;
}

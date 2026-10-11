import { expect, test } from 'vitest';
import { outcomeTag, reduce, type Action, type RunState } from './run';
import type { StreamEvent } from './types';

const run = (...actions: Action[]) => actions.reduce<RunState | null>(reduce, null)!;
let t = 0;
const ev = (e: StreamEvent): Action => ({ type: 'event', at: (t += 1000), ev: e });

const plan = { hypotheses: [{ id: 'H1', verdict: 'TRUE_POSITIVE' }, { id: 'H2', verdict: 'BENIGN' }], tasks: [{ task_id: 'T1' }] };
const task = { task_id: 'r-L2-T1', hypothesis_id: 'r-L2-T1', question: 'q', entity: [], time_window: { start: 'a', end: 'b' } };
const hs = { sent: ['r-L2-T1'], fetched: ['r-L2-T1'], returned: ['r-L2-T1'], not_fetched: [], not_returned: [], unexpected: [] };

const happy: Action[] = [
  { type: 'start', at: 0, key: 'k' },
  { type: 'runId', at: 500, id: 'r' },
  ev({ type: 'analyst', data: plan, message: '', tokens: { prompt_tokens: 10, generation_tokens: 5 } }),
  ev({ type: 'handoff', data: { tasks: [task], dropped: [], task_file: 'f' }, message: '', loop: 2 }),
  ev({ type: 'broker_log', data: { line: 'fetching' }, message: '', loop: 2 }),
  ev({ type: 'broker', data: { runs: [{ task_id: 'r-L2-T1', run_dir: 'd', spend_micro_usd: 1_500_000,
    steps: [{ step_id: 's', family: 'siem', objective: 'o', completed: true, rows_retrieved: 7 }] }], handshake: hs }, message: '', loop: 2 }),
  ev({ type: 'payload', data: { payloads: [{ task_id: 'r-L2-T1', hypothesis_id: 'x', findings: [{ domain: 'endpoint', narrative: 'saw it' }] }] }, message: '', loop: 2 }),
  ev({ type: 'synthesis', data: { status: 'VERDICT_REACHED', hypothesis_scores: { H1: 95, H2: 20 } }, message: '', loop: 2 }),
  ev({ type: 'verdict', data: { status: 'VERDICT_REACHED', verdict: 'TRUE_POSITIVE' }, message: 'VERDICT' }),
];

test('a full run ends in a decided verdict, every stage done', () => {
  const r = run(...happy);
  expect(Object.values(r.stages).map(s => s.status)).toEqual(['done', 'done', 'done', 'done', 'done']);
  expect(r.tasks[0]).toMatchObject({ steps: '1/1', rows: 7, dom: { endpoint: 'ok' } });
  expect(r.spend).toBe(1_500_000);
  expect(r.tokIn).toBe(10);
  expect(r.stages.broker.items.find(i => i.kind === 'broker')).toMatchObject({ lines: ['fetching'], state: 'Done' });
  expect(r.stages.synthesis.open).toBe(true);
  expect(outcomeTag(r)).toEqual({ tag: 'TP', color: 'var(--bad)' });
});

test('a run that ran out of loops is no verdict, not a decision', () => {
  const r = run(...happy.slice(0, -1), ev({ type: 'verdict', data: { status: 'REQUIRES_INVESTIGATION', verdict: 'BENIGN' }, message: 'Max loops reached' }));
  expect(r.stages.synthesis.status).toBe('undecided');
  expect(outcomeTag(r)?.tag).toBe('NO VERDICT');
});

test('a broker error fails the current stage and marks its card', () => {
  const r = run(...happy.slice(0, 5), ev({ type: 'error', message: 'Loop 2 broker failed: broker exited 2' }));
  expect(r.stages.broker.status).toBe('failed');
  expect(r.stages.broker.items.find(i => i.kind === 'broker')).toMatchObject({ state: 'Failed' });
  expect(r.stages.broker.items.at(-1)).toMatchObject({ kind: 'error' });
  expect(outcomeTag(r)?.tag).toBe('FAILED');
});

test('a plan with no tasks fails the plan stage', () => {
  const r = run(happy[0], happy[1], ev({ type: 'analyst', data: { reasoning: 'hmm' }, message: '' }));
  expect(r.stages.plan.status).toBe('failed');
  expect(r.stages.plan.items[0]).toMatchObject({ kind: 'plan', usable: false });
});

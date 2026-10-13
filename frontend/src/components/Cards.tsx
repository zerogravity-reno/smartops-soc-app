// One card per ledger item. Every value is alert, log or model text (attacker-
// influenced), and React escapes it; nothing here uses dangerouslySetInnerHTML.
import type { ReactNode } from 'react';
import type { Contract } from '../contract';
import { CODE_HEADERS, domState, explain, plural, shortId, VERDICT_COLOR, type DomState } from '../format';
import type { Item } from '../run';
import type { BrokerRun, CtiResult, DomainFinding, EscuResult, Handoff, Handshake, Plan, PayloadBatch, Step, Synthesis, Tokens } from '../types';

const tok = (t?: Tokens) => (t ? (t.prompt_tokens || 0) + ' in / ' + (t.generation_tokens || 0) + ' out' : '');

function Card({ lane, title, meta, children, id }: { lane: 'a' | 'b'; title: ReactNode; meta?: ReactNode; children: ReactNode; id?: string }) {
  return (
    <div className={'card ' + lane} id={id}>
      <div className="card-title">
        <span className="actor">{lane === 'a' ? 'Analyst' : 'Tool Broker'}</span>{title}
        {meta ? <span className="card-meta">{meta}</span> : null}
      </div>
      {children}
    </div>
  );
}

export function Details({ label, children, open, className, id }: { label: ReactNode; children: ReactNode; open?: boolean; className?: string; id?: string }) {
  if (!children) return null;
  return <details className={className} open={open} id={id}><summary>{label}</summary>{children}</details>;
}

const P = ({ cls, children }: { cls?: string; children: ReactNode }) => <div className={'xr-p' + (cls ? ' ' + cls : '')}>{children}</div>;
const H = ({ children }: { children: ReactNode }) => <div className="xr-h">{children}</div>;
const Chips = ({ xs }: { xs?: unknown[] }) => <div className="chips">{(xs || []).filter(Boolean).map((x, i) => <span className="chip" key={i}>{String(x)}</span>)}</div>;
const Reasoning = ({ text }: { text?: string }) => <Details label="Full reasoning">{text ? <P cls="dim">{text}</P> : null}</Details>;
const json = (v: unknown) => JSON.stringify(v, null, 2);

function ContextCard({ contract, escu, cti }: { contract: Contract; escu: EscuResult; cti: CtiResult }) {
  const ec = contract.escu_context;
  const res = cti.results || {};
  const keys = Object.keys(res);
  const failed = keys.filter(k => JSON.stringify(res[k]).includes('"error"'));
  const down = cti.status === 'unavailable';
  const fps = (ec.known_false_positives || []).filter(Boolean);
  const section = (title: string, xs: unknown[]) => (xs || []).length ? <><H>{title}</H><Chips xs={xs} /></> : null;
  return (
    <Card lane="a" title="Context">
      <H>ESCU matches</H>
      {(escu.matches || []).length
        ? escu.matches!.map((m, i) => <P key={i}>{m.rule} <span className="dim">score {Number(m.score).toFixed(1)}</span></P>)
        : <P cls="dim">No ESCU rule matched this name.</P>}
      {ec.description ? <P cls="dim">{ec.description}</P> : null}
      {section('MITRE', ec.mitre_techniques)}
      {section('Analytic stories', ec.analytic_story)}
      {section('Data sources', ec.data_sources)}
      {fps.length ? <><H>Known false positives (ESCU)</H>{fps.map((f, i) => <P key={i}>{String(f)}</P>)}</> : null}
      <H>OpenCTI</H>
      <P cls={failed.length || down ? 'bad' : ''}>
        {down ? 'Threat intel unavailable: ' + (cti.message || 'OpenCTI did not answer')
          : keys.length ? (failed.length ? failed.length + ' of ' + keys.length + ' lookups failed (OpenCTI unreachable or timing out)' : keys.length + ' lookups answered')
          : 'No observables to look up'}
      </P>
      <details className="raw"><summary>Raw context sent to the pipeline</summary>
        <H>Context contract</H><pre>{json(contract)}</pre>
        <H>ESCU match</H><pre>{json(escu)}</pre>
        <H>OpenCTI lookup</H><pre>{json(cti)}</pre>
      </details>
    </Card>
  );
}

function Alignment({ plan, contract }: { plan: Plan; contract?: Contract }) {
  if (!plan.semantic_alignment) return null;
  const ok = plan.semantic_alignment === 'ALIGNED';
  const ri = contract?.rule_intent;
  return <>
    <H>Deployed SPL vs ESCU reference</H>
    <P cls={ok ? 'ok' : 'bad'}><b>{ok ? 'Aligned' : 'Not aligned'}</b></P>
    {plan.alignment_reasoning ? <P cls="dim">{plan.alignment_reasoning}</P> : null}
    <Details label="Compare the two SPLs">
      <div className="xr-spl">
        <div><H>Deployed</H><pre>{ri?.deployed_spl}</pre></div>
        <div><H>Reference</H><pre>{ri?.reference_spl}</pre></div>
      </div>
    </Details>
  </>;
}

function PlanCard({ plan, tokens, usable, contract }: { plan: Plan; tokens?: Tokens; usable: boolean; contract?: Contract }) {
  if (!usable) return (
    <Card lane="a" title="Plan" meta={tok(tokens)}>
      <P cls="bad">The Analyst answered without a usable plan (no tasks{plan.hypotheses ? '' : ', no hypotheses, no JSON'}), so there is nothing to send to the Tool Broker.</P>
      <Details label="What the model said" open>{plan.reasoning ? <P cls="dim">{plan.reasoning}</P> : null}</Details>
    </Card>
  );
  return (
    <Card lane="a" title="Plan" meta={tok(tokens)}>
      {plan.model_reasoning ? <P cls="dim">{plan.model_reasoning}</P> : null}
      <H>Hypotheses</H>
      {(plan.hypotheses || []).length ? plan.hypotheses!.map((h, i) => (
        <P key={i}><b style={{ color: VERDICT_COLOR[h.verdict || ''] || 'inherit' }}>{h.id} {String(h.verdict || '').replace(/_/g, ' ').toLowerCase()}</b> {h.description}</P>
      )) : <P cls="dim">No hypotheses in the plan.</P>}
      <Alignment plan={plan} contract={contract} />
      <Reasoning text={plan.reasoning} />
    </Card>
  );
}

function HandoffCard({ data }: { data: Handoff }) {
  const tasks = data.tasks || [];
  // `dropped` also carries notes on tasks that were sent changed (narrowed, or re-scoped to the alert).
  const notes = (data.dropped || []).filter(d => d.sent);
  const lost = (data.dropped || []).filter(d => !d.sent);
  return (
    <Card lane="b" title={'Handoff, ' + plural(tasks.length, 'task')} meta={lost.length ? lost.length + ' not sent' : ''}>
      {tasks.length ? tasks.map(t => (
        <div key={t.task_id}>
          <P><b>{shortId(t.task_id)}</b> {t.question}</P>
          <div className="xr-mono">{(t.entity || []).map(e => e.type + '=' + e.value).join('  ')}   {t.time_window?.start} to {t.time_window?.end}</div>
        </div>
      )) : <P cls="bad">Nothing arrived: no task could be converted.</P>}
      {notes.map((d, i) => <P key={'n' + i} cls="dim"><b>{shortId(d.task_id) || 'Task'}</b> sent changed: {d.why}</P>)}
      {lost.map((d, i) => <div key={'l' + i}>
        <P cls="bad"><b>{shortId(d.task_id) || 'Task'}</b> not sent: {d.why}</P>
        {d.question ? <P cls="dim">{d.question}</P> : null}
      </div>)}
      <div className="xr-mono">{data.task_file}</div>
    </Card>
  );
}

const lineClass = (t: string) => /\[ok|success/i.test(t) ? 'l-ok' : /\[rejected|\[error|ERROR/i.test(t) ? 'l-bad'
  : /task|\[T\d/i.test(t) ? 'l-task' : /subagent|agent/i.test(t) ? 'l-agent' : undefined;

function StepLine({ s }: { s: Step }) {
  const mk = s.completed ? <span className="mk ok">done</span>
    : s.status ? <span className="mk no">{s.status === 'rejected' ? 'rejected' : 'failed'}</span> : <span className="mk wait">skipped</span>;
  const got = s.confirmed_empty ? 'looked, found nothing' : s.rows_retrieved != null ? s.rows_retrieved + ' rows' : 'not run';
  return (
    <div className="xr-step">{mk}
      <div><b>{s.family}</b>{(s.categories || []).length ? ' for ' + s.categories!.join(', ') : ''}: {got}{s.status && !s.completed ? ' (' + s.status + ')' : ''}</div>
      <div className="sub">{s.objective}{s.reason ? <><br />{s.reason}</> : null}</div>
    </div>
  );
}

function BrokerRunView({ r }: { r: BrokerRun }) {
  if (!r.run_dir) return <details className="task" id={'task-' + r.task_id}><summary><b>{shortId(r.task_id)}</b> <span className="xr-p bad">no run recorded</span></summary></details>;
  const steps = r.steps || [];
  const results = r.results || [];
  return (
    <details className="task" id={'task-' + r.task_id}>
      <summary><b>{shortId(r.task_id)}</b> {steps.filter(s => s.completed).length}/{plural(steps.length, 'step')} complete
        {r.spend_micro_usd != null ? ', $' + (r.spend_micro_usd / 1e6).toFixed(2) : ''}
        {results.some(x => x.error || x.status === 'error') ? <>, <span className="xr-p bad">errors</span></> : null}
      </summary>
      {r.plan_rationale ? <P cls="dim">{r.plan_rationale}</P> : null}
      {(r.plan_repairs || []).length ? <P cls="dim">Guards repaired the plan: {r.plan_repairs!.map(x => (typeof x === 'string' ? x : JSON.stringify(x))).join('; ')}</P> : null}
      {steps.map(s => <StepLine key={s.step_id} s={s} />)}
      <Details label="Why these tools">{r.classification ? <P cls="dim">{r.classification}</P> : null}</Details>
      <Details label={'Queries run (' + (r.dispatched || []).join(', ') + ')'}>{results.length ? results.map((x, i) => (
        <div key={i}>
          <P>{x.family}: {x.status}, {(x.queries || []).length} quer{(x.queries || []).length === 1 ? 'y' : 'ies'}
            {(x.blocked || []).length ? <>, <span className="xr-p bad">{x.blocked!.length} blocked</span></> : null}
            {(x.gaps || []).length ? ', suggests ' + x.gaps!.join(', ') : ''}</P>
          {x.reason ? <P cls="dim">{x.reason}</P> : null}
          {x.error ? <P cls="bad">error: {x.error}</P> : null}
          <div className="xr-mono">{[...(x.queries || []), ...(x.blocked || []).map(q => 'blocked: ' + q)].join('\n')}</div>
        </div>
      )) : null}</Details>
      <div className="xr-mono">trace {r.trace_id || 'none'}{'\n'}{r.run_dir}</div>
    </details>
  );
}

function BrokerCard({ loop, lines, runs, state }: { loop: number; lines: string[]; runs?: BrokerRun[]; state: string }) {
  const last = [...lines].reverse().find(l => l.trim()) || '';
  return (
    <Card lane="b" title="Evidence fetch" meta={state} id={'bk-' + loop}>
      <details><summary>Engine log<span className="log-last">{last.trim().slice(0, 90)}</span></summary>
        <LogTail lines={lines} />
      </details>
      {runs ? <div>{runs.map(r => <BrokerRunView key={r.task_id} r={r} />)}</div> : null}
    </Card>
  );
}

// Sticks to the bottom while the reader is at the bottom.
function LogTail({ lines }: { lines: string[] }) {
  return (
    <div className="xr-log xr-mono" ref={el => {
      if (el && el.scrollHeight - el.scrollTop - el.clientHeight < 80) el.scrollTop = el.scrollHeight;
    }}>
      {lines.map((l, i) => <span key={i} className={lineClass(l)}>{l + '\n'}</span>)}
    </div>
  );
}

function HandshakeStamp({ h }: { h: Handshake }) {
  const miss = [
    h.not_fetched.length ? 'never fetched: ' + h.not_fetched.join(', ') : '',
    h.not_returned.length ? 'no findings came back for: ' + h.not_returned.join(', ') : '',
    h.unexpected.length ? 'came back but was never sent: ' + h.unexpected.join(', ') : '',
  ].filter(Boolean);
  return (
    <div className={'xr-stamp ' + (miss.length ? 'bad' : 'ok')} role="status">
      {miss.length ? 'Handshake broken' : 'Handshake held'}: {h.sent.length} sent, {h.fetched.length} fetched, {h.returned.length} returned
      {miss.length ? <small>{miss.map((m, i) => <span key={i}>{m}<br /></span>)}</small> : null}
    </div>
  );
}

// "described identity, network; failed endpoint": which sub-analysts had something to say.
export function DomLine({ pairs }: { pairs: [string, DomState][] }) {
  const ok = pairs.filter(p => p[1] === 'ok').map(p => p[0]);
  const bad = pairs.filter(p => p[1] === 'bad').map(p => p[0]);
  if (!ok.length && !bad.length) return <>nothing to describe</>;
  return <>{ok.length ? 'described ' + ok.join(', ') : ''}{ok.length && bad.length ? '; ' : ''}{bad.length ? <span className="bad">failed {bad.join(', ')}</span> : null}</>;
}

function Finding({ f }: { f: DomainFinding }) {
  const st = domState(f);
  if (st === 'none') return <div className="dom none"><b>{f.domain}</b><span className="xr-p dim">nothing to describe</span></div>;
  const narr = String(f.narrative || '').trim();
  const prose = narr.split(CODE_HEADERS)[0].trim();
  const code = narr.slice(prose.length).trim();
  const obs = f.observations || [], sums = f.summaries || [];
  return (
    <div className="dom"><b>{f.domain}</b><div>
      <P cls={st === 'bad' ? 'bad' : ''}>{prose}</P>
      {code ? <div className="code-lines" title="Computed by code from the rows, not written by the model">{code}</div> : null}
      <Details label={'Observations (' + obs.length + ') and row summaries (' + sums.length + ')'}>{obs.length || sums.length ? <>
        {obs.length ? <div className="xr-mono">{obs.join('\n')}</div> : null}
        {sums.length ? <div className="code-lines">{sums.join('\n\n')}</div> : null}
      </> : null}</Details>
    </div></div>
  );
}

function PayloadCard({ data }: { data: PayloadBatch }) {
  const ps = data.payloads || [];
  return (
    <Card lane="b" title="Findings" meta={plural(ps.length, 'finding set')}>
      {ps.length ? ps.map(p => (
        <details className="task" id={'fd-' + p.task_id} key={p.task_id}>
          <summary><b>{shortId(p.task_id)}</b> {p.hypothesis || ''} <span className="dim dom-line"><DomLine pairs={(p.findings || []).map(f => [f.domain, domState(f)])} /></span></summary>
          {(p.findings || []).length ? p.findings.map((f, i) => <Finding key={i} f={f} />) : <P cls="dim">No domain had evidence to describe.</P>}
        </details>
      )) : <P cls="dim">No findings.</P>}
    </Card>
  );
}

function SynthCard({ data, reasoning, tokens }: { data: Synthesis; reasoning?: string; tokens?: Tokens }) {
  const done = data.status === 'VERDICT_REACHED';
  const scores = Object.entries(data.hypothesis_scores || {}).map(([k, v]) => k + ' ' + v).join(', ');
  const list = (title: string, xs?: string[]) => (xs || []).length ? <><H>{title}</H>{xs!.map((x, i) => <P key={i}>{x}</P>)}</> : null;
  return (
    <Card lane="a" title="Assessment" meta={tok(tokens)}>
      <P cls={done ? 'ok' : ''}><b>{done ? 'Verdict reached' : 'Needs another loop'}</b>{scores ? <span className="dim"> ({scores})</span> : null}</P>
      {data.verdict_reasoning ? <><H>Why</H><P>{data.verdict_reasoning}</P></> : null}
      {(data.evidence_refs || []).length ? <><H>Evidence cited</H><Chips xs={data.evidence_refs} /></> : null}
      {list('Refused citations', data.refused_refs)}
      {list('Still missing', data.evidence_gaps)}
      {list('Follow-up tasks asked for', (data.follow_up_tasks || []).map(t => t.question || JSON.stringify(t)))}
      <Reasoning text={reasoning} />
    </Card>
  );
}

export function ItemView({ item, contract, runId }: { item: Item; contract?: Contract; runId?: string }) {
  switch (item.kind) {
    case 'context': return <ContextCard {...item} />;
    case 'plan': return <PlanCard {...item} contract={contract} />;
    case 'loop': return <div className="loop-h">Loop {item.n}</div>;
    case 'handoff': return <HandoffCard data={item.data} />;
    case 'broker': return <BrokerCard {...item} />;
    case 'handshake': return <HandshakeStamp h={item.h} />;
    case 'payload': return <PayloadCard data={item.data} />;
    case 'synthesis': return <SynthCard {...item} />;
    case 'error': return <div className="xr-stamp bad" role="alert">{item.msg}<small>{explain(item.msg, runId)}</small></div>;
  }
}

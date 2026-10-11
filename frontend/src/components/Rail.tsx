import { Fragment, useLayoutEffect, useRef, type CSSProperties } from 'react';
import { explain, secs, shortId, VERDICT_COLOR, VERDICT_TAG } from '../format';
import type { RunState } from '../run';
import { DomLine } from './Cards';

const reducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;

// Ranked by score; when a synthesis rescores, rows slide to their new rank (FLIP).
export function Scores({ run }: { run: RunState | null }) {
  const ref = useRef<HTMLOListElement>(null);
  const tops = useRef<Record<string, number>>({});
  const hyps = run?.plan?.hypotheses || [];
  const scores = run?.curScores || {};
  const prev = run?.prevScores || {};
  const num = (id: string) => (scores[id] == null ? -1 : Number(scores[id]) || 0);
  const ids = (hyps.length ? hyps.map(h => h.id) : Object.keys(scores)).sort((x, y) => num(y) - num(x));

  useLayoutEffect(() => {
    const rows = [...(ref.current?.querySelectorAll<HTMLElement>('.score') || [])];
    const before = tops.current;
    tops.current = Object.fromEntries(rows.map(r => [r.dataset.id!, r.getBoundingClientRect().top]));
    if (reducedMotion()) return;
    rows.forEach(r => {
      const dy = (before[r.dataset.id!] ?? tops.current[r.dataset.id!]) - tops.current[r.dataset.id!];
      if (!dy) return;
      r.style.transition = 'none';
      r.style.transform = 'translateY(' + dy + 'px)';
      r.getBoundingClientRect();
      r.style.transition = 'transform .7s cubic-bezier(.2,.8,.2,1)';
      r.style.transform = '';
    });
  }, [ids.join('|')]);

  if (!ids.length) return <ol className="scores"><li className="dim">Appear with the plan.</li></ol>;
  return (
    <ol className="scores" ref={ref}>
      {ids.map((id, i) => {
        const h = hyps.find(x => x.id === id) || { id };
        const has = scores[id] != null;
        const d = has && prev[id] != null ? Number(scores[id]) - Number(prev[id]) : 0;
        return (
          <li key={id} className={'score' + (has && i === 0 ? ' top' : '')} data-id={id}>
            <span className="h-id">{id}</span>
            <span className="h-desc" title={h.description || ''}>{h.description || ''}</span>
            <span className={'h-n' + (has ? '' : ' none')}>{has ? String(scores[id]) : '-'}</span>
            <span className="h-meta">
              <span className="h-v" style={{ '--c': VERDICT_COLOR[h.verdict || ''] || 'var(--warn)' } as CSSProperties}>{VERDICT_TAG[h.verdict || ''] || h.verdict || ''}</span>
              {d ? <span key={String(scores[id])} className={'h-d flash' + (d > 0 ? ' up' : '')}>{(d > 0 ? '+' : '−') + Math.abs(d)}</span> : null}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

// A task opens its findings in the ledger (or, before they arrive, its evidence run).
function openTask(id: string) {
  const el = document.getElementById('fd-' + id) || document.getElementById('task-' + id);
  if (!el) return;
  for (let p: HTMLElement | null = el; p; p = p.parentElement) if (p instanceof HTMLDetailsElement) p.open = true;
  el.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
  el.querySelector('summary')?.focus({ preventScroll: true });
}

export function Tasks({ run }: { run: RunState | null }) {
  if (!run?.tasks.length) return <ol className="tasks"><li className="dim">Appear with the plan.</li></ol>;
  return (
    <ol className="tasks">
      {run.tasks.map(t => {
        const bad = t.noRun || Object.values(t.dom).includes('bad');
        const dom = Object.entries(t.dom);
        return (
          <li key={t.id}>
            <button type="button" title={t.q} onClick={() => openTask(t.id)}>
              <span className="tid">{shortId(t.id)}</span>
              <span className="tq">{t.q}</span>
              {t.steps == null
                ? <span className={'tst' + (run.failed ? ' bad' : '')}>{run.failed ? 'stopped' : 'fetching'}</span>
                : <span className={'tst ' + (bad ? 'bad' : t.rejected ? 'warn' : 'ok')}>{t.steps} steps, {t.rows} rows</span>}
              {dom.length || t.rejected ? <span className="tdom">
                {dom.length ? <DomLine pairs={dom} /> : null}{t.rejected ? (dom.length ? '; ' : '') + t.rejected + ' step rejected' : ''}
              </span> : null}
            </button>
          </li>
        );
      })}
    </ol>
  );
}

export function Meta({ run, now, lastEvent }: { run: RunState | null; now: number; lastEvent: number | null }) {
  const end = run?.ended ?? now;
  const rows = ([
    ['Status', run?.status || 'Idle'],
    run?.id ? ['Run', run.id] : null,
    run ? ['Elapsed', secs(end - run.started)] : null,
    run && run.mode !== 'ended' && lastEvent ? ['Last event', secs(now - lastEvent) + ' ago'] : null,
    run?.spend ? ['Broker spend', '$' + (run.spend / 1e6).toFixed(2)] : null,
    run?.tokIn ? ['Analyst tokens', run.tokIn + ' in, ' + run.tokOut + ' out'] : null,
    run?.loops ? ['Broker rounds', String(run.loops - 1)] : null,
    run?.id ? ['Files', '.smartops/runs/' + run.id + '/'] : null,
  ] as ([string, string] | null)[]).filter((x): x is [string, string] => !!x);
  return <dl className="meta">{rows.map(([k, v]) => <Fragment key={k}><dt>{k}</dt><dd>{v}</dd></Fragment>)}</dl>;
}

// The case, once the run says something final: a verdict, no verdict, or a failure.
export function Verdict({ run }: { run: RunState | null }) {
  const ring = useRef<HTMLDivElement>(null);
  const v = run?.verdict;
  const conf = v ? v.data.verdict_confidence ?? v.data.confidence : undefined;
  const hasRing = conf != null && !isNaN(Number(conf));
  useLayoutEffect(() => {
    if (!hasRing) return;
    requestAnimationFrame(() => requestAnimationFrame(() => ring.current?.style.setProperty('--conf', String(Math.max(0, Math.min(100, Number(conf)))))));
  }, [v, conf, hasRing]);

  if (!run) return null;
  if (!v && run.failed) return (
    <section className="verdict landed" aria-live="polite">
      <div className="v-main"><div className="v-label">Run failed</div><div className="v-conf">{run.failed}</div>
        <div className="v-sum">{explain(run.failed, run.id)}</div></div>
    </section>
  );
  if (!v) return null;
  const word = String(v.data.verdict || 'UNKNOWN').toUpperCase();
  const words = word.replace(/_/g, ' ').toLowerCase();
  const list = (h: string, xs?: string[]) => (xs || []).length ? <div><div className="v-h">{h}</div><ul className="v-list">{xs!.map((x, i) => <li key={i}>{x}</li>)}</ul></div> : null;
  return (
    <section className="verdict landed" aria-live="polite" key={run.id}>
      {hasRing ? <div className="v-ring" ref={ring}><span>{Math.round(Number(conf))}<small>%</small></span></div> : null}
      <div className="v-main">
        <div className="v-label"><i className={'ph-bold ' + (!v.decided ? 'ph-question' : word === 'TRUE_POSITIVE' ? 'ph-shield-warning' : 'ph-shield-check')} aria-hidden="true" />
          {v.decided ? words.replace(/^./, c => c.toUpperCase()) : 'No verdict'}</div>
        <div className="v-conf">{v.decided ? (hasRing ? 'Confidence ' + conf + '%' : '') : 'Leaning ' + words + '. The evidence gate did not pass. Stopped: ' + (v.why || 'unknown') + '.'}</div>
        <div className="v-sum">{v.data.verdict_reasoning || v.data.reasoning || v.data.executive_summary || 'The model gave no reasoning for this verdict.'}</div>
        <div className="v-cols">{list('Evidence cited', v.data.evidence_refs)}{list('Still missing', v.data.evidence_gaps)}</div>
      </div>
    </section>
  );
}

// The page's accent follows the verdict (`--v` on body), as in the old console.
export function verdictColor(run: RunState | null): string | null {
  if (!run) return null;
  if (run.verdict) return run.verdict.decided ? VERDICT_COLOR[String(run.verdict.data.verdict || '').toUpperCase()] || 'var(--warn)' : 'var(--warn)';
  return run.failed ? 'var(--bad)' : null;
}

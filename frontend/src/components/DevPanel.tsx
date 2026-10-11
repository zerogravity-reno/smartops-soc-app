import { Fragment, useEffect, useRef, useState } from 'react';
import { secs } from '../format';
import { STAGE_LABEL, type RunState } from '../run';
import type { StreamEvent } from '../types';

export type Src = 'pipe' | 'analyst' | 'broker' | 'ui';
export interface DevLine { at: number; rel: number | null; src: Src; text: string; cls: '' | 'ok' | 'bad' | 'warn'; stage: string; json?: unknown }

const SRC_LABEL: Record<Src, string> = { pipe: 'Pipeline', analyst: 'Analyst', broker: 'Broker', ui: 'UI' };
const FILTERS: [string, string][] = [['all', 'All'], ['pipe', 'Pipeline'], ['analyst', 'Analyst'], ['broker', 'Broker'], ['ui', 'UI'], ['err', 'Errors']];
export const DEV_MAX = 5000; // ponytail: last 5000 lines, all rendered; virtualise if runs outgrow it
const demojibake = (t: string) => String(t || '').replace(/â€”/g, '-').replace(/â€“/g, '-');

export function devLine(src: Src, text: string, run: RunState | null, cls: DevLine['cls'] = '', json?: unknown): DevLine {
  const at = Date.now();
  return { at, rel: run ? (at - run.started) / 1000 : null, src, text: demojibake(text), cls,
    stage: run && run.mode !== 'ended' ? STAGE_LABEL[run.current] : '', json };
}

// One SSE event -> one readable line. Broker lines are kept verbatim.
export function eventLine(m: StreamEvent, run: RunState | null): DevLine {
  const d = (m.data || {}) as any;
  const has = d && Object.keys(d).length > 0;
  if (m.type === 'broker_log') {
    const l = d.line || '';
    return devLine('broker', l, run, /\[ok|success/i.test(l) ? 'ok' : /\[rejected|\[error|ERROR|Traceback/i.test(l) ? 'bad' : '');
  }
  const src: Src = /^(analyst|synthesis|verdict)$/.test(m.type) ? 'analyst' : 'pipe';
  const digest = ({
    analyst: has ? 'Plan: ' + (d.hypotheses || []).length + ' hypotheses, ' + (d.tasks || []).length + ' tasks' : '',
    handoff: (d.tasks || []).length + ' task(s) handed to the broker' + ((d.dropped || []).length ? ', ' + d.dropped.length + ' dropped or changed' : ''),
    broker: d.handshake ? (d.handshake.returned || []).length + ' of ' + (d.handshake.sent || []).length + ' tasks returned' : '',
    payload: (d.payloads || []).length + ' finding set(s) from the sub-analysts',
    synthesis: has ? 'Scores ' + JSON.stringify(d.hypothesis_scores || {}) + ', ' + (d.status || '') : '',
    verdict: 'Verdict ' + (d.verdict || '?') + (d.verdict_confidence != null ? ' at ' + d.verdict_confidence + '%' : ''),
  } as Record<string, string>)[m.type];
  const text = [m.message, digest].filter(Boolean).join('. ') || m.type;
  const cls = m.type === 'error' ? 'bad' : /paused|stopped/.test(m.type) ? 'warn' : /done|verdict|resumed/.test(m.type) ? 'ok' : '';
  return devLine(src, '[' + m.type + '] ' + text, run, cls, has ? d : undefined);
}

const asText = (lines: DevLine[]) =>
  lines.map(l => [(l.rel == null ? '' : '+' + l.rel.toFixed(1) + 's').padStart(8), SRC_LABEL[l.src].padEnd(8), (l.stage || '').padEnd(9), l.text].join('  ')).join('\n');

function Highlight({ text, q }: { text: string; q: string }) {
  if (!q) return <>{text}</>;
  const parts = text.split(new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi'));
  return <>{parts.map((p, i) => (i % 2 ? <mark key={i}>{p}</mark> : p))}</>;
}

export function DevPanel({ lines, run, now, onClose, toast, searchRef }: {
  lines: DevLine[]; run: RunState | null; now: number; onClose: () => void;
  toast: (m: string, bad?: boolean) => void; searchRef: React.RefObject<HTMLInputElement | null>;
}) {
  const [filter, setFilter] = useState('all');
  const [query, setQuery] = useState('');
  const [follow, setFollow] = useState(true);
  const [openRows, setOpenRows] = useState<Set<number>>(new Set());
  const logRef = useRef<HTMLOListElement>(null);
  const q = query.trim().toLowerCase();
  const match = (l: DevLine) => (filter === 'err' ? l.cls === 'bad' : filter === 'all' || l.src === filter) && (!q || (l.text + ' ' + l.stage).toLowerCase().includes(q));
  const visible = lines.map((l, i) => [l, i] as const).filter(([l]) => match(l));
  const counts: Record<string, number> = { all: lines.length, err: lines.filter(l => l.cls === 'bad').length };
  lines.forEach(l => { counts[l.src] = (counts[l.src] || 0) + 1; });

  useEffect(() => { if (follow && logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [lines, follow, filter, q]);

  const mode = run ? (run.mode === 'ended' ? 'ended' : run.mode === 'paused' ? 'paused' : 'live') : 'idle';
  const toggle = (i: number) => setOpenRows(s => { const n = new Set(s); n.has(i) ? n.delete(i) : n.add(i); return n; });
  const copy = () => navigator.clipboard.writeText(asText(visible.map(([l]) => l)))
    .then(() => toast('Copied ' + visible.length + ' lines'), () => toast('Copy failed: the browser blocked the clipboard.', true));
  const save = () => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([asText(lines)], { type: 'text/plain' }));
    a.download = 'run-' + (run?.id || 'none') + '.log';
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <aside className="dev" aria-label="Dev mode">
      <header className="dev-head">
        <b className="dev-title"><i className="ph ph-terminal-window" aria-hidden="true" />Dev mode</b>
        <span className="dev-run">
          <span className={'dev-st ' + mode}>{mode}</span>
          {run?.id ? <>
            <b>{run.id}</b><span>{run.mode !== 'ended' ? STAGE_LABEL[run.current] : run.status}</span>
            <span>{secs((run.ended ?? now) - run.started)}</span><code>.smartops/runs/{run.id}/</code>
          </> : null}
        </span>
        <span className="dev-keys"><kbd>Ctrl D</kbd> toggle <kbd>/</kbd> search <kbd>Esc</kbd> close</span>
        <button className="btn-ghost dev-x" type="button" aria-label="Close dev mode" onClick={onClose}><i className="ph ph-x" aria-hidden="true" /></button>
      </header>
      <div className="dev-bar">
        <div className="dev-filters" role="group" aria-label="Filter by source">
          {FILTERS.map(([k, label]) => (
            <button key={k} type="button" data-src={k} aria-pressed={filter === k} className={counts[k] ? 'has' : undefined} onClick={() => setFilter(k)}>
              {label} <span>{counts[k] || 0}</span>
            </button>
          ))}
        </div>
        <input ref={searchRef} className="dev-search" type="search" placeholder="Search the log" aria-label="Search the log" value={query} onChange={e => setQuery(e.target.value)} />
        <label className="dev-follow"><input type="checkbox" checked={follow} onChange={e => setFollow(e.target.checked)} /> Follow</label>
        <button className="btn-ghost dev-act" type="button" aria-label="Copy visible lines" onClick={copy}><i className="ph ph-copy" aria-hidden="true" /><span>Copy</span></button>
        <button className="btn-ghost dev-act" type="button" aria-label="Download the log" onClick={save}><i className="ph ph-download-simple" aria-hidden="true" /><span>Download</span></button>
      </div>
      <div className="dev-body">
        <ol className="dev-log" aria-live="off" ref={logRef} onScroll={e => {
          const el = e.currentTarget, atEnd = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
          if (atEnd !== follow) setFollow(atEnd);
        }}>
          {visible.length ? visible.map(([l, i]) => (
            <Fragment key={i}>
              <li className={'dl ' + l.cls + (l.json ? ' has-json' : '')} tabIndex={l.json ? 0 : undefined} aria-expanded={l.json ? openRows.has(i) : undefined}
                onClick={l.json ? () => toggle(i) : undefined} onKeyDown={l.json ? e => { if (e.key === 'Enter') toggle(i); } : undefined}>
                <time title={new Date(l.at).toLocaleTimeString()}>{l.rel == null ? '' : '+' + l.rel.toFixed(1) + 's'}</time>
                <b className={'dl-src src-' + l.src}>{SRC_LABEL[l.src]}</b><span className="dl-stage">{l.stage}</span>
                <span className="dl-text"><Highlight text={l.text} q={q} />{l.json ? <i className="ph ph-caret-right dl-caret" aria-hidden="true" /> : null}</span>
              </li>
              {l.json && openRows.has(i) ? <li className="dl-json"><pre>{JSON.stringify(l.json, null, 2)}</pre></li> : null}
            </Fragment>
          )) : <li className="dl-empty">{lines.length ? 'No lines match.' : 'No run yet. Start an investigation and its live log streams here.'}</li>}
        </ol>
        {follow ? null : <button className="dev-jump" type="button" onClick={() => setFollow(true)}><i className="ph-bold ph-arrow-down" aria-hidden="true" />Jump to latest</button>}
      </div>
    </aside>
  );
}

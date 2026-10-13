import { useEffect, useRef, type CSSProperties } from 'react';
import { familyIcon, sev, shortRule } from '../format';
import type { QueueEvent, QueueGroup } from '../types';

export type Seen = Record<string, { tag: string; color: string }>;
export const eventKey = (ev: QueueEvent) => ev.rule_name + '|' + ev.time;
const groupId = (g: QueueGroup) => g.rule_name + '|' + g.dest;
const clock = (t: string) => String(t || '').slice(11, 19) || t;
const Fam = ({ rule }: { rule: string }) => <i className={'ph ' + familyIcon(rule) + ' q-fam'} aria-hidden="true" />;

interface QueueProps {
  groups: QueueGroup[] | null; error: string | null; intro: boolean; seen: Seen;
  current: string | null; running: boolean; openGroup: { id: string } | null; // a new object per request, so a repeat click re-opens
  onPick: (ev: QueueEvent) => void; onRefresh: () => void;
}

function Row({ ev, inGroup, i, p }: { ev: QueueEvent; inGroup: boolean; i?: number; p: QueueProps }) {
  const s = sev(ev.urgency), k = eventKey(ev), seen = p.seen[k];
  const cur = k === p.current;
  const cls = [s ? 'sev-' + s[0] : '', p.running && cur ? 'running' : '', seen ? 'ran' : ''].filter(Boolean).join(' ');
  const who = (inGroup ? [ev.user, ev.src] : [ev.dest, ev.user, ev.src]).filter(Boolean).join(', ');
  return (
    <li style={i == null ? undefined : ({ '--i': i } as CSSProperties)}>
      <button type="button" className={cls || undefined} style={seen ? ({ '--c': seen.color } as CSSProperties) : undefined}
        aria-current={cur || undefined} disabled={p.running} title={ev.rule_name + '\n' + ev.time} onClick={() => p.onPick(ev)}>
        {inGroup ? null : <span className="q-rule"><Fam rule={ev.rule_name} />{shortRule(ev.rule_name) || 'Unnamed rule'}</span>}
        <span className="q-time">{clock(ev.time)}</span>
        <span className="q-who">
          {s && !inGroup ? <span className="q-sev">{s[1]}</span> : null}
          <span>{who}</span>
          {seen ? <span className="q-seen" style={{ '--c': seen.color } as CSSProperties}>{seen.tag}</span> : null}
        </span>
      </button>
    </li>
  );
}

function Group({ g, i, p }: { g: QueueGroup; i: number; p: QueueProps }) {
  const ref = useRef<HTMLDetailsElement>(null);
  const s = sev(g.urgency);
  // A group shows how many of its alerts ran this session; its streak takes the gravest verdict seen.
  const ran = g.events.map(e => p.seen[eventKey(e)]).filter(Boolean);
  const edge = (ran.find(x => x.tag === 'TP') || ran[0])?.color;
  const holdsCurrent = g.events.some(e => eventKey(e) === p.current);
  // Uncontrolled: a group the reader opened stays open across polls; one holding the current alert opens.
  useEffect(() => { if (holdsCurrent && ref.current) ref.current.open = true; }, [holdsCurrent]);
  useEffect(() => {
    if (p.openGroup?.id === groupId(g) && ref.current) {
      ref.current.open = true;
      ref.current.scrollIntoView({ block: 'start' });
      ref.current.querySelector('summary')?.focus({ preventScroll: true });
    }
  }, [p.openGroup]);
  return (
    <li className="grp" style={{ '--i': i } as CSSProperties}>
      <details ref={ref}>
        <summary className={[s ? 'sev-' + s[0] : '', edge ? 'ran' : ''].filter(Boolean).join(' ')} style={edge ? ({ '--c': edge } as CSSProperties) : undefined} title={g.rule_name}>
          <span className="q-rule"><Fam rule={g.rule_name} />{shortRule(g.rule_name) || 'Unnamed rule'}</span>
          <span className="q-time">{clock(g.time)}</span>
          <span className="q-who">
            {s ? <span className="q-sev">{s[1]}</span> : null}
            <span className="q-count">×{g.count}</span><span>{g.dest || ''}</span>
            <span className={'q-ran' + (ran.length ? ' some' : '')}>{ran.length ? 'ran ' + ran.length + '/' + g.events.length : 'none ran'}</span>
          </span>
        </summary>
        <ol className="q-inst">{g.events.map(e => <Row key={e.index} ev={e} inGroup p={p} />)}</ol>
      </details>
    </li>
  );
}

export function Queue(p: QueueProps) {
  const { groups, error } = p;
  return (
    <aside className="queue" aria-labelledby="queueTitle">
      <div className="queue-head">
        <h2 id="queueTitle">Incident queue</h2>
        <button className="btn-ghost" type="button" onClick={p.onRefresh}>Refresh</button>
      </div>
      <ol className={'queue-list' + (p.intro ? ' intro' : '')} aria-busy={groups == null && !error}>
        {error ? <li className="q-state bad">Could not reach Splunk: {error}<br />Check the Splunk MCP connection, then Refresh.</li>
          : groups == null ? <><li className="skel" /><li className="skel" /><li className="skel" /></>
          : !groups.length ? <li className="q-state">No alerts in the last 30 days. Enter the fields by hand to investigate.</li>
          : groups.map((g, i) => (g.count || 1) < 2 ? <Row key={groupId(g)} ev={g.events[0]} inGroup={false} i={i} p={p} /> : <Group key={groupId(g)} g={g} i={i} p={p} />)}
      </ol>
    </aside>
  );
}

// What the queue holds, shown until a run starts.
export function Overview({ groups, seen, intro, onGroup, onPick }: {
  groups: QueueGroup[]; seen: Seen; intro: boolean; onGroup: (id: string) => void; onPick: (ev: QueueEvent) => void;
}) {
  const ref = useRef<HTMLElement>(null);
  const evs = groups.flatMap(g => g.events || []);
  const ts = evs.map(e => Date.parse(e.time)).filter(n => !isNaN(n));
  useEffect(() => {
    if (!intro || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    ref.current?.querySelectorAll<HTMLElement>('[data-n]').forEach(b => {
      const n = Number(b.dataset.n), t0 = performance.now();
      const step = (now: number) => { const k = Math.min(1, (now - t0) / 700); b.textContent = String(Math.round(n * (1 - Math.pow(1 - k, 3)))); if (k < 1) requestAnimationFrame(step); };
      requestAnimationFrame(step);
    });
  }, [intro, groups]);
  if (!ts.length) return <section className="overview" aria-label="Queue overview" />;

  const lo = Math.min(...ts), hi = Math.max(...ts), span = Math.max(hi - lo, 1);
  const at = (t: string) => ((Date.parse(t) - lo) / span * 100).toFixed(2) + '%';
  const N = 36, bins = Array(N).fill(0);
  ts.forEach(t => bins[Math.min(N - 1, Math.floor((t - lo) / span * N))]++);
  const peak = Math.max(...bins);
  const hhmm = (t: number) => String(evs.find(e => Date.parse(e.time) === t)!.time).slice(11, 16);
  const stat = (n: number, label: string) => <div className="ov-stat"><b data-n={n}>{n}</b><span>{label}</span></div>;
  return (
    <section className="overview" aria-label="Queue overview" ref={ref}>
      <div className="ov-stats">
        {stat(evs.length, 'Alerts')}{stat(groups.length, groups.length === 1 ? 'Group' : 'Groups')}
        {stat(evs.filter(e => /^(critical|high)$/i.test(e.urgency || '')).length, 'Critical or high')}
        {stat(evs.filter(e => seen[eventKey(e)]).length, 'Investigated')}
      </div>
      <div className="ov-card"><h3>Activity</h3>
        <div className="ov-bars">{bins.map((b, i) => <span key={i} style={{ height: (b / peak * 100).toFixed(1) + '%' }} title={b + ' alert' + (b === 1 ? '' : 's')} />)}</div>
        <div className="ov-axis"><span>{hhmm(lo)}</span><span>{hhmm(hi)}</span></div>
      </div>
      <div className="ov-card"><h3>By rule and host</h3>
        <ol className="ov-rules">{groups.map(g => (
          <li key={groupId(g)}>
            {/* A row opens its group in the queue, or imports a lone alert. */}
            <button type="button" onClick={() => ((g.count || 1) < 2 ? onPick(g.events[0]) : onGroup(groupId(g)))}>
              <Fam rule={g.rule_name} />
              <span className="ov-name">{shortRule(g.rule_name)}<small>{g.dest || ''}</small></span>
              <span className="ov-ticks">{g.events.map(e => {
                const x = seen[eventKey(e)];
                return <span key={e.index} className={x ? 'ran' : undefined} style={{ left: at(e.time), ...(x ? { '--c': x.color } : {}) } as CSSProperties} />;
              })}</span>
              <span className="ov-n">×{g.count || 1}</span>
            </button>
          </li>
        ))}</ol>
      </div>
    </section>
  );
}

import { secs } from '../format';
import { STAGE_LABEL, STAGES, type RunState, type StageName } from '../run';
import { ItemView } from './Cards';

const ICON: Record<StageName, string> = { context: 'ph-file-text', plan: 'ph-tree-structure', broker: 'ph-database', findings: 'ph-magnifying-glass', synthesis: 'ph-scales' };

const elapsed = (r: RunState, s: StageName, now: number) => {
  const t = r.stages[s];
  return t.start ? secs((t.end ?? (r.mode === 'ended' ? r.ended! : now)) - t.start) : '';
};

// The five stages: a track with the live line above, then one fold-out per stage.
export function Ledger({ run, now, onToggle }: { run: RunState; now: number; onToggle: (s: StageName, open: boolean) => void }) {
  return <>
    <div className="now">
      <ol className="track" aria-hidden="true">
        {STAGES.map(s => (
          <li key={s} data-stage={s} className={run.stages[s].status}>
            <span className="dot" /><i className={'ph ' + ICON[s]} /><b>{STAGE_LABEL[s]}</b><time>{elapsed(run, s, now)}</time>
          </li>
        ))}
      </ol>
      <p className="now-line" role="status"><b>{STAGE_LABEL[run.current]}</b><span>{run.now}</span></p>
    </div>
    <ol className="ledger">
      {STAGES.map(s => {
        const st = run.stages[s];
        return (
          <li key={s} className={'stg' + (st.status ? ' ' + st.status : '')} data-stage={s}>
            <details open={st.open} onToggle={e => {
              const open = (e.currentTarget as HTMLDetailsElement).open;
              if (open !== st.open) onToggle(s, open);
            }}>
              <summary>
                <span className="node" aria-hidden="true" />
                <span className="stg-name"><i className={'ph ' + ICON[s]} aria-hidden="true" />{STAGE_LABEL[s]}</span>
                <span className="stg-sum">{st.sum}</span>
                <span className="stg-time">{elapsed(run, s, now)}</span>
              </summary>
              <div className="stg-body">
                {st.items.map((item, i) => <ItemView key={i} item={item} contract={run.contract} runId={run.id} />)}
              </div>
            </details>
          </li>
        );
      })}
    </ol>
  </>;
}

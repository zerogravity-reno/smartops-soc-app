import { useRef, useState, type FormEvent } from 'react';
import type { AlertFields } from '../contract';
import { sev, sha256, shortRule, when } from '../format';
import type { ImportedAlert } from '../types';

export type Controls = 'idle' | 'running' | 'pausing' | 'paused' | 'stopping' | 'ended';

const ICON: Record<string, string> = { host: 'ph-desktop-tower', user: 'ph-user', ip: 'ph-globe-simple', mitre: 'ph-crosshair', time: 'ph-clock',
  integrity: 'ph-shield', hash: 'ph-fingerprint', proc: 'ph-terminal-window', parent: 'ph-tree-structure' };

const FORM: [keyof AlertFields, string, boolean, boolean?][] = [
  ['rule_name', 'Detection rule', true], ['src_ip', 'Source IP', false], ['dest', 'Destination host', false], ['user', 'User', false],
  ['hash', 'File hash', false], ['domain', 'Domain', false], ['mitre', 'MITRE technique', false], ['signature', 'Signature', true],
  ['deployed_spl', 'Deployed SPL', true, true],
];

function CodeBlock({ icon, label, value, onCopyFail }: { icon: string; label: string; value: string; onCopyFail: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = () => navigator.clipboard.writeText(value).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200); }, onCopyFail);
  return (
    <div className="code">
      <div className="code-h"><i className={'ph ' + ICON[icon]} aria-hidden="true" />{label}<button type="button" className="copy" onClick={copy}>{copied ? 'Copied' : 'Copy'}</button></div>
      <code>{value}</code>
    </div>
  );
}

function Facts({ data, onCopyFail }: { data: ImportedAlert; onCopyFail: () => void }) {
  const r = data.raw_event_data || {};
  const one = (v: unknown) => String((Array.isArray(v) ? v[0] : v) ?? '');
  const s = sev(data.urgency);
  const pills = ([['host', 'Host', data.dest], ['user', 'User', data.user], ['ip', 'Source IP', data.src],
    ['mitre', 'MITRE', one(r['annotations.mitre_attack'])], ['integrity', 'Integrity', one(r.process_integrity_level)],
    ['time', 'Event', when(data.event_time)], ['time', 'Notable', when(one(r._time))]] as [string, string, string][]).filter(p => p[2]);
  const codes = ([['parent', 'Parent process', one(r.parent_process_path) || one(r.parent_process)],
    ['proc', 'Command line', one(r.process) || data.sig], ['hash', 'SHA256', sha256(one(r.process_hash) || data.file_hash)]] as [string, string, string][]).filter(c => c[2]);
  if (!pills.length && !codes.length && !s) return null;
  return (
    <div className="facts">
      <div className="pills">
        {s ? <span className={'pill sev sev-' + s[0]}>{s[1]}</span> : null}
        {pills.map(([i, k, v]) => <span className="pill" key={k}><i className={'ph ' + ICON[i]} aria-hidden="true" /><small>{k}</small>{v}</span>)}
      </div>
      {codes.map(([i, k, v]) => <CodeBlock key={k} icon={i} label={k} value={v} onCopyFail={onCopyFail} />)}
    </div>
  );
}

interface Props {
  fields: AlertFields; setFields: (f: AlertFields) => void; imported: ImportedAlert | null; note: string;
  controls: Controls; onInvestigate: () => void; onPause: () => void; onStop: () => void; onRestart: () => void; onReset: () => void;
  onExport: () => void; exporting: boolean;
  toast: (msg: string, bad?: boolean) => void;
}

export function AlertStrip(p: Props) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState('');
  const ruleRef = useRef<HTMLInputElement>(null);
  const { controls: c } = p;
  const live = c === 'running' || c === 'pausing' || c === 'paused' || c === 'stopping';
  const title = p.imported ? shortRule(p.imported.rule_name) : p.fields.rule_name ? shortRule(p.fields.rule_name) : 'No alert selected';

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!p.fields.rule_name.trim()) {
      setError('Pick an alert from the queue, or open Edit fields and enter the detection rule name.');
      setOpen(true);
      setTimeout(() => ruleRef.current?.focus());
      return;
    }
    setError('');
    setOpen(false);
    p.onInvestigate();
  };

  return (
    <section className="strip" aria-labelledby="alertTitle">
      <div className="strip-top">
        <h2 id="alertTitle" className="strip-rule" title={p.imported?.rule_name || ''}>{title}</h2>
        <div className="strip-actions">
          <button className="btn-ghost" type="button" aria-expanded={open} aria-controls="alertForm" onClick={() => setOpen(!open)}>{open ? 'Hide fields' : 'Edit fields'}</button>
          {live ? <>
            <button className="btn-ghost btn-ctl" type="button" disabled={c === 'stopping' || c === 'pausing'} onClick={p.onPause}>
              {c === 'paused' ? <><i className="ph-bold ph-play" />Resume</> : <><i className="ph-bold ph-pause" />{c === 'pausing' ? 'Pausing' : 'Pause'}</>}
            </button>
            <button className="btn-ghost btn-ctl btn-stop" type="button" disabled={c === 'stopping'} onClick={p.onStop}><i className="ph-bold ph-stop" />{c === 'stopping' ? 'Stopping' : 'Stop'}</button>
          </> : null}
          {c === 'ended' ? <>
            <button className="btn-ghost btn-ctl" type="button" disabled={p.exporting} onClick={p.onExport}>
              <i className="ph ph-download-simple" aria-hidden="true" />{p.exporting ? 'Exporting' : 'Export HTML'}
            </button>
            <button className="btn-ghost btn-ctl" type="button" onClick={p.onReset}><i className="ph-bold ph-arrow-counter-clockwise" aria-hidden="true" />Reset</button>
            <button className="btn-ghost btn-ctl" type="button" onClick={p.onRestart}><i className="ph-bold ph-arrows-clockwise" aria-hidden="true" />Restart</button>
          </> : null}
          {live ? null : <button className="btn-primary" type="submit" form="alertForm">Investigate</button>}
        </div>
      </div>
      <p className="note">{p.note}</p>
      {p.imported ? <Facts data={p.imported} onCopyFail={() => p.toast('Copy failed: the browser blocked the clipboard.', true)} /> : null}
      <form id="alertForm" className="fields" noValidate hidden={!open} onSubmit={submit}>
        {FORM.map(([k, label, full, area]) => (
          <label key={k} className={'field' + (full ? ' full' : '')}>{label}
            {area
              ? <textarea rows={3} value={p.fields[k]} onChange={e => p.setFields({ ...p.fields, [k]: e.target.value })} />
              : <input ref={k === 'rule_name' ? ruleRef : undefined} required={k === 'rule_name'} value={p.fields[k]} onChange={e => p.setFields({ ...p.fields, [k]: e.target.value })} />}
          </label>
        ))}
      </form>
      <p className="field-error" role="alert">{error}</p>
    </section>
  );
}

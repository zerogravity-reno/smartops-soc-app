// Small pure helpers shared by the components (ported from webapp/static/app.js).

// "Threat - sama- ESCU - Malicious PowerShell Process - Encoded Command - Rule"
//   -> "Malicious PowerShell Process - Encoded Command"
export function shortRule(name?: string): string {
  let s = String(name || '');
  while (/^(Threat|sama|ESCU|Custom|Endpoint|Network|Identity|Access)\s*-\s*/i.test(s)) s = s.replace(/^[^-]*-\s*/, '');
  return s.replace(/(\s*-\s*Rule)+\s*$/i, '') || String(name || '');
}

const SEV: Record<string, [string, string]> = {
  critical: ['critical', 'CRIT'], high: ['high', 'HIGH'], medium: ['medium', 'MED'], low: ['low', 'LOW'], informational: ['low', 'INFO'],
};
export const sev = (u?: string) => SEV[String(u || '').toLowerCase()] || null;

// The rule's family is its first prefix: "Endpoint - sama - ESCU - ..." -> Endpoint.
const FAMILY: Record<string, string> = { endpoint: 'ph-desktop', threat: 'ph-warning-octagon', network: 'ph-share-network', identity: 'ph-key', access: 'ph-key' };
export const familyIcon = (rule?: string) => FAMILY[String(rule || '').split(/\s*-\s*/)[0].toLowerCase()] || 'ph-bell-simple';

// "2026-10-06T22:48:19.000+03:00" -> "2026-10-06 22:48:19 +03:00"; a UTC time reads "... UTC".
export const when = (t?: unknown) => t ? String(t).replace('T', ' ').replace(/\.\d+/, '').replace(/(\d)([+-]\d\d:\d\d|Z)$/, '$1 $2').replace(/ (\+00:00|Z)$/, ' UTC') : '';

export const secs = (ms: number) => { const s = Math.round(ms / 1000); return s < 60 ? s + 's' : Math.floor(s / 60) + 'm ' + String(s % 60).padStart(2, '0') + 's'; };

// "r1-L2-T3" -> "T3"
export const shortId = (id?: string | null) => String(id || '').replace(/^.*-(L\d+-)?(?=T\d+$)/, '');

export const sha256 = (h?: string) => { const m = /SHA256=([0-9A-Fa-f]{64})/.exec(h || ''); return m ? m[1] : (h || ''); };

export const plural = (n: number, one: string, many = one + 's') => n + ' ' + (n === 1 ? one : many);

export const VERDICT_COLOR: Record<string, string> = { TRUE_POSITIVE: 'var(--bad)', FALSE_POSITIVE: 'var(--ok)', BENIGN: 'var(--ok)' };
export const VERDICT_TAG: Record<string, string> = { TRUE_POSITIVE: 'TP', FALSE_POSITIVE: 'FP', BENIGN: 'BENIGN' };

// A finding's narrative is the model's prose, then code-written blocks that open with a known header.
export const CODE_HEADERS = /\n\s*\n(?=(Names in this narrative|Encoded commands in these rows)[^\n]*:)/;
export type DomState = 'ok' | 'bad' | 'none';
export function domState(f: { narrative?: string }): DomState {
  const narr = String(f.narrative || '');
  if (/produced no parseable/i.test(narr)) return 'bad';
  return narr.trim() ? 'ok' : 'none';
}

// What an error means and where to look. First match wins; order is specific to general.
const ERRORS: [RegExp, string][] = [
  [/was cut off at [\d,]+ tokens/i, 'The Analyst model spent its whole output allowance before it finished (stop_reason=length), usually by thinking in a loop, so there was no answer to read. This is the model failing, not an unsure verdict. The full generation is in the run\'s investigation.jsonl, step cut_off.'],
  [/no task could be converted/i, 'The Analyst handed the Tool Broker nothing it can search: no plan came back, or every task was dropped (an entity type the broker does not know, or a time window whose start is not before its end). The Plan and Evidence stages say which.'],
  [/broker timed out/i, 'The Tool Broker ran for more than 30 minutes and was stopped. Usually a slow Splunk search or a model stuck retrying. The engine log in the Evidence stage shows where it was.'],
  [/broker exited 2\b/i, 'The Tool Broker refused to start, so nothing was fetched: a configuration problem (MCP config, a task file it rejected, or model credentials). The quoted error line names it; fix .env and run again.'],
  [/broker exited/i, 'The Tool Broker crashed part-way through. The quoted lines and the end of the engine log show the exception.'],
  [/no analyst payload/i, 'The Tool Broker fetched evidence but the sub-analysts wrote no findings. Check SMARTOPS_ANALYST_MODEL_ARN and SMARTOPS_ANALYST_API_KEY in .env, and the end of the engine log.'],
  [/SMARTOPS_ANALYST_MODEL_ARN|FS8B_API_KEY/, 'The Analyst model is not configured. Set SMARTOPS_ANALYST_MODEL_ARN (and FS8B_API_KEY until AR3) in .env and restart the server.'],
  [/Bedrock (unreachable|call failed|failed)|HTTP (401|403)/i, 'The call to the Analyst model on Bedrock failed: network, an expired or wrong API key, or the imported model not reachable in that region.'],
  [/\/api\/(escu|opencti)/i, 'Building the context failed before the pipeline started (ESCU match or OpenCTI lookup). Check the server console.'],
  [/\/api\/run\b|run id/i, 'The server would not start a run. Check the server console.'],
  [/Lost the live stream/i, 'The browser lost the run. If the server restarted (for example a --reload after a file change), the run is gone; start it again.'],
  [/Failed to fetch|NetworkError/i, 'The browser cannot reach the server. Is uvicorn still running?'],
];
export function explain(msg: string, runId?: string): string {
  const hit = ERRORS.find(([re]) => re.test(msg || ''));
  return (hit ? hit[1] : 'An unexpected error. The server console has the traceback.') +
    (runId ? ' Everything for this run is in .smartops/runs/' + runId + '/.' : '');
}

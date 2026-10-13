import type { CtiResult, EscuResult, ImportedAlert, QueueGroup } from './types';

export async function getJSON<T>(url: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(url + ' answered HTTP ' + res.status);
  return res.json();
}
export const postJSON = <T>(url: string, body: unknown) =>
  getJSON<T>(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

// Most routes report failure as HTTP 200 with status "error": turn that into a throw.
function ok<T extends { status?: string; message?: string }>(r: T): T {
  if (r.status === 'error') throw new Error(r.message || 'The server reported an error');
  return r;
}

export const api = {
  queue: () => getJSON<{ status: string; message?: string; groups: QueueGroup[] }>('/api/incident-queue').then(ok).then(r => r.groups || []),
  importAlert: (index: number) => getJSON<ImportedAlert>('/api/import-from-splunk?index=' + index).then(r => {
    if (r.status !== 'ok') throw new Error(r.message || 'No alert returned');
    return r;
  }),
  escu: (rule_name: string) => postJSON<EscuResult>('/api/escu', { rule_name }),
  opencti: (observables: string[]) => postJSON<CtiResult>('/api/opencti', { observables }),
  startRun: (context_contract: object) => postJSON<{ run_id?: string }>('/api/run', { context_contract }),
  control: (runId: string, action: 'stop' | 'pause' | 'resume') => postJSON<{ status: string }>('/api/run/' + encodeURIComponent(runId) + '/' + action, {}),
  streamUrl: (runId: string) => '/api/run/stream/' + encodeURIComponent(runId),
};

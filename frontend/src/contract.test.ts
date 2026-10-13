import { expect, test } from 'vitest';
import { buildContract, observables, relevantStories, type AlertFields } from './contract';

const f = { rule_name: 'r' } as AlertFields;
const escu = { status: 'success' }, cti = { status: 'success' as const };

test('an unresolved event time stays unset, never the notable time (W9)', () => {
  const c = buildContract(f, { _time: '2026-10-06T14:59:55.000+03:00' }, null, escu, cti);
  expect(c.normalized_seed.event_time).toBeUndefined();
  expect(buildContract(f, {}, '2026-10-06T11:51:16Z', escu, cti).normalized_seed.event_time).toBe('2026-10-06T11:51:16.000Z');
});

test('no hardcoded index reaches the context (P3)', () => {
  expect(JSON.stringify(buildContract(f, {}, null, escu, cti))).not.toContain('win_sysmon');
});

test('irrelevant server-exploit stories do not reach OpenCTI or the contract', () => {
  const fields = { ...f, rule_name: 'PowerShell execution' };
  const raw = { 'annotations.analytic_story': 'Exchange Server Exploitation;PowerShell' };
  expect(relevantStories(fields.rule_name, ['Exchange Server Exploitation', 'PowerShell'])).toEqual(['PowerShell']);
  expect(observables(fields, raw)).not.toContain('Exchange Server Exploitation');
  expect(buildContract(fields, raw, null, { status: 'success', matches: [{ rule: 'PowerShell', score: 1, data: { analytic_story: ['Exchange Server Exploitation', 'PowerShell'] } }] }, cti).escu_context.analytic_story).toEqual(['PowerShell']);
});

// The context contract /api/run receives, built from the alert fields, the imported
// Splunk row, and the ESCU + OpenCTI answers. Data logic unchanged from webapp/static/app.js.
import type { CtiResult, EscuResult } from './types';

export interface AlertFields {
  rule_name: string; src_ip: string; dest: string; user: string; hash: string;
  domain: string; mitre: string; signature: string; deployed_spl: string;
}

type Raw = Record<string, any>;

// The values worth asking OpenCTI about (non-empty only).
export function observables(f: AlertFields, raw: Raw): string[] {
  const mitre = raw['annotations.mitre_attack'] ? String(raw['annotations.mitre_attack']).split(';') : [];
  const story = raw['annotations.analytic_story'] ? String(raw['annotations.analytic_story']).split(';') : [];
  return [f.src_ip, f.hash, f.domain, raw.url || raw.uri || '', raw.email || raw.recipient || raw.sender || '',
    raw.file_name || raw.process_name || raw.app || '', ...mitre, ...story].filter(v => v && v.length > 0);
}

// Recursively remove nulls, empty arrays, and empty objects.
function clean(obj: Raw) {
  for (const key in obj) {
    if (obj[key] === null) delete obj[key];
    else if (Array.isArray(obj[key])) { if (obj[key].length === 0) delete obj[key]; }
    else if (typeof obj[key] === 'object') {
      clean(obj[key]);
      if (Object.keys(obj[key]).length === 0) delete obj[key];
    }
  }
  return obj;
}

const arr = (v: unknown) => (Array.isArray(v) ? v : [v]);

export function buildContract(f: AlertFields, raw: Raw, eventTime: string | null, escu: EscuResult, cti: CtiResult) {
  const { rule_name, src_ip, dest, user, hash, domain, signature, deployed_spl } = f;
  const url = raw.url || raw.uri || '';
  const email = raw.email || raw.recipient || raw.sender || '';
  const file_name = raw.file_name || raw.process_name || raw.app || '';
  const splunk_mitre = raw['annotations.mitre_attack'] ? String(raw['annotations.mitre_attack']).split(';') : [];
  const splunk_story = raw['annotations.analytic_story'] ? String(raw['annotations.analytic_story']).split(';') : [];

  const raw_event = Object.keys(raw).length > 0 ? { ...raw } : {
    orig_time: Math.floor(Date.now() / 1000).toString(),
    rule_title: rule_name || 'Unknown Alert', severity_level: 'High',
    src: src_ip || '0.0.0.0', dest_host: dest || 'Unknown', user_name: user || 'N/A',
    proc_name: 'unknown.exe', proc_cmd: signature || 'N/A', file_hash: hash || 'N/A', domain_query: domain || 'N/A',
    index: 'win_sysmon', sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
    _raw_spl: deployed_spl || undefined,
  };

  // The alert's own time, in UTC. It was the browser's "now", which sent run cecd266a
  // searching 3 hours after a +03:00 alert; then the notable's _time, which sent run
  // 600721d3 74 minutes late. The import resolves it from firstTime.
  const d = new Date(eventTime || ([] as unknown[]).concat(raw._time)[0] as string || NaN);
  const normalized_seed = clean({
    event_id: 'evt-' + Math.floor(Math.random() * 1000000),
    event_time: isNaN(d.getTime()) ? null : d.toISOString(),
    ingest_time: new Date().toISOString(),
    detection: { name: rule_name || null, severity: 'high' },
    source_context: { siem: 'Splunk ES', index: 'win_sysmon', sourcetype: 'XmlWinEventLog' },
    entities: { hostname: dest || null, user: user || null, src_ip: src_ip || null },
    process: {
      process_name: raw.process_name || signature || null, process_path: raw.process_path || null, process_id: raw.process_id || null,
      process_guid: raw.process_guid || null, command_line: raw.process || null,
      parent_process_name: raw.parent_process_name || null, parent_process_path: raw.parent_process_path || null,
      parent_process_id: raw.parent_process_id || null,
    },
    file: { sha256: hash || null },
    http: { domain: domain || null },
    opencti_observables: {
      ip_addresses: src_ip ? [src_ip] : [], domains: domain ? [domain] : [], urls: url ? [url] : [],
      file_hashes: hash ? [hash] : [], email_addresses: email ? [email] : [], file_names: file_name ? [file_name] : [],
      mitre_techniques: splunk_mitre, analytic_stories: splunk_story,
    },
    finding: raw_event,
  });

  let mitre_techniques: unknown = [], analytic_story: unknown = [], data_sources: unknown = ['Simulated Data Source'], known_false_positives: unknown = [];
  let reference_spl = 'No SPL returned from ESCU.';
  let description = 'Detection logic and context mapped from ESCU bm25 corpus.';
  let full_metadata = {};
  const match = escu.matches?.[0];
  if (match) {
    full_metadata = match;
    if (match.data) {
      mitre_techniques = match.data.mitre_attack_id || match.data.mitre || [];
      analytic_story = match.data.analytic_story || [];
      reference_spl = match.data.spl || match.data.search || 'SPL missing in ESCU definition';
      data_sources = match.data.data_source || [];
      known_false_positives = match.data.known_false_positives || [];
      description = match.data.description || description;
    }
  }

  return {
    normalized_seed,
    rule_intent: {
      intent: 'To be determined by LLM (Rule Intent Interpreter) via semantic comparison of both SPLs.',
      semantic_alignment: 'ALIGNED | NOT_ALIGNED',
      deployed_spl: deployed_spl || 'Not provided — paste the SPL from Splunk ES here.',
      reference_spl,
    },
    escu_context: {
      description, mitre_techniques: arr(mitre_techniques), data_sources: arr(data_sources),
      known_false_positives: arr(known_false_positives), analytic_story: arr(analytic_story), reference_spl, full_metadata,
    },
    opencti_threat_intelligence: {
      indicators: Object.keys(cti.results || {}).map(key => ({ observable: key, type: cti.results![key]._queried_as })),
      malware: [], threat_actors: [], campaigns: [], relationships: [],
      _raw_intel_dump: cti.results,
    },
  };
}
export type Contract = ReturnType<typeof buildContract>;

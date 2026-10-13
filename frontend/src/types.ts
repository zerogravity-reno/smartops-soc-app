// The backend's API, as written down in docs/frontend-api-contract.md.
// Model-written fields are optional everywhere: the model is asked for them, not bound to them.

export type Urgency = 'informational' | 'low' | 'medium' | 'high' | 'critical' | '';

export interface QueueEvent {
  index: number; time: string; rule_name: string; urgency: string; src: string; dest: string; user: string;
}
export interface QueueGroup {
  rule_name: string; dest: string; time: string; urgency: Urgency;
  users: string[]; srcs: string[]; count: number; events: QueueEvent[];
}

export interface ImportedAlert {
  status: 'ok' | 'empty' | 'error'; message?: string;
  event_time?: string; rule_name: string; urgency: string; src: string; dest: string; user: string;
  file_hash: string; domain: string; mitre: string; sig: string; deployed_spl: string;
  raw_event_data: Record<string, unknown>;
}

export interface EscuResult { status: string; matches?: { rule: string; score: number; data?: Record<string, any> }[]; message?: string }
export interface CtiResult { status: 'success' | 'unavailable'; message?: string; results?: Record<string, any> }

export interface Hypothesis { id: string; verdict?: string; description?: string }
export interface Plan {
  model_reasoning?: string; semantic_alignment?: string; alignment_reasoning?: string;
  hypotheses?: Hypothesis[]; tasks?: unknown[]; reasoning?: string; status?: string; verdict?: string;
}
export interface Tokens { prompt_tokens?: number; generation_tokens?: number; stop_reason?: string }

export interface Entity { type: string; value: string }
export interface SentTask { task_id: string; hypothesis_id: string; question: string; entity: Entity[]; time_window: { start: string; end: string } }
export interface Dropped { task_id: string | null; question?: string; why: string; sent?: boolean }
export interface Handoff { tasks: SentTask[]; dropped: Dropped[]; task_file: string }

export interface Step {
  step_id: string; family: string; objective: string; categories?: string[];
  completed?: boolean; rows_retrieved?: number | null; confirmed_empty?: boolean; status?: string | null; reason?: string | null;
}
export interface BrokerRun {
  task_id: string; run_dir: string | null; trace_id?: string; plan_rationale?: string; classification?: string;
  plan_repairs?: unknown[]; spend_micro_usd?: number; steps?: Step[]; dispatched?: string[];
  results?: { family: string; status: string; reason?: string; error?: string; gaps?: string[]; queries?: string[]; blocked?: string[] }[];
}
export interface Handshake { sent: string[]; fetched: string[]; returned: string[]; not_fetched: string[]; not_returned: string[]; unexpected: string[] }

export interface DomainFinding { domain: string; narrative: string; observations?: string[]; summaries?: string[]; facts?: string[] }
export interface Payload { task_id: string; run_id?: string; hypothesis_id: string; hypothesis?: string; findings: DomainFinding[] }
export interface PayloadBatch { batch_id?: string; payloads?: Payload[] }

export interface Synthesis {
  hypothesis_scores?: Record<string, number | string>; verdict?: string; verdict_reasoning?: string;
  evidence_refs?: string[]; status?: 'VERDICT_REACHED' | 'REQUIRES_INVESTIGATION'; evidence_gaps?: string[];
  refused_refs?: string[]; follow_up_tasks?: { question?: string }[];
  verdict_confidence?: number; confidence?: number; reasoning?: string; executive_summary?: string;
}

export type StreamEvent =
  | { type: 'analyst'; data: Plan; message: string; tokens?: Tokens }
  | { type: 'handoff'; data: Handoff; message: string; loop: number }
  | { type: 'broker_log'; data: { line: string }; message: string; loop: number }
  | { type: 'broker'; data: { runs: BrokerRun[]; handshake: Handshake }; message: string; loop: number }
  | { type: 'payload'; data: PayloadBatch; message: string; loop: number }
  | { type: 'synthesis'; data: Synthesis; message: string; loop: number; reasoning?: string; tokens?: Tokens }
  | { type: 'verdict'; data: Synthesis; message: string }
  | { type: 'paused' | 'resumed' | 'done' | 'stopped'; data?: object; message: string }
  | { type: 'error'; data?: object; message: string; trace?: unknown; cut_off?: CutOff };

// An Analyst call that used its whole max_gen_len (stop_reason=length): a model failure, not a verdict (T15).
export interface CutOff { stage: 'planning' | 'synthesis'; loop: number; max_gen_len: number; prompt_tokens: number }

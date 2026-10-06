# Analyst hand-off, 2026-10-06

Findings from the web-console work that need a change on the **main Analyst** side (`webapp/prompts/system_prompt.txt`, the evaluation header in `webapp/main.py` `_run_investigation`, the synthesis schema). The integration side has not touched any of these. Evidence is the run folders under `.smartops/runs/<run_id>/`.

## 1. The Analyst <-> Tool Broker loop stopped looping after `330d1bc`

Commit `330d1bc` (2026-10-05, "port the analyst branch's keepers by hand") added the evaluation header. It lists the required fields as `hypothesis_scores`, `verdict`, `verdict_reasoning`, `evidence_refs`, `status`. It does not list `follow_up_tasks`, and it says "Do NOT output planning JSON (hypotheses list, tasks list)".

Since then the model returns no follow-ups, so a loop that misses the evidence gate has nothing to send and the run stops after one round:

| Run | When | Loops | Follow-ups per loop |
|---|---|---|---|
| `04a15495` | 10-01 | 2 | 2, 0 |
| `a8118db9` | 10-01 | 3 | 2, 2, 0 |
| `e1461da6` | 10-05 14:49 | 2 | 3, 0 |
| `67da804d` | 10-05 15:40 | 1 | 0 (status REQUIRES_INVESTIGATION) |
| `dbb0e75c` | 10-05 16:14 | 1 | 0 (REQUIRES_INVESTIGATION) |
| `dce405e5` | 10-06 09:08 | 1 | 0 (REQUIRES_INVESTIGATION) |
| `30b729b6` | 10-06 12:16 | 1 | 0 (REQUIRES_INVESTIGATION) |

The integration side is ready for follow-ups: `run_trace.follow_up_tasks` turns `follow_up_tasks: [{task_id, question}]` into the next round's tasks, inheriting the entities and widest window of the tasks just sent.

**Ask:** put `follow_up_tasks` back in the evaluation output (required when `status` is REQUIRES_INVESTIGATION), and make clear it isn't the forbidden "tasks list".

## 2. Entity types the broker accepts

The broker contract (`task-input.v1`, `EntityKind` in `engine/contracts/src/contracts/subtask.py`) now accepts:

`host, user, ip, file_hash, domain, url, process, file_name, command_line`

`file_name` and `command_line` were added today, so tasks like "was `OneDrive.exe` replaced" or "decode `JAB...`" now reach the SIEM agent.

The handoff now also absorbs the common drift:
- **Spellings:** `ip_address`, `username`, `sha256`, `file_path` and so on map to the nine types.
- **Joined types:** `scheduled_task|group_policy` is split and each part tried.
- **Where to look rather than what to match:** a task whose entity is something like `log`, `script_block_log` or `scheduled_task` is no longer dropped. It's sent scoped to the alert's own host and user, and the SIEM agent searches the lab's indexes. The handoff card shows it as "sent changed".

Seen in `90ccaa99` (T4 `log`, T5 `file`) and `4e926f17` (`file`, `ip_address`, `scheduled_task|group_policy|change_request`, `script_block_log`).

**Ask:** list the nine types in the planning prompt. The entity is the value to match (host, process, user...), never the data source. The fallback scopes to the whole alert, which is broader than a precise entity.

## 3. Zero-width time windows

In the `dbf00ccc` repro, two tasks had `start == end == event_time` (`11:39:17Z` to `11:39:17Z`). The handoff drops those, because the broker's `Scope` needs start before end.

**Ask:** the planning prompt asks for a window around the event (for example, minutes before to minutes after), start strictly before end.

## 4. Unparseable plan, no retry

Run `dbf00ccc`: the plan answer after `</think>` had no JSON that `extract_json` could read, so the plan had no hypotheses and no tasks, and the run ended at the handoff. Re-sending the identical prompt returned valid JSON (1870 vs 2301 output tokens), so the endpoint isn't deterministic at temperature 0. The raw answer was not kept, so the original can't be inspected.

**Ask:** keep the raw answer when parsing fails, and retry once.

## 5. Verdict reasoning and attack narrative

The evaluation schema has only `verdict_reasoning`. In `30b729b6`:
- The reasoning rested on the decoded command (`$env:username`) and on process lineage. That lineage was the Splunk forwarder's `splunk-powershell.exe` launched by `splunkd.exe`.
- It did not address the T5 endpoint findings: `powershell.exe` launched from OneDrive, reachability scripts to internal IPs, and a download from an internal HTTP address.
- `evidence_refs` were bare task ids (`T1`, `T2`...) rather than `<task_id>:<domain>`, and cited `T2`, which was never sent.

**Ask:** consider a required narrative (an ordered timeline citing finding refs) that has to account for every finding set returned, plus refs in the `<task_id>:<domain>` form.

## What the console shows now

The web console shows each of these as it happens:
- the dropped tasks and why
- whether the handshake held
- the synthesis "why" and cited evidence
- a "No verdict, leaning X, stopped: <reason>" panel when the gate didn't pass, instead of a bare verdict

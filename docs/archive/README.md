# Archive — superseded architecture prose

Kept for the reasoning it records, not as a description of the current system.
**Nothing here is maintained**, none of it is checked by `docs/check_anchors.py`,
and every `file:line` in it should be assumed stale.

For what the system does now, read [`../architecture.md`](../architecture.md) and
its three `confluence-*.md` companions. For *why* it does it, read
[`../PROJECT_DOCS.md`](../PROJECT_DOCS.md), compiled from `../sessions/`.

| File | What it was | Superseded because | Current through |
|---|---|---|---|
| `agent_architecture.md` | The deep dive on Broker internals, and the doc `README.md` pointed at | Predates the analyst tier entirely. `architecture.md` already disclaimed it, and `confluence-task-broker-architecture.md` now carries the fetch-tier depth | 2026-08-15 |
| `broker_agent_architecture.md` | A second, longer Broker architecture draft | Overlapped `agent_architecture.md` without ever being linked as a companion; two documents describing one subsystem at different dates | 2026-08-16 |
| `agy-skddles-handover.md` | A handover written before the `sessions/` convention existed | **Describes code that no longer exists** — `broker_flat.py` and the Arm S vs Arm F comparison, removed in `2dc5ff9`. Written directly to `docs/` rather than `docs/sessions/`, in the same week that convention started | 2026-08-13 |

Archived 2026-08-30. Nothing was deleted: a superseded document still explains why
a decision was made, and that is the part git history reads poorly.

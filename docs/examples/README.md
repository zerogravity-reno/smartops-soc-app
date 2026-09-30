# Example task files

Input for `smartops.main --task-file`, validated against
`contracts.TaskInputFile` and its published schema
`contracts/schemas/task-input.v1.schema.json`.

## `botsv3-coinhive-tasks.json`

The three hypotheses from the input template the Analyst side sent, in the shape
they sent them, with two changes for the BOTSv3 dataset.

**The window is 2018, deliberately.** BOTSv3 is 2018 data. The template's own
window is 2026, and a window over the wrong era returns no rows and looks
**identical** to a dataset that simply had nothing to say — which is why this
file exists rather than the received template being run directly.

`2018-08-20T00:00:00Z .. 2018-08-21T00:00:00Z` is not a guess. The saved run at
`.smartops/runs/cli-20260823T112627/` — the only one with real evidence in all
three domains — issued its SPL with `earliest=1534723200 latest=1534809600`,
which is exactly that pair, and the rows it returned are timestamped
2018-08-20T09:05Z to 15:07Z. `bench.DEFAULT_BOTSV3_TASK` uses the same window,
and `backend/tests/test_task_file.py` fails if this file ever drifts from it.

**`entity` is a list here.** The template sends a single object; the list form is
an extension of ours (see `contracts/src/contracts/task_input.py`), used so each
task carries the indicators BOTSv3 actually holds — `BSTOLL-L`, `coinhive.com`,
`bostoll` — instead of one. A producer sending a single object still validates.

Run it:

```bash
env -u AWS_PROFILE SMARTOPS_RUNS_DIR=/some/scratch/dir \
  uv run python -m smartops.main --task-file docs/examples/botsv3-coinhive-tasks.json
```

Add `--task-id botsv3-coinhive-consent` to run one hypothesis instead of all
three. **Point `SMARTOPS_RUNS_DIR` at a scratch directory** — the default
`.smartops/runs/` holds the saved runs used as replay fixtures.

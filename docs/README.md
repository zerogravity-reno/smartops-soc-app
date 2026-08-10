# SmartOps SOC App — Documentation

This folder holds a running, per-session record of *why* the project looks the
way it does — decisions, trade-offs, and what shipped — not a restatement of
what the code already says. If something is only discoverable by reading git
history or the source, it doesn't need a session entry.

## Adding a session entry

At the end of a work session, add one file to `sessions/`, named
`YYYY-MM-DD-<short-slug>.md`, starting with a small frontmatter block:

```markdown
---
date: 2026-08-05
title: Subtask contract, EDR diagram, backend scaffolding
---

## What we built
...

## Decisions
...

## Open items / next up
...
```

`date` and `title` are required — the compiler uses them for the table of
contents. Everything after the closing `---` is free-form markdown.

## Compiling

```
python docs/compile_docs.py
```

Reads every file in `sessions/`, sorts by filename (hence the date prefix),
and writes the concatenated result with a table of contents to
`docs/PROJECT_DOCS.md`. That file is generated — edit the session file and
recompile, never edit `PROJECT_DOCS.md` directly.

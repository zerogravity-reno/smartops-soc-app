# Repository instructions

## Branches and pull requests

- Create a dedicated topic branch before editing files for each new task. Use a descriptive name such as `docs/update-setup-guide` or `fix/incident-queue`.
- Do not commit or push directly to `main`. An environment's generic `work` branch is not a substitute for a task-specific branch.
- Use the existing checkout; create a Git worktree only when explicitly requested.
- Commit focused changes, push the topic branch, and open a pull request targeting `main`. Follow `.github/pull_request_template.md` and include relevant validation and limitations.
- Merge through pull request review only. Do not merge without the user's explicit instruction, and never bypass repository protection rules.
- If permissions or network access prevent pushing or opening the PR, preserve the work on its topic branch and report the exact blocker. Do not describe a compare link as a created PR.

## Development and handoff

- Read `CONTRIBUTING.md` for installation, startup, testing, and collaboration conventions. Read `README.md` for service configuration and architecture.
- Preserve existing user changes. Keep credentials, generated dependencies, builds, logs, and investigation output out of commits.
- Use the committed dependency lockfiles for routine setup. Application code, tests, manifests, and lockfiles must remain unchanged when the task is only environment setup.
- Run checks relevant to the change. For application changes, use the Python suite and/or frontend tests and build described in `CONTRIBUTING.md`; validate startup with a functional request when it changes. For documentation-only edits, check links, command syntax, and any newly documented behavior.
- Update contributor documentation when development commands or requirements change. Report passed, failed, skipped, and unrun checks accurately.
- Keep TLS and artifact verification enabled. Reuse existing credential bindings; never print or commit secret values. Live model investigations require an explicit request because they incur API charges.

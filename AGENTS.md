# Repository instructions

## Branches and pull requests

- Create a dedicated topic branch before editing files for each new task. Use a descriptive name such as `docs/update-setup-guide` or `fix/incident-queue`.
- Do not commit or push directly to `main`. An environment's generic `work` branch is not a substitute for a task-specific branch.
- Use the existing checkout; create a Git worktree only when explicitly requested.
- Commit focused changes, push the topic branch, and open a pull request targeting `main`. Follow `.github/pull_request_template.md` and include relevant validation and limitations.
- For Codex-requested changes, create the PR automatically and arrange GitHub auto-merge with `--squash`. Auto-merge completes only after the required checks pass and the code owner from `.github/CODEOWNERS` approves; the owner merges their own PRs through the review ruleset's bypass. Do not request a separate merge confirmation beyond that.
- Before enabling auto-merge, verify that the main branch requires PRs and the GitHub Actions `SmartOps CI` check from `.github/workflows/ci.yml`, with the branch up to date. Never use an administrator bypass, remove required checks, or fabricate an approval or passing result to make a merge pass. Do not silently change a live repository policy if it differs; report it unless the user authorized that policy change.
- If repository settings, permissions, unresolved discussions, or missing/failing CI prevent auto-merge, leave the PR open and report what is needed. Do not report auto-merge as enabled until GitHub confirms it.
- If permissions or network access prevent pushing or opening the PR, preserve the work on its topic branch and report the exact blocker. Do not describe a compare link as a created PR.

## Development and handoff

- Read `CONTRIBUTING.md` for installation, startup, testing, and collaboration conventions. Read `README.md` for service configuration and architecture.
- Preserve existing user changes. Keep credentials, generated dependencies, builds, logs, and investigation output out of commits.
- Use the committed dependency lockfiles for routine setup. Application code, tests, manifests, and lockfiles must remain unchanged when the task is only environment setup.
- Run checks relevant to the change. For application changes, use the Python suite and/or frontend tests and build described in `CONTRIBUTING.md`; validate startup with a functional request when it changes. For documentation-only edits, check links, command syntax, and any newly documented behavior.
- Update contributor documentation when development commands or requirements change. Report passed, failed, skipped, and unrun checks accurately.
- Keep TLS and artifact verification enabled. Reuse existing credential bindings; never print or commit secret values. Live model investigations require an explicit request because they incur API charges.

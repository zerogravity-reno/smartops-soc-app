# Autonomous discussion of the quality-gates RFC

The developers use GitHub comments; they do not need Codex accounts. The proposed [feedback workflow](../.github/workflows/rfc-feedback.yml) runs a separate Codex agent to reconcile discussion on [draft PR #9](https://github.com/zerogravity-reno/smartops-soc-app/pull/9). It does not resume the original chat or retain its private context. Its prompt supplies the proposal, authenticated human feedback, the previous bot reply, and the main checkout for source references.

## One-time activation

1. Add a funded OpenAI API key as the repository **Actions secret** named `RFC_FEEDBACK_API_KEY` in [Settings → Secrets and variables → Actions](https://github.com/zerogravity-reno/smartops-soc-app/settings/secrets/actions). Never paste the value into chat, comments, source files, or logs. The integration could not read the repository's secret metadata (HTTP 403), so existing secret availability is unverified.
2. Merge the automation PR through the existing protected PR/CI workflow. Comment-triggered and scheduled workflows must exist on the default branch to become active. The quality-gates proposal itself remains draft and unmerged.
3. Have either developer post feedback on PR #9, or run **Actions → RFC feedback reconciliation → Run workflow** to collect existing feedback. Verify that Codex completes and a `github-actions[bot]` reconciliation comment appears. A passing unit test or a no-feedback sweep is not end-to-end verification of the API key or model response.

Model calls use the repository owner's API account and incur API charges. New human feedback or a changed proposal revision can cause a call. An hourly sweep also consumes GitHub Actions runner time; idle sweeps and already-answered snapshots do not invoke the model. A job timeout and context/output budgets bound individual runs; they are not a monetary spending cap. Use an appropriately budgeted API project.

## Developer workflow

- @ysalahai discusses the main Analyst; @mrahmy-reno discusses the Tool Broker. @ayousry84 can contribute as requester.
- They can comment in Conversation, leave inline comments, submit review feedback, or edit their previous comments. No command or Codex subscription is required.
- The bot replies on the PR's Conversation tab with links to the original feedback, proposed wording/acceptance criteria, explicit agreement so far, unresolved conflicts, and targeted follow-up questions.
- Developers reply to that discussion normally. Each snapshot includes all supported feedback types rather than just the most recent comment. Events normally start a run promptly; an hourly sweep catches missed events/backlogs. GitHub queueing and scheduled-run delays mean a reply is not instantaneous or guaranteed at a fixed time.
- Agreement must identify the proposal revision/amendments being accepted. Silence and passing CI are not developer agreement. The bot proposes amendments in comments; it does **not** commit RFC edits. Once the developers agree, the requester can have the agreed amendments applied in the proposal PR and proceed with implementation PRs.

## Scope and controls

The fixed target is PR #9, from `docs/analyst-broker-quality-gates-rfc` in this repository to `main`, while it is open, draft, and has no auto-merge request. Only feedback authenticated as the two named owners or the requester is actionable. The original invitation comment is excluded from the initial backlog.

The official [Codex action](https://github.com/openai/codex-action) is pinned to a commit and runs as a read-only agent with privilege dropping on a fresh hosted runner. The model job has read permissions only. A separate job has permission to post issue comments, and its trusted publisher can only create a comment on PR #9. Neither job has repository-content write permission. Tokens are not passed through human comment text or embedded in the model prompt. The source checkout is the default branch, not executable PR code.

The publisher validates the model response, checks the PR and discussion again, suppresses duplicate snapshots, and drops stale results. Bot replies cannot trigger another model run; feedback from other authors is ignored. A fingerprint includes the proposal head and all eligible comment contents, so edits are detected. Oversized discussions fail visibly instead of silently omitting feedback. Model-generated statements still need to be assessed against the cited human comments; automation is not an authoritative vote counter or a proof of consensus.

The bot cannot edit application code, change CI or rules, approve either developer's work, mark a PR ready, or merge. Conflicts remain explicit questions for the responsible people. This preserves the request to agree on the quality-gates plan before implementing it.

To disable the bot, disable **RFC feedback reconciliation** in GitHub Actions. Closing PR #9, marking it ready, or enabling its auto-merge also makes the target ineligible. To change the target or participants, modify the workflow/script and this guide through a separate PR; it is deliberately not an unrestricted repository-wide assistant.

## Verification and limitations

The existing Python CI suite includes [offline bot tests](../tests/test_rfc_feedback.py) for event/identity filtering, target restrictions, edit detection, deduplication, stale feedback, output limits, literal handling of shell-like text, and the comment-only publisher. Workflow syntax is checked separately with `actionlint` during implementation.

The API key, a real Codex invocation, and the actual bot reply must be verified after activation. Missing credentials or GitHub organization restrictions can still prevent operation. No current chat, detached process in the onboarding machine, or fabricated scheduler is used as a substitute for that verification.

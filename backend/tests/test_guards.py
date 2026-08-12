"""The index scope guard: a boundary the model cannot argue with.

The 2026-08-11 live run issued every SPL as `index=*`, attributable only by luck
and invisible without a raw span dump. The design spec settled the fix as a
`BeforeToolCallEvent` hook rather than a prompt instruction, on the same
principle that already puts domain gating in code: a precondition is not a
judgement.
"""

import pytest
from smartops import subagents
from smartops.domains import DOMAINS
from smartops.guards import IndexScopeGuard

ALLOWLIST = ("botsv3",)


class _BeforeEvent:
    """Mirrors `strands.hooks.BeforeToolCallEvent` for the fields the guard uses.

    `cancel_tool` is `bool | str`; setting a string cancels the call and hands
    that string back to the model as an error tool result.
    """

    def __init__(self, name, tool_input):
        self.tool_use = {"name": name, "toolUseId": "tu-1", "input": tool_input}
        self.cancel_tool: bool | str = False


def _run(tool_input, name="splunk_run_query"):
    event = _BeforeEvent(name, tool_input)
    IndexScopeGuard("siem", ALLOWLIST)._check(event)
    return event


class TestAllowedQueriesPass:
    def test_an_allowlisted_index_is_not_cancelled(self):
        event = _run({"query": "index=botsv3 sourcetype=WinEventLog | stats count"})

        assert event.cancel_tool is False

    def test_quoting_and_spacing_do_not_evade_the_match(self):
        assert _run({"query": 'search index = "botsv3" | head 5'}).cancel_tool is False

    def test_case_is_not_significant(self):
        assert _run({"query": "INDEX=BOTSv3 | head 1"}).cancel_tool is False

    def test_a_tool_that_takes_no_search_is_untouched(self):
        """A tool that lists indexes has no SPL and must not be forced to pin one."""
        event = _run({}, name="splunk_get_indexes")

        assert event.cancel_tool is False


class TestDisallowedQueriesAreCancelled:
    def test_the_wildcard_index_is_rejected(self):
        """The exact failure this guard exists for."""
        event = _run({"query": "index=* sourcetype=WinEventLog | stats count"})

        assert isinstance(event.cancel_tool, str)
        assert "index=*" in event.cancel_tool
        assert "index=botsv3" in event.cancel_tool

    def test_a_named_but_disallowed_index_is_rejected(self):
        event = _run({"query": "index=main | head 10"})

        assert isinstance(event.cancel_tool, str)
        assert "index=main" in event.cancel_tool

    def test_a_wildcard_suffix_is_not_treated_as_a_match(self):
        assert isinstance(_run({"query": "index=bots* | head 1"}).cancel_tool, str)

    def test_a_search_with_no_index_at_all_is_rejected(self):
        """The spec requires a *literal* allowlisted index, not merely the absence
        of a disallowed one -- an unpinned search runs against whatever the token's
        default indexes happen to be."""
        event = _run({"query": "sourcetype=WinEventLog | stats count by host"})

        assert isinstance(event.cancel_tool, str)
        assert "does not pin an index" in event.cancel_tool

    def test_one_disallowed_index_among_several_still_rejects(self):
        assert isinstance(
            _run({"query": "search index=botsv3 OR index=main | head 5"}).cancel_tool, str
        )

    def test_the_query_is_found_wherever_it_sits_in_the_input(self):
        """The tool schema comes from whichever MCP server is configured, so the
        guard cannot assume which parameter carries the search."""
        event = _run({"opts": {"searches": ["index=* | head 1"]}})

        assert isinstance(event.cancel_tool, str)

    def test_the_reason_tells_the_model_how_to_proceed(self):
        """`cancel_tool` becomes the tool result the model sees, so it is the only
        chance to get a corrected query rather than a repeated one."""
        reason = _run({"query": "index=* | head 1"}).cancel_tool

        assert "reissue" in reason.lower()


class TestRegistration:
    def test_siem_gets_a_guard(self):
        hooks = subagents._hooks_for("siem", subagents._EvidenceCollector())

        assert any(isinstance(h, IndexScopeGuard) for h in hooks)

    def test_a_domain_without_an_allowlist_gets_none(self):
        """`index_allowlist=None` means the domain has no index concept. Attaching
        a guard with nothing to allow would reject every search it makes."""
        assert DOMAINS["vt"].index_allowlist is None

        hooks = subagents._hooks_for("vt", subagents._EvidenceCollector())

        assert not any(isinstance(h, IndexScopeGuard) for h in hooks)

    def test_the_collector_is_still_registered_alongside(self):
        hooks = subagents._hooks_for("siem", subagents._EvidenceCollector())

        assert any(isinstance(h, subagents._EvidenceCollector) for h in hooks)


class TestCancelledCallsAreNotEvidence:
    """The guard and the evidence collector were built for different reasons; that
    they compose is worth pinning rather than assuming.

    Strands turns a cancelled call into a `ToolResult` with `status="error"`, and
    the collector skips error results -- so a blocked query cannot be reported as
    a finding about the estate.
    """

    def test_a_cancelled_call_does_not_become_evidence(self):
        collector = subagents._EvidenceCollector()

        cancel_message = _run({"query": "index=* | head 1"}).cancel_tool
        assert isinstance(cancel_message, str)

        # The shape Strands synthesises for a cancelled call.
        collector._record(
            _AfterEvent(
                {"name": "splunk_run_query"},
                {"status": "error", "content": [{"text": cancel_message}]},
            )
        )

        assert collector.calls == []


class _AfterEvent:
    def __init__(self, tool_use, result, exception=None):
        self.tool_use = tool_use
        self.result = result
        self.exception = exception


class TestItIsActuallyWiredToStrands:
    """The tests above drive `_check` directly, which proves the rule and not the
    wiring. This drives a real `HookRegistry` with the real event type, so a
    change to the hook protocol -- a renamed field, a different registration
    call -- fails here rather than silently disarming the guard in production.
    """

    @staticmethod
    def _dispatch(query):
        from unittest.mock import MagicMock

        from strands.hooks import BeforeToolCallEvent, HookRegistry

        registry = HookRegistry()
        registry.add_hook(IndexScopeGuard("siem", ALLOWLIST))

        event = BeforeToolCallEvent(
            agent=MagicMock(),
            selected_tool=None,
            tool_use={"name": "splunk_run_query", "toolUseId": "tu-1", "input": {"query": query}},
            invocation_state={},
        )
        dispatched, _ = registry.invoke_callbacks(event)
        return dispatched

    def test_the_registry_dispatches_to_the_guard_and_the_wildcard_is_cancelled(self):
        assert isinstance(self._dispatch("index=* | head 1").cancel_tool, str)

    def test_an_allowed_query_survives_the_real_dispatch(self):
        assert self._dispatch("index=botsv3 | head 1").cancel_tool is False


@pytest.mark.parametrize("family", sorted(DOMAINS))
def test_every_domain_declares_its_index_intent(family):
    """`None` and a tuple are both valid; an empty tuple is not, since it would
    forbid every query the domain could make."""
    allowlist = DOMAINS[family].index_allowlist

    assert allowlist is None or len(allowlist) > 0

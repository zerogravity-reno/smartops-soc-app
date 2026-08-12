import base64
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from contracts import Entity, Scope, SubtaskStatus

from smartops.tools.native import virustotal
from smartops.tools.native.virustotal import (
    API_KEY_ENV_VAR,
    Verdict,
    VirusTotalError,
    VirusTotalNotConfigured,
    enrich_scope,
    queryable_entities,
)


def make_scope(*entities):
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)
    return Scope(entities=list(entities), time_window=(now - timedelta(hours=1), now))


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    """A dummy key by default -- present so tests exercise the request path,
    fake so nothing can reach the real API even by accident."""
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-key-not-real")


# Captured before any patching: the factory below must construct a *real*
# client, and referring to `httpx.AsyncClient` inside it would resolve to the
# patched factory and recurse.
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def fake_transport(handler):
    """Installs an httpx transport that answers without touching the network.

    Patches the AsyncClient the module constructs, so no test can make a live
    VirusTotal call -- the free tier is 4 requests/minute and a test suite would
    exhaust it instantly.
    """

    def _factory(*args, **kwargs):
        kwargs.pop("timeout", None)
        return _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler), **kwargs)

    return _factory


def stats_response(*, malicious=0, suspicious=0, harmless=60, undetected=10, reputation=0):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },
                "reputation": reputation,
            }
        }
    }


class TestAuthAndAddressing:
    async def test_sends_the_x_apikey_header_not_authorization(self, monkeypatch):
        # The reason this module exists instead of strands_tools.http_request:
        # VirusTotal accepts only `x-apikey`, and the alternatives 401 silently.
        seen = {}

        def handler(request):
            seen["headers"] = dict(request.headers)
            return httpx.Response(200, json=stats_response())

        monkeypatch.setattr(virustotal.httpx, "AsyncClient", fake_transport(handler))
        await enrich_scope(make_scope(Entity(kind="ip", value="8.8.8.8")))

        assert seen["headers"]["x-apikey"] == "test-key-not-real"
        assert "authorization" not in seen["headers"]

    async def test_the_api_key_is_never_a_tool_parameter(self):
        # Structural guard on the actual threat: a key passed as tool input would
        # land in the model's context, the conversation history, and any span
        # that records tool inputs.
        for tool_fn in virustotal.TOOLS:
            params = tool_fn.tool_spec["inputSchema"]["json"]["properties"]
            assert not any("key" in name.lower() or "token" in name.lower() for name in params), (
                f"{tool_fn.tool_name} exposes a credential-shaped parameter: {sorted(params)}"
            )

    async def test_each_kind_hits_its_own_endpoint(self, monkeypatch):
        paths = []

        def handler(request):
            paths.append(request.url.path)
            return httpx.Response(200, json=stats_response())

        monkeypatch.setattr(virustotal.httpx, "AsyncClient", fake_transport(handler))
        await enrich_scope(
            make_scope(
                Entity(kind="file_hash", value="abc123"),
                Entity(kind="ip", value="8.8.8.8"),
                Entity(kind="domain", value="example.com"),
            )
        )

        assert paths == [
            "/api/v3/files/abc123",
            "/api/v3/ip_addresses/8.8.8.8",
            "/api/v3/domains/example.com",
        ]

    async def test_urls_are_addressed_by_unpadded_base64url(self, monkeypatch):
        # VirusTotal's own scheme, and the easiest part of this to get subtly
        # wrong -- padding included, or standard base64 instead of urlsafe.
        url = "https://example.com/a?b=c"
        seen = {}

        def handler(request):
            seen["path"] = request.url.path
            return httpx.Response(200, json=stats_response())

        monkeypatch.setattr(virustotal.httpx, "AsyncClient", fake_transport(handler))
        await enrich_scope(make_scope(Entity(kind="url", value=url)))

        expected = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        assert seen["path"] == f"/api/v3/urls/{expected}"
        assert "=" not in seen["path"].rsplit("/", 1)[1]


class TestPathEncoding:
    """Entity values are alert-derived and only checked for non-blankness, so
    nothing in one may be readable as URL path structure."""

    async def test_traversal_in_an_entity_value_cannot_redirect_the_request(self, monkeypatch):
        # The attack: httpx normalises `..` before sending, so an unencoded value
        # sent the AUTHENTICATED request to /api/v3/users/self -- which returns
        # 200, was read as a clean verdict for a known-bad domain, and stored a
        # payload containing the account's own API key as Evidence.
        seen = {}

        def handler(request):
            # `raw_path`, not `path`: httpx's `.path` percent-DECODES for
            # convenience, so it shows `a/../../users/self` even when the wire
            # bytes are correctly escaped. Asserting on `.path` would fail
            # against a correct fix and pass against no fix at all.
            seen["raw"] = request.url.raw_path.decode()
            return httpx.Response(200, json=stats_response())

        monkeypatch.setattr(virustotal.httpx, "AsyncClient", fake_transport(handler))
        await enrich_scope(make_scope(Entity(kind="domain", value="a/../../users/self")))

        assert seen["raw"] == "/api/v3/domains/a%2F..%2F..%2Fusers%2Fself"
        # The point: the value cannot escape its own path segment.
        assert "/users/self" not in seen["raw"]
        assert "/../" not in seen["raw"]

    async def test_query_and_fragment_characters_are_encoded(self, monkeypatch):
        # `?` or `#` would otherwise truncate the path and append attacker-chosen
        # query parameters to an authenticated request.
        seen = {}

        def handler(request):
            seen["url"] = str(request.url)
            return httpx.Response(200, json=stats_response())

        monkeypatch.setattr(virustotal.httpx, "AsyncClient", fake_transport(handler))
        await enrich_scope(make_scope(Entity(kind="domain", value="evil.test?x=1#frag")))

        assert "?x=1" not in seen["url"]
        assert "#frag" not in seen["url"]
        assert "%3F" in seen["url"] and "%23" in seen["url"]


class TestPartialResults:
    """A run that stops partway must still return what it retrieved."""

    async def test_verdicts_retrieved_before_a_failure_survive(self, monkeypatch):
        # The loss this prevents: six indicators, rate limit on the third, and
        # the two completed lookups -- one of them a malicious hit -- were
        # discarded along with the exception.
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            if calls["n"] <= 2:
                return httpx.Response(200, json=stats_response(malicious=9))
            return httpx.Response(429, json={})

        monkeypatch.setattr(virustotal.httpx, "AsyncClient", fake_transport(handler))
        outcome = await enrich_scope(
            make_scope(
                Entity(kind="ip", value="1.1.1.1"),
                Entity(kind="ip", value="2.2.2.2"),
                Entity(kind="ip", value="3.3.3.3"),
                Entity(kind="ip", value="4.4.4.4"),
            )
        )

        assert len(outcome.verdicts) == 2
        assert all(v.is_flagged for v in outcome.verdicts)
        assert outcome.is_partial
        assert outcome.attempted == 4
        assert "rate limit" in outcome.failure

    async def test_a_missing_key_still_propagates(self, monkeypatch):
        # Nothing was attempted, which is a different condition from stopping
        # partway -- it must stay distinguishable so the caller can report
        # REJECTED rather than ERROR.
        monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)

        with pytest.raises(VirusTotalNotConfigured):
            await enrich_scope(make_scope(Entity(kind="ip", value="8.8.8.8")))


class TestFailureModes:
    async def test_missing_key_is_a_distinct_expected_condition(self, monkeypatch):
        monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)

        with pytest.raises(VirusTotalNotConfigured):
            await enrich_scope(make_scope(Entity(kind="ip", value="8.8.8.8")))

    async def test_404_is_a_finding_not_an_error(self, monkeypatch):
        # VirusTotal returns 404 for an indicator it has never seen. That is a
        # legitimate answer ("unknown"), not a broken lookup.
        monkeypatch.setattr(
            virustotal.httpx,
            "AsyncClient",
            fake_transport(lambda request: httpx.Response(404, json={})),
        )

        outcome = await enrich_scope(make_scope(Entity(kind="ip", value="8.8.8.8")))

        assert outcome.failure is None
        assert outcome.verdicts[0].found is False
        assert outcome.verdicts[0].is_flagged is False
        assert "unknown to VirusTotal" in outcome.verdicts[0].summary()

    async def test_429_reads_as_the_rate_limit_it_is(self, monkeypatch):
        # The free tier allows ~4 requests/minute, so this is expected traffic,
        # not a bug -- the message has to say so.
        monkeypatch.setattr(
            virustotal.httpx,
            "AsyncClient",
            fake_transport(lambda request: httpx.Response(429, json={})),
        )

        outcome = await enrich_scope(make_scope(Entity(kind="ip", value="8.8.8.8")))

        assert "rate limit" in outcome.failure
        assert outcome.verdicts == []

    async def test_401_names_the_env_var_to_check(self, monkeypatch):
        monkeypatch.setattr(
            virustotal.httpx,
            "AsyncClient",
            fake_transport(lambda request: httpx.Response(401, json={})),
        )

        outcome = await enrich_scope(make_scope(Entity(kind="ip", value="8.8.8.8")))

        assert API_KEY_ENV_VAR in outcome.failure

    async def test_error_messages_never_contain_the_key(self, monkeypatch):
        monkeypatch.setenv(API_KEY_ENV_VAR, "super-secret-value")
        monkeypatch.setattr(
            virustotal.httpx,
            "AsyncClient",
            fake_transport(lambda request: httpx.Response(500, json={})),
        )

        outcome = await enrich_scope(make_scope(Entity(kind="ip", value="8.8.8.8")))

        assert "super-secret-value" not in (outcome.failure or "")

    async def test_a_200_without_analysis_stats_is_refused_not_read_as_clean(self, monkeypatch):
        # Defence in depth behind the path-encoding fix: this is exactly the
        # shape a request redirected to a non-indicator endpoint returns, and
        # reporting it as "0 malicious" would call a known-bad indicator clean.
        monkeypatch.setattr(
            virustotal.httpx,
            "AsyncClient",
            fake_transport(lambda request: httpx.Response(200, json={"data": {"attributes": {}}})),
        )

        outcome = await enrich_scope(make_scope(Entity(kind="domain", value="evil.example")))

        assert outcome.verdicts == []
        assert "no analysis stats" in outcome.failure


class TestScopeFiltering:
    def test_only_queryable_kinds_are_selected(self):
        scope = make_scope(
            Entity(kind="user", value="someuser"),
            Entity(kind="ip", value="8.8.8.8"),
            Entity(kind="host", value="web01"),
            Entity(kind="file_hash", value="abc"),
        )

        assert [e.kind for e in queryable_entities(scope)] == ["ip", "file_hash"]

    async def test_a_scope_with_nothing_queryable_makes_no_request(self, monkeypatch):
        # A mixed scope must not send the user or host to VirusTotal, and a scope
        # with none of its kinds must not spend a request at all.
        def handler(request):  # pragma: no cover - must not be reached
            raise AssertionError(f"unexpected request to {request.url}")

        monkeypatch.setattr(virustotal.httpx, "AsyncClient", fake_transport(handler))

        outcome = await enrich_scope(make_scope(Entity(kind="user", value="someuser")))

        assert outcome.verdicts == []
        assert outcome.failure is None  # nothing to look up is not a failure
        assert outcome.attempted == 0


class TestVerdict:
    def test_flagged_when_any_engine_says_malicious_or_suspicious(self):
        base = dict(entity=Entity(kind="ip", value="1.1.1.1"), harmless=60, undetected=5, reputation=0, found=True, raw={})

        assert Verdict(malicious=1, suspicious=0, **base).is_flagged
        assert Verdict(malicious=0, suspicious=1, **base).is_flagged
        assert not Verdict(malicious=0, suspicious=0, **base).is_flagged

    def test_summary_quotes_counts_against_the_engine_total(self):
        verdict = Verdict(
            entity=Entity(kind="ip", value="1.1.1.1"),
            malicious=3,
            suspicious=1,
            harmless=50,
            undetected=6,
            reputation=-10,
            found=True,
            raw={},
        )

        assert verdict.summary() == "ip=1.1.1.1: 3 malicious / 1 suspicious of 60 engines"


class TestBrokerIntegration:
    """The path that makes `vt` return real evidence with no model at all."""

    async def test_a_flagged_indicator_produces_ok_plus_citable_evidence(self, monkeypatch):
        from smartops.broker import broker_task
        from smartops.budget import Budget, ModelChoice

        import test_broker  # reuse the broker suite's fakes rather than re-inventing them

        monkeypatch.setattr(
            virustotal.httpx,
            "AsyncClient",
            fake_transport(lambda request: httpx.Response(200, json=stats_response(malicious=7))),
        )

        task = test_broker.make_task(
            scope=make_scope(Entity(kind="ip", value="10.2.4.9"))
        )
        outcome = await broker_task(
            task,
            Budget.from_usd(1.0),
            model=ModelChoice(model_id="x", pricing_key="claude-sonnet-4-6"),
            invoke=test_broker.fake_invoker(["vt"]),
        )

        result = outcome.results[0]
        assert result.status == SubtaskStatus.OK
        # Projected by code from the parsed response, not retyped by a model.
        assert [v.malicious for v in result.findings.verdicts] == [7]
        # Evidence is the point: a citable record, and citations that resolve.
        assert len(result.evidence) == 1
        assert result.citation_ids == [result.evidence[0].id]
        assert result.evidence[0].tool_family == "vt"

    async def test_a_clean_indicator_is_no_data_not_ok(self, monkeypatch):
        # The triage distinction: the lookup succeeded and found nothing to act
        # on, which is different from finding something.
        from smartops.broker import broker_task
        from smartops.budget import Budget, ModelChoice

        import test_broker

        monkeypatch.setattr(
            virustotal.httpx,
            "AsyncClient",
            fake_transport(lambda request: httpx.Response(200, json=stats_response())),
        )

        outcome = await broker_task(
            test_broker.make_task(scope=make_scope(Entity(kind="ip", value="8.8.8.8"))),
            Budget.from_usd(1.0),
            model=ModelChoice(model_id="x", pricing_key="claude-sonnet-4-6"),
            invoke=test_broker.fake_invoker(["vt"]),
        )

        assert outcome.results[0].status == SubtaskStatus.NO_DATA
        assert outcome.results[0].evidence  # still citable, just nothing flagged


class TestLookupSerialisation:
    """The model-callable lookups must not stampede the free tier.

    `enrich_scope()` gets sequencing free from its own `for` loop, and its
    docstring explains why it needs it: at ~4 requests/minute "parallelism buys
    nothing and just turns one 429 into several." A subagent's model can request
    four lookups in a single turn, and Strands may run them concurrently -- the
    exact stampede that loop avoids.
    """

    async def test_concurrent_tool_lookups_do_not_overlap(self, monkeypatch):
        import asyncio

        from smartops.tools.native import virustotal

        overlapping = []
        active = 0

        async def fake_lookup(entity, **kwargs):
            nonlocal active
            active += 1
            overlapping.append(active)
            await asyncio.sleep(0)  # yield, so an unlocked version would interleave
            active -= 1
            return virustotal.Verdict(
                entity=entity,
                malicious=0,
                suspicious=0,
                harmless=1,
                undetected=0,
                reputation=0,
                found=True,
                raw={},
            )

        monkeypatch.setattr(virustotal, "_lookup", fake_lookup)

        await asyncio.gather(
            *(virustotal._tool_lookup("domain", f"d{i}.example") for i in range(4))
        )

        assert max(overlapping) == 1

    async def test_a_failed_lookup_cannot_be_read_as_clean(self, monkeypatch):
        from smartops.tools.native import virustotal

        async def rate_limited(entity, **kwargs):
            raise virustotal.VirusTotalError("429 rate limit exceeded")

        monkeypatch.setattr(virustotal, "_lookup", rate_limited)

        message = await virustotal._tool_lookup("domain", "coinhive.com")

        assert "LOOKUP FAILED" in message
        assert "NOT evidence that the indicator is clean" in message

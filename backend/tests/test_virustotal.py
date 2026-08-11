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

        verdicts = await enrich_scope(make_scope(Entity(kind="ip", value="8.8.8.8")))

        assert verdicts[0].found is False
        assert verdicts[0].is_flagged is False
        assert "unknown to VirusTotal" in verdicts[0].summary()

    async def test_429_reads_as_the_rate_limit_it_is(self, monkeypatch):
        # The free tier allows ~4 requests/minute, so this is expected traffic,
        # not a bug -- the message has to say so.
        monkeypatch.setattr(
            virustotal.httpx,
            "AsyncClient",
            fake_transport(lambda request: httpx.Response(429, json={})),
        )

        with pytest.raises(VirusTotalError, match="rate limit"):
            await enrich_scope(make_scope(Entity(kind="ip", value="8.8.8.8")))

    async def test_401_names_the_env_var_to_check(self, monkeypatch):
        monkeypatch.setattr(
            virustotal.httpx,
            "AsyncClient",
            fake_transport(lambda request: httpx.Response(401, json={})),
        )

        with pytest.raises(VirusTotalError, match=API_KEY_ENV_VAR):
            await enrich_scope(make_scope(Entity(kind="ip", value="8.8.8.8")))

    async def test_error_messages_never_contain_the_key(self, monkeypatch):
        monkeypatch.setenv(API_KEY_ENV_VAR, "super-secret-value")
        monkeypatch.setattr(
            virustotal.httpx,
            "AsyncClient",
            fake_transport(lambda request: httpx.Response(500, json={})),
        )

        with pytest.raises(VirusTotalError) as exc:
            await enrich_scope(make_scope(Entity(kind="ip", value="8.8.8.8")))

        assert "super-secret-value" not in str(exc.value)


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

        assert await enrich_scope(make_scope(Entity(kind="user", value="someuser"))) == []


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
        assert "7 malicious" in result.summary
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

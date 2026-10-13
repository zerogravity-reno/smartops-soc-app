"""VirusTotal v3 lookups for the `vt` family.

VirusTotal is a REST API, so this is a native tool rather than an MCP server --
there is nothing to host and no gateway to stand up.

**Why not `strands_tools.http_request`.** Its four auth types emit
`Authorization: Bearer|token|<raw>` or `X-API-Key`; VirusTotal requires
`x-apikey`, which none of them produce. The header *can* be supplied as tool
input instead, but tool input comes from the model -- so the API key would sit
in the prompt, in the conversation history, and in any span that records tool
inputs. Twenty lines of `httpx` keeps the key in the process environment where
it belongs.

Two entry points onto one HTTP path:

- `enrich_scope()` -- a direct, model-free lookup. Deciding *what* to ask
  VirusTotal needs no reasoning: the entity's kind selects the endpoint and its
  value is the argument. So this runs today, without a subagent or a model.
- The `@tool` functions -- the same lookups exposed for a model to call, for
  when the Aug-27 `vt` subagent wants to follow up on its own initiative.

⚠️ Confirm the auth header and the URL-identifier scheme against VirusTotal's
current documentation before trusting a live run; both are recorded here from
their v3 API as of writing, not verified against a live key.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import ValidationError
from strands import tool

from contracts import Entity, EntityKind, Scope
from smartops.errors import NotConfigured

logger = logging.getLogger(__name__)

API_ROOT = "https://www.virustotal.com/api/v3"
API_KEY_ENV_VAR = "VT_API_KEY"

# VirusTotal authenticates with this header specifically -- not `Authorization`,
# and not `X-API-Key`. Getting it wrong returns 401 with no hint.
_AUTH_HEADER = "x-apikey"

_DEFAULT_TIMEOUT = 15.0

# Which entity kinds VirusTotal can answer for, and the endpoint each uses.
_PATH_BY_KIND: dict[EntityKind, str] = {
    "file_hash": "files",
    "ip": "ip_addresses",
    "domain": "domains",
    "url": "urls",
}


class VirusTotalError(RuntimeError):
    """A lookup that was attempted and failed. Carries a message fit to put in a
    `SubtaskResult`, never the API key.

    Attempted-and-failed maps to `SubtaskStatus.ERROR`, which the contract
    defines as retryable -- as a rate limit or a transport blip should be.
    """


class VirusTotalNotConfigured(NotConfigured):
    """No API key in the environment. Expected, not exceptional -- it is how
    this runs before credentials exist.

    Deliberately **not** a `VirusTotalError`: nothing was attempted, so this maps
    to `REJECTED` rather than `ERROR`. Inheriting from the broker's `NotConfigured`
    is what lets `enrich_mission` distinguish the two without matching on messages.
    """


@dataclass(frozen=True)
class Verdict:
    """One indicator's reputation, reduced to what a decision needs.

    `raw` keeps the full response for the evidence store; the counts are what a
    summary line quotes.
    """

    entity: Entity
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    reputation: int | None
    found: bool
    raw: dict[str, Any]

    @property
    def is_flagged(self) -> bool:
        return self.malicious > 0 or self.suspicious > 0

    def summary(self) -> str:
        if self.raw.get("private"):
            return f"{self.entity.kind}={self.entity.value}: {self.raw['detail']}"
        if not self.found:
            return f"{self.entity.kind}={self.entity.value}: unknown to VirusTotal"
        engines = self.malicious + self.suspicious + self.harmless + self.undetected
        return (
            f"{self.entity.kind}={self.entity.value}: "
            f"{self.malicious} malicious / {self.suspicious} suspicious of {engines} engines"
        )


def _api_key() -> str:
    key = os.environ.get(API_KEY_ENV_VAR, "").strip()
    if not key:
        raise VirusTotalNotConfigured(f"{API_KEY_ENV_VAR} is not set")
    return key


def _identifier(entity: Entity) -> str:
    """The path segment VirusTotal expects for this entity.

    URLs are addressed by their unpadded base64url encoding rather than the URL
    itself -- VirusTotal's own scheme, and the one part of this that is easy to
    get subtly wrong.

    ⚠️ Everything else is percent-encoded with `safe=""`, so no character in an
    entity value can be read as path structure. Entity values derive from alert
    data and are only checked for non-blankness, so an unencoded value like
    `a/../../users/self` would have httpx normalise the dot segments and send the
    *authenticated* request to a different API resource entirely -- returning 200
    with no `last_analysis_stats`, which the caller would then report as a clean
    verdict for a known-bad indicator, while storing that endpoint's response
    (which for `/users/{id}` includes the account's own API key) as `Evidence`.
    """
    if entity.kind == "url":
        return base64.urlsafe_b64encode(entity.value.encode()).decode().rstrip("=")
    return quote(entity.value, safe="")


async def _lookup(entity: Entity, *, timeout: float = _DEFAULT_TIMEOUT) -> Verdict:
    """One GET against VirusTotal, with its failure modes named.

    A 404 is **not** an error: it means VirusTotal has never seen the indicator,
    which is a legitimate finding ("unknown") rather than a broken lookup. Every
    other non-2xx is an error the caller should surface.
    """
    path = _PATH_BY_KIND.get(entity.kind)
    if path is None:
        raise VirusTotalError(f"VirusTotal cannot be queried for a {entity.kind!r} observable")
    key = (entity.kind, entity.value)
    if key in _CACHE:
        return _CACHE[key]
    verdict = await _fetch(entity, path, timeout)
    _CACHE[key] = verdict  # errors raise above, so only answers are cached
    return verdict


# One round's tasks looked up the same hash 7 times (25965109). Per process, so per
# round; errors are never cached, so a rate limit is retried on the next ask.
_CACHE: dict[tuple[str, str], Verdict] = {}


def is_private_ip(value: str) -> bool:
    """An IP address that is not globally routable (RFC 1918, loopback, link-local...).
    False for anything that is not an IP address."""
    try:
        return not ipaddress.ip_address(value.strip()).is_global
    except ValueError:
        return False


def _is_private(entity: Entity) -> bool:
    """A private address has no reputation: 874ab334 looked up 192.168.40.211 and
    its harmless count reached synthesis as "no detected threats" against H1."""
    return entity.kind == "ip" and is_private_ip(entity.value)


async def _fetch(entity: Entity, path: str, timeout: float) -> Verdict:
    if _is_private(entity):
        return Verdict(entity=entity, malicious=0, suspicious=0, harmless=0, undetected=0,
                       reputation=None, found=False,
                       raw={"private": True, "detail": "private address, not looked up: VirusTotal holds no reputation for it"})

    url = f"{API_ROOT}/{path}/{_identifier(entity)}"
    headers = {_AUTH_HEADER: _api_key(), "accept": "application/json"}

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(url, headers=headers)

    if response.status_code == 404:
        return Verdict(
            entity=entity,
            malicious=0,
            suspicious=0,
            harmless=0,
            undetected=0,
            reputation=None,
            found=False,
            raw={"status": 404, "detail": "not found in VirusTotal"},
        )
    if response.status_code == 401:
        raise VirusTotalError(f"VirusTotal rejected the API key (check {API_KEY_ENV_VAR})")
    if response.status_code == 429:
        # The free tier allows ~4 requests/minute; a multi-indicator
        # investigation will hit this, so it must read as an expected condition.
        raise VirusTotalError("VirusTotal rate limit reached (free tier allows ~4 requests/minute)")
    if response.status_code >= 400:
        raise VirusTotalError(f"VirusTotal returned HTTP {response.status_code}")

    body = response.json()
    attributes = body.get("data", {}).get("attributes", {})
    if "last_analysis_stats" not in attributes:
        # Defence in depth behind the encoding fix above: a 200 without analysis
        # stats is not an indicator verdict, so it must never be reported as a
        # clean one. Reaching here means we queried something that is not an
        # indicator object -- refuse to interpret it rather than inventing zeros.
        raise VirusTotalError(
            f"unexpected VirusTotal response for {entity.kind}={entity.value!r}: "
            "no analysis stats in the payload"
        )
    stats = attributes["last_analysis_stats"]
    return Verdict(
        entity=entity,
        malicious=int(stats.get("malicious", 0)),
        suspicious=int(stats.get("suspicious", 0)),
        harmless=int(stats.get("harmless", 0)),
        undetected=int(stats.get("undetected", 0)),
        reputation=attributes.get("reputation"),
        found=True,
        raw=body,
    )


def queryable_entities(scope: Scope) -> list[Entity]:
    """The entities in `scope` VirusTotal can actually answer for.

    The same precondition the Broker's entity gate applies, at the granularity
    that matters here: a scope can hold a queryable IP *and* an unqueryable
    user, and only the IP should be sent.
    """
    return [e for e in scope.entities if e.kind in _PATH_BY_KIND and not _is_private(e)]


@dataclass(frozen=True)
class Enrichment:
    """What a scope-wide lookup produced, including a partial result.

    `failure` set with a non-empty `verdicts` is the important case: some
    indicators were successfully looked up and then the run stopped. Those
    verdicts were paid for and may include a confirmed-malicious hit, so they
    must reach the caller rather than being discarded with the exception.
    """

    verdicts: list[Verdict]
    failure: str | None = None
    attempted: int = 0


async def enrich_scope(scope: Scope, *, timeout: float = _DEFAULT_TIMEOUT) -> Enrichment:
    """Look up every queryable entity in `scope`. Model-free.

    Sequential rather than concurrent, deliberately: the free tier's ~4
    requests/minute means parallelism buys nothing and just turns one 429 into
    several.

    Stops at the first hard failure but **returns what it already has**. An
    earlier version raised, which threw away every verdict retrieved before the
    failure -- so a six-indicator scope that hit the rate limit on the fifth
    lookup reported nothing at all, losing four completed results including any
    malicious hit among them.

    `VirusTotalNotConfigured` still propagates: no key means nothing was
    attempted, which is a different condition from a run that stopped partway.
    """
    entities = queryable_entities(scope)
    verdicts: list[Verdict] = []
    for entity in entities:
        try:
            verdicts.append(await _lookup(entity, timeout=timeout))
        except VirusTotalNotConfigured:
            raise
        except VirusTotalError as exc:
            return Enrichment(verdicts=verdicts, failure=str(exc), attempted=len(entities))
        except Exception as exc:  # transport errors, malformed JSON
            return Enrichment(
                verdicts=verdicts,
                failure=f"{type(exc).__name__}: {exc}",
                attempted=len(entities),
            )
    return Enrichment(verdicts=verdicts, attempted=len(entities))


# --- Model-callable surface (for the Aug-27 `vt` subagent) --------------------
#
# One tool per lookup shape rather than one polymorphic tool, so each carries
# its own description and the model cannot pass an IP where a hash is expected.


# Serialises the model-callable lookups. `enrich_scope()` gets sequencing for
# free from its own `for` loop, but a subagent's model can request four lookups
# in one turn and Strands may execute them concurrently -- which is precisely the
# stampede that loop was written to avoid: "the free tier's ~4 requests/minute
# means parallelism buys nothing and just turns one 429 into several."
#
# A lock rather than a rate limiter because the goal is only to stop *self*-
# inflicted concurrency. Pacing against VirusTotal's actual quota belongs with a
# real token bucket, once anything runs at a volume that needs one.
_LOOKUP_LOCK = asyncio.Lock()


async def _tool_lookup(kind: EntityKind, value: str) -> str:
    async with _LOOKUP_LOCK:
        try:
            entity = Entity(kind=kind, value=value)
        except ValidationError as exc:
            # `value` is model-authored, so `Entity`'s allowlist rejects it here
            # rather than at a trusted producer -- an IDN in Unicode form, a
            # look-alike bracket, a value with structure in it. Caught for two
            # reasons. Strands turns an uncaught exception into a tool result of
            # `status: "error"` with the text `Error: ValidationError - 1
            # validation error for Entity...` (`tools/decorator.py:657-668`);
            # that is not a crash, but it reaches the model wrapped in pydantic's
            # shape and *without* this file's one invariant -- that no failure
            # may read as a clean verdict. So it is restated in the house wording
            # below, with the contract's own message kept because that is the
            # part telling the model what to send instead (punycode, or a
            # percent-encoded `<`).
            reason = "; ".join(err["msg"].removeprefix("Value error, ") for err in exc.errors())
            return (
                f"REJECTED: {value!r} is not a valid {kind} to look up -- {reason}. "
                "No lookup was attempted, so this is NOT evidence that the indicator "
                "is clean. Correct the value and call this tool again."
            )
        try:
            verdict = await _lookup(entity)
        except VirusTotalError as exc:
            # Worded so a model cannot read a failure as a clean verdict. "not
            # found" and "we could not ask" are opposite conclusions about an
            # indicator, and only one of them is evidence.
            return (
                f"LOOKUP FAILED for {kind} {value} -- no reputation data was retrieved: {exc}. "
                "This is NOT evidence that the indicator is clean."
            )
    return verdict.summary()


@tool
async def vt_lookup_file_hash(file_hash: str) -> str:
    """Look up a file's reputation in VirusTotal by MD5, SHA-1, or SHA-256 hash.

    Returns how many antivirus engines flagged it as malicious or suspicious, or
    reports that VirusTotal has never seen the file. Knows nothing about our own
    environment -- use the SIEM or EDR for that.

    Args:
        file_hash: An MD5, SHA-1, or SHA-256 hash of the file.
    """
    return await _tool_lookup("file_hash", file_hash)


@tool
async def vt_lookup_ip(ip: str) -> str:
    """Look up an IP address's reputation in VirusTotal.

    Returns third-party detection counts for the address, or reports it as
    unknown. This is external reputation only -- for traffic to or from the
    address in our environment, use the NDR or SIEM.

    Args:
        ip: An IPv4 or IPv6 address.
    """
    return await _tool_lookup("ip", ip)


@tool
async def vt_lookup_domain(domain: str) -> str:
    """Look up a domain's reputation in VirusTotal.

    Returns third-party detection counts for the domain, or reports it as
    unknown. External reputation only.

    Args:
        domain: A domain name, without scheme or path.
    """
    return await _tool_lookup("domain", domain)


@tool
async def vt_lookup_url(url: str) -> str:
    """Look up a URL's reputation in VirusTotal.

    Returns third-party detection counts for the URL, or reports it as unknown.
    External reputation only.

    Args:
        url: A full URL, including scheme.
    """
    return await _tool_lookup("url", url)


TOOLS = [vt_lookup_file_hash, vt_lookup_ip, vt_lookup_domain, vt_lookup_url]

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

import base64
import logging
import os
from dataclasses import dataclass
from typing import Any

import httpx
from contracts import Entity, EntityKind, Scope
from strands import tool

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
    """A lookup that could not be completed. Carries a message fit to put in a
    `SubtaskResult`, never the API key."""


class VirusTotalNotConfigured(VirusTotalError):
    """No API key in the environment. Expected, not exceptional -- it is how
    this runs before credentials exist."""


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
    """
    if entity.kind == "url":
        return base64.urlsafe_b64encode(entity.value.encode()).decode().rstrip("=")
    return entity.value


async def _lookup(entity: Entity, *, timeout: float = _DEFAULT_TIMEOUT) -> Verdict:
    """One GET against VirusTotal, with its failure modes named.

    A 404 is **not** an error: it means VirusTotal has never seen the indicator,
    which is a legitimate finding ("unknown") rather than a broken lookup. Every
    other non-2xx is an error the caller should surface.
    """
    path = _PATH_BY_KIND.get(entity.kind)
    if path is None:
        raise VirusTotalError(f"VirusTotal cannot be queried for a {entity.kind!r} observable")

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
    stats = attributes.get("last_analysis_stats", {})
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
    return [entity for entity in scope.entities if entity.kind in _PATH_BY_KIND]


async def enrich_scope(scope: Scope, *, timeout: float = _DEFAULT_TIMEOUT) -> list[Verdict]:
    """Look up every queryable entity in `scope`. Model-free.

    Sequential rather than concurrent, deliberately: the free tier's ~4
    requests/minute means parallelism buys nothing and just turns one 429 into
    several. Raises on the first hard failure so the caller reports one clear
    reason rather than a partial result with a silent hole.
    """
    verdicts: list[Verdict] = []
    for entity in queryable_entities(scope):
        verdicts.append(await _lookup(entity, timeout=timeout))
    return verdicts


# --- Model-callable surface (for the Aug-27 `vt` subagent) --------------------
#
# One tool per lookup shape rather than one polymorphic tool, so each carries
# its own description and the model cannot pass an IP where a hash is expected.


async def _tool_lookup(kind: EntityKind, value: str) -> str:
    try:
        verdict = await _lookup(Entity(kind=kind, value=value))
    except VirusTotalError as exc:
        return f"lookup failed: {exc}"
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

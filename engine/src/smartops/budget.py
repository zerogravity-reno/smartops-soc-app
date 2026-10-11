"""Shared token/cost budget for a SmartOps investigation.

One Budget instance is created per investigation and threaded into every
LLM call, across every role -- planner, analyst, critic, and every
subagent domain. It answers two different questions:

1. Gating: should this call happen at all, given what is left?
2. Observability: once it happened, what did it actually cost, and who
   spent it -- planner vs. analyst vs. critic vs. subagent:edr, etc.?

Real per-call cost is not known until the response comes back (output
tokens especially can't be predicted ahead of time). So spend happens in
two steps: `reserve()` before the call is an atomic, concurrency-safe
admission check against a worst-case estimate; `settle()` after the call
reconciles that reservation against the real `usage` the API reports and
records it in the ledger. Nothing else in this module ever touches
`remaining` directly.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


_NANO_PER_MICRO = 1000


@dataclass(frozen=True)
class ModelPrice:
    """**nano-USD per token** (equivalently: USD per *billion* tokens).

    Integers, because every amount in this module is an integer -- money is
    never a float.

    An earlier version stored USD per *million* tokens, leaning on the tidy
    coincidence that USD/Mtok equals micro-USD/token. That only holds for
    whole-dollar rates. Every Claude tier is $1-$25/Mtok so it never bit us,
    but a sub-dollar model (DeepSeek is ~$0.27/Mtok) truncated to `0` -- which
    did not merely under-report cost: `estimate_cost()` feeds `reserve()`, so a
    zero input rate made the admission check wave everything through and budget
    gating silently stopped working on the cheapest provider.

    nano resolution spans $0.014/Mtok (14) to $25/Mtok (25_000) exactly, so one
    table prices every provider and `cost_of()` never learns which one ran.

    Cache multipliers are ratios on `input_per_token_nano`: a 5-minute-TTL cache
    write costs ~1.25x normal input price, a cache read ~0.1x. ⚠️ Ratios are an
    Anthropic-shaped abstraction -- Anthropic prices caching as a multiple of the
    base input rate, while some providers (DeepSeek) publish an absolute
    cache-hit price. Where the two aren't a clean ratio this is an
    approximation.

    These multipliers are now live rather than theoretical: `ModelChoice.
    cache_prefix` marks the tool schemas and system prompt as a cacheable
    prefix, so a multi-turn agent loop bills most of its input at the read rate.
    On Bedrock the ratios stay an approximation for the same reason every other
    figure here does -- `PRICING` holds Anthropic first-party rates and Bedrock
    is partner-operated.
    """

    input_per_token_nano: int
    output_per_token_nano: int
    cache_write_multiplier: float = 1.25
    cache_read_multiplier: float = 0.1
    long_context_threshold: int | None = None
    """Prompt tokens (input + cache reads + cache writes) above which ONE request
    bills at `long_context` instead. Per request, not per mission: Haiku 5.5 prices
    a 120k prompt at 5x, two 60k prompts at 1x."""
    long_context: ModelPrice | None = None


PRICING: dict[str, ModelPrice] = {
    # nano-USD per token: $5.00/Mtok -> 5_000. Rates from platform.claude.com/docs pricing, 2026-10-11.
    "claude-opus-5-5": ModelPrice(input_per_token_nano=4_000, output_per_token_nano=20_000, cache_read_multiplier=0.05),
    "claude-sonnet-5-5": ModelPrice(input_per_token_nano=2_000, output_per_token_nano=10_000, cache_read_multiplier=0.05),
    "claude-haiku-5-5": ModelPrice(
        input_per_token_nano=100, output_per_token_nano=500, long_context_threshold=100_000,
        long_context=ModelPrice(input_per_token_nano=500, output_per_token_nano=2_500),
    ),
    "claude-opus-5": ModelPrice(input_per_token_nano=5_000, output_per_token_nano=25_000),
    "claude-sonnet-5": ModelPrice(input_per_token_nano=2_000, output_per_token_nano=10_000),
    "claude-sonnet-4-6": ModelPrice(input_per_token_nano=3_000, output_per_token_nano=15_000),
    "claude-haiku-4-5": ModelPrice(input_per_token_nano=1_000, output_per_token_nano=5_000),
}
"""Anthropic **first-party** rates: exact on `Provider.ANTHROPIC`.

⚠️ These are NOT Bedrock rates. Amazon Bedrock is partner-operated with its own
separate price list, so every figure a `ModelChoice` bills through a Bedrock
`model_id` is an approximation until re-baselined against
https://aws.amazon.com/bedrock/pricing/. Relative ordering between tiers holds;
absolute numbers do not. `spend_by_role()` is therefore directionally correct on
Bedrock and not an invoice.
"""



def _nano_to_micro(nano: int) -> int:
    """Round nano-USD to the ledger's micro-USD unit, half-up, in integers.

    One rounding, applied to a whole call's total -- never per token, which
    would compound. A call of only a handful of tokens on a very cheap model
    can still round to 0; micro-USD is the ledger's resolution and a real call
    is thousands of tokens.
    """
    return (nano + _NANO_PER_MICRO // 2) // _NANO_PER_MICRO


class Provider(StrEnum):
    """Which backend serves a model.

    Not cosmetic: it decides what `build()` hands to `Agent(model=...)`. Bedrock
    takes a bare id string, which Strands turns into a `BedrockModel`; anything
    OpenAI-compatible needs a constructed `Model` instance instead.
    """

    BEDROCK = "bedrock"
    DEEPSEEK = "deepseek"
    ANTHROPIC = "anthropic"


@dataclass(frozen=True)
class ModelChoice:
    """Pairs a provider-facing model id with the `PRICING` key that bills it.

    These are two different namespaces and conflating them is a real bug, not a
    style question. `Agent(model="claude-sonnet-5")` does not look anything up:
    Strands turns a bare string straight into `BedrockModel(model_id=...)`, so
    the value it needs is a Bedrock id like
    `us.anthropic.claude-sonnet-4-5-20250929-v1:0` -- including the `us.`/`eu.`
    inference-profile prefix on-demand throughput requires. `PRICING` is keyed
    by our own short names. One string cannot satisfy both; whichever you pick,
    the other call fails.

    Validating at construction means a bad pairing fails at startup rather than
    on the first billed call.

    ⚠️ `PRICING` holds Anthropic **first-party** rates. Bedrock is
    partner-operated with its own price list, so on Bedrock the ledger is an
    approximation until re-baselined -- relative ordering between tiers holds,
    absolute figures don't.
    """

    model_id: str
    pricing_key: str
    provider: Provider = Provider.BEDROCK
    region: str | None = None
    base_url: str | None = None
    api_key_env_var: str | None = None
    connect_timeout: float = 10.0
    read_timeout: float = 120.0
    temperature: float = 0.3
    top_p: float | None = None
    effort: str | None = None
    """`output_config.effort` on the Anthropic API (low/medium/high/xhigh/max); None
    keeps the model's default. Ignored by the other providers."""
    max_tokens: int = 16_000
    """Per-request output ceiling the Anthropic API requires. Thinking counts
    against it; `Limits(output_tokens=...)` still caps the whole loop."""
    cache_prefix: bool = True
    """Whether to mark the tool schemas and system prompt as a cacheable prefix.

    Bedrock-only, and it has to be explicit: unlike the first-party Anthropic
    API, Bedrock has no automatic caching, so a `cachePoint` block is the only
    way to get one. What it buys is bounded but real -- the tool schemas and
    system prompt are byte-identical on every turn of an agent loop, so from the
    second turn on that prefix bills at the cache-read rate instead of full
    input price.

    On by default because the arithmetic favours it for anything multi-turn: a
    write costs ~1.25x input and a read ~0.1x, so two turns already come out
    ahead of paying full price twice (1.35x vs 2.0x) and the margin widens from
    there. The one configuration it loses on is a single-turn run, which pays
    the 1.25x write and never reads it back -- worth knowing, not worth gating,
    since neither the Broker nor a subagent finishes in one turn.

    Below the provider's minimum cacheable prefix the cache point is ignored
    rather than charged, so a short prompt costs nothing extra -- it just does
    not cache. `Usage` already carries both counters, so a run that silently
    fails to cache is visible as `cache_read_input_tokens == 0` rather than
    invisible.
    """

    def __post_init__(self) -> None:
        if not self.model_id.strip():
            raise ValueError("model_id must not be blank")
        if self.pricing_key not in PRICING:
            raise ValueError(
                f"no pricing entry for pricing_key {self.pricing_key!r} -- "
                f"known keys: {sorted(PRICING)}"
            )

    def build(self) -> Any:
        """What to pass as `Agent(model=...)`.

        Returns a bare id string for Bedrock -- Strands constructs the
        `BedrockModel` itself -- and a constructed `Model` for anything
        OpenAI-compatible, since a string would be misread as a Bedrock id.

        Imports the provider lazily so a deployment that never touches DeepSeek
        needn't have the `openai` extra installed to import this module.
        """
        if self.provider is Provider.BEDROCK:
            return self._build_bedrock()
        if self.provider is Provider.DEEPSEEK:
            return self._build_openai_compatible()
        if self.provider is Provider.ANTHROPIC:
            return self._build_anthropic()
        raise ValueError(f"unsupported provider {self.provider!r}")

    def _build_bedrock(self) -> Any:
        from botocore.config import Config
        from strands.models.bedrock import BedrockModel

        # `region_name` explicitly, because AWS_REGION loses to a configured AWS
        # profile and Strands then falls back to us-west-2 silently -- a wrong
        # region reads as a missing model. And an explicit request timeout,
        # because Python Bedrock has no default at all: a stuck connection would
        # hang the run forever, and `Limits` bounds tokens, not wall clock.
        kwargs: dict[str, Any] = {
            "model_id": self.model_id,
            "region_name": self.region,
            "temperature": self.temperature,
            "boto_client_config": Config(
                connect_timeout=self.connect_timeout,
                read_timeout=self.read_timeout,
                retries={"max_attempts": 2, "mode": "standard"},
            ),
        }
        if self.top_p is not None:
            kwargs["top_p"] = self.top_p
        if self.cache_prefix:
            # Appends a cache point after `toolConfig.tools`. The tool schemas
            # are the larger and more stable half of the prefix -- they are
            # identical on every turn -- so this is where most of the saving is.
            # `cache_prompt` would be the system-prompt equivalent but is
            # deprecated (bedrock.py:285); that half is done with an explicit
            # `cachePoint` block instead, via `system_prompt_blocks()`.
            kwargs["cache_tools"] = "default"
        return BedrockModel(**kwargs)

    def system_prompt_blocks(self, text: str) -> Any:
        """The system prompt in whatever form lets this provider cache it.

        Bedrock takes a list of `SystemContentBlock`s and caches everything
        before a `cachePoint`; `Agent` accepts either that list or a bare string
        (`agent.py:171`). Every other provider takes the string, so the
        provider-specific shape is decided here rather than at each of the three
        Agent construction sites -- otherwise adding a provider means finding
        all three again.
        """
        if self.provider is Provider.BEDROCK and self.cache_prefix:
            return [{"text": text}, {"cachePoint": {"type": "default"}}]
        return text

    def _build_anthropic(self) -> Any:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set")
        # No temperature/top_p: Opus 5.5, Sonnet 5.5 and Haiku 5.5 all reject them
        # with a 400. Top-level `cache_control` caches the tools + system prefix.
        params: dict[str, Any] = {"cache_control": {"type": "ephemeral"}}
        if self.effort:
            params["output_config"] = {"effort": self.effort}
        return _anthropic_model_class()(
            client_args={"api_key": api_key},
            model_id=self.model_id,
            max_tokens=self.max_tokens,
            params=params,
        )

    def _build_openai_compatible(self) -> Any:
        from strands.models.openai import OpenAIModel

        if not self.api_key_env_var:
            raise ValueError(f"provider {self.provider} requires api_key_env_var")
        api_key = os.environ.get(self.api_key_env_var, "").strip()
        if not api_key:
            raise ValueError(f"{self.api_key_env_var} is not set")

        # DeepSeek speaks the OpenAI wire format, so the only difference from
        # OpenAI proper is base_url. The key is read from the environment here
        # rather than stored on this object, so it cannot be logged by a repr.
        client_args: dict[str, Any] = {"api_key": api_key, "base_url": self.base_url}
        kwargs: dict[str, Any] = {
            "client_args": client_args,
            "model_id": self.model_id,
            "temperature": self.temperature,
        }
        if self.top_p is not None:
            kwargs["top_p"] = self.top_p
        return OpenAIModel(**kwargs)


PROVIDER_ENV_VAR = "SMARTOPS_LLM_PROVIDER"

# The env var that both *activates* Bedrock and supplies its model id. Keyed on
# the model id rather than AWS_REGION deliberately: AWS_REGION is set in almost
# any AWS environment (S3, CloudWatch, anything), so activating on it would
# select Bedrock for deployments that never intended to use it. The model id is
# Bedrock-specific and is the one value Bedrock cannot run without.
BEDROCK_MODEL_ID_ENV_VAR = "AWS_BEDROCK_MODEL_ID"

_PROVIDER_DEFAULTS: dict[Provider, dict[str, Any]] = {
    Provider.BEDROCK: {
        # No default model id: Strands' BedrockModel uses the legacy Converse
        # path, whose ARN-versioned inference-profile id carries a date suffix
        # that cannot be guessed. Requiring it is better than shipping a
        # placeholder that looks configured and 404s on the first call:
        #   aws bedrock list-inference-profiles --region <r> --query \
        #     "inferenceProfileSummaries[?contains(inferenceProfileId,'sonnet')].inferenceProfileId"
    },
    # Model id from SMARTOPS_MODEL_ID or a role's own (`model_choices_from_env`).
    # Chosen only by SMARTOPS_LLM_PROVIDER=anthropic: switching back is manual.
    Provider.ANTHROPIC: {},
    Provider.DEEPSEEK: {
        "model_id": "deepseek-chat",
        "base_url": "https://api.deepseek.com",
        "api_key_env_var": "DEEPSEEK_API_KEY",
    },
}


def infer_pricing_key(model_id: str) -> str | None:
    """Which `PRICING` row bills `model_id`, guessed from the id itself.

    A provider model id and a pricing key are different namespaces -- one is
    `us.anthropic.claude-sonnet-4-6-20260115-v1:0`, the other is
    `claude-sonnet-4-6` -- but the family name is embedded in the first, so
    requiring both to be configured is friction rather than information.

    Longest key first, so `claude-sonnet-4-6` is preferred over
    `claude-sonnet-5` when an id could loosely match both. Returns None rather
    than guessing when nothing matches, because billing against the wrong tier
    silently is worse than a startup error.
    """
    lowered = model_id.lower()
    for key in sorted(PRICING, key=len, reverse=True):
        family = key.removeprefix("claude-")
        if family in lowered or family.replace("-", ".") in lowered:
            return key
    return None


def available_provider() -> Provider | None:
    """Which provider this environment can actually serve, or None.

    Resolution is at **startup, from configuration** -- not failover on error.
    "Bedrock isn't in the env" is a config question; retrying a failed Bedrock
    call on DeepSeek is a different feature with different semantics (differing
    prices, differing capabilities, a partially-billed first attempt), and
    conflating the two would make an outage silently change which model, and
    which price, served a request.

    Returning None is a supported outcome, not an error: it means no live model
    is configured, and the caller falls back to a scripted invoker.
    """
    override = os.environ.get(PROVIDER_ENV_VAR, "").strip().lower()
    # `none` turns the Broker's model off even with credentials in the file (K2).
    # Blank stays "detect": a blank line in a copied .env must not change behaviour.
    if override == "none":
        return None
    if override:
        try:
            return Provider(override)
        except ValueError:
            raise ValueError(
                f"{PROVIDER_ENV_VAR}={override!r} is not a known provider -- "
                f"expected one of {[p.value for p in Provider]}"
            ) from None

    # Bedrock is the primary, so it is checked first: setting a Bedrock model id
    # is an explicit statement of intent, and a DeepSeek key left in the file
    # should not quietly take over from it.
    if os.environ.get(BEDROCK_MODEL_ID_ENV_VAR, "").strip():
        return Provider.BEDROCK
    if os.environ.get("DEEPSEEK_API_KEY", "").strip():
        return Provider.DEEPSEEK
    return None


def model_choice_from_env(
    provider: Provider | None = None, *, model_id: str | None = None, effort: str | None = None
) -> ModelChoice | None:
    """Build the `ModelChoice` this environment implies, or None if no provider.

    Model id comes from `AWS_BEDROCK_MODEL_ID` for Bedrock (or `SMARTOPS_MODEL_ID`
    for any provider). The pricing key is inferred from the model id, with
    `SMARTOPS_PRICING_KEY` as an explicit override for when inference can't --
    a new tier, or a rate that needs re-baselining.
    """
    provider = provider or available_provider()
    if provider is None:
        return None

    defaults = dict(_PROVIDER_DEFAULTS[provider])

    if provider is Provider.BEDROCK:
        if bedrock_id := os.environ.get(BEDROCK_MODEL_ID_ENV_VAR, "").strip():
            defaults["model_id"] = bedrock_id
    if env_id := os.environ.get("SMARTOPS_MODEL_ID", "").strip():
        defaults["model_id"] = env_id  # provider-agnostic override, wins
    if model_id:
        defaults["model_id"] = model_id  # a role's own id (`model_choices_from_env`)
    if effort:
        defaults["effort"] = effort

    # Model id before region: when both are missing, the id is the more
    # fundamental gap and naming it first is the more useful error.
    if not defaults.get("model_id"):
        raise ValueError(
            f"provider {provider.value!r} needs a model id -- "
            f"set {BEDROCK_MODEL_ID_ENV_VAR} (or SMARTOPS_MODEL_ID). For Bedrock: "
            f"aws bedrock list-inference-profiles --region <r>"
        )

    if provider is Provider.BEDROCK:
        region = (
            os.environ.get("AWS_REGION", "").strip()
            or os.environ.get("AWS_DEFAULT_REGION", "").strip()
        )
        if not region:
            # Activation is keyed on the model id, which is independent of the
            # region -- so without this check `region=None` reaches
            # `BedrockModel(region_name=None)` and Strands falls back to
            # us-west-2 *silently*. A deployment that chose eu-central-1 for data
            # residency would ship investigation data to a US region with no
            # error and no log line, which is the exact failure that passing
            # region_name explicitly was meant to prevent.
            raise ValueError(
                "Bedrock is selected but no region is set -- set AWS_REGION "
                "(or AWS_DEFAULT_REGION). Strands would otherwise default to "
                "us-west-2 without warning."
            )
        defaults["region"] = region

    # A role's own id is priced from that id: one SMARTOPS_PRICING_KEY would bill
    # every role at one tier.
    if not model_id and (pricing_key := os.environ.get("SMARTOPS_PRICING_KEY", "").strip()):
        defaults["pricing_key"] = pricing_key
    elif "pricing_key" not in defaults:
        inferred = infer_pricing_key(defaults["model_id"])
        if inferred is None:
            raise ValueError(
                f"cannot tell which PRICING entry bills model id "
                f"{defaults['model_id']!r} -- set SMARTOPS_PRICING_KEY to one of "
                f"{sorted(PRICING)}. Billing against the wrong tier silently is "
                f"worse than this error."
            )
        defaults["pricing_key"] = inferred

    return ModelChoice(provider=provider, **defaults)


ROLES = ("broker", "siem", "vt")
"""Broker roles that can each run their own model (K4). Recovery calls ride on
their family's agent: switching models mid-conversation drops its thinking."""

TIER_PRESETS: dict[str, dict[str, tuple[str, str]]] = {
    "A": {"broker": ("claude-opus-5-5", "high"), "siem": ("claude-sonnet-5-5", "medium"),
          "vt": ("claude-haiku-5-5", "low")},
    "B": {"broker": ("claude-sonnet-5-5", "high"), "siem": ("claude-haiku-5-5", "medium"),
          "vt": ("claude-haiku-5-5", "low")},
}
"""Anthropic-API tier sets for the K4 A/B test, picked by `SMARTOPS_BROKER_TIERS`.
Model ids, not Bedrock ids: on Bedrock only per-role env ids apply."""


def model_choices_from_env(provider: Provider | None = None) -> dict[str, ModelChoice] | None:
    """One `ModelChoice` per Broker role, or None if no provider.

    Per role: `SMARTOPS_MODEL_ID_<ROLE>` / `SMARTOPS_EFFORT_<ROLE>`, else the
    `SMARTOPS_BROKER_TIERS` preset (Anthropic only), else the single id every
    role used before.
    """
    provider = provider or available_provider()
    if provider is None:
        return None
    tier = os.environ.get("SMARTOPS_BROKER_TIERS", "").strip().upper()
    if tier and tier not in TIER_PRESETS:
        raise ValueError(f"SMARTOPS_BROKER_TIERS={tier!r} -- expected one of {sorted(TIER_PRESETS)}")
    preset = TIER_PRESETS[tier] if tier and provider is Provider.ANTHROPIC else {}
    choices = {}
    for role in ROLES:
        preset_id, preset_effort = preset.get(role, (None, None))
        choices[role] = model_choice_from_env(
            provider,
            model_id=os.environ.get(f"SMARTOPS_MODEL_ID_{role.upper()}", "").strip() or preset_id,
            effort=os.environ.get(f"SMARTOPS_EFFORT_{role.upper()}", "").strip() or preset_effort,
        )
    return choices


OUTPUT_TOKENS_PER_TURN = {"low": 1_000, "medium": 2_000, "high": 4_000}
"""Output one loop turn may take at each effort, thinking included (K4). The loop
caps were sized for Bedrock Sonnet 4.6, which did not think: siem had ~480 a turn."""
# ponytail: allowance per effort is an estimate; reset from the smoke run's per-turn usage


def loop_output_tokens(choice: ModelChoice, turns: int, default: int) -> int:
    """A loop's cumulative output cap: `turns` x the effort's allowance, else `default`."""
    per_turn = OUTPUT_TOKENS_PER_TURN.get(choice.effort or "")
    return turns * per_turn if per_turn else default


_FORCED_TOOL_CHOICE_REJECTED = ("claude-opus-5-5", "claude-sonnet-5-5")


def _anthropic_model_class() -> type:
    """Strands' `AnthropicModel`, with forced tool choice relaxed where it 400s.

    Strands forces `tool_choice: any` when a turn ends without the structured
    answer tool (`strands/event_loop/event_loop.py:366`); Opus 5.5 and Sonnet 5.5
    reject forced tool use. `auto` lets the model answer; if it still skips the
    tool, Strands raises and the step takes the existing no-answer ERROR path.
    """
    from strands.models.anthropic import AnthropicModel

    class _AnthropicModel(AnthropicModel):
        # ponytail: model-id match; ask the Models API for capabilities if the list grows
        def _format_tool_choice(self, tool_choice):  # type: ignore[override]
            if tool_choice and self.config["model_id"].startswith(_FORCED_TOOL_CHOICE_REJECTED):
                tool_choice = {"auto": {}}
            return AnthropicModel._format_tool_choice(tool_choice)

    return _AnthropicModel



def _price_for(model: str) -> ModelPrice:
    try:
        return PRICING[model]
    except KeyError:
        raise ValueError(f"no pricing entry for model {model!r} -- add one to PRICING") from None


class Usage(BaseModel):
    """Mirrors the fields on an Anthropic response's `usage` object."""

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cache_creation_input_tokens: int = Field(default=0, ge=0)
    cache_read_input_tokens: int = Field(default=0, ge=0)


def cost_of(model: str, usage: Usage) -> int:
    """Real cost of ONE completed request, in micro-USD (a long-context tier is
    judged per request; pass each call to `settle(calls=...)`).

    Accumulates in nano-USD and converts once at the end, so a sub-dollar rate
    survives the arithmetic instead of truncating to zero on the way in.
    """
    price = _price_for(model)
    prompt = usage.input_tokens + usage.cache_creation_input_tokens + usage.cache_read_input_tokens
    if price.long_context and price.long_context_threshold is not None and prompt > price.long_context_threshold:
        price = price.long_context
    nano = (
        usage.input_tokens * price.input_per_token_nano
        + usage.output_tokens * price.output_per_token_nano
        + round(usage.cache_creation_input_tokens * price.input_per_token_nano * price.cache_write_multiplier)
        + round(usage.cache_read_input_tokens * price.input_per_token_nano * price.cache_read_multiplier)
    )
    return _nano_to_micro(nano)


def usage_from(accumulated: dict) -> Usage:
    """Strands' camelCase usage dict (`inputTokens`, `cacheReadInputTokens`, ...)
    as this codebase's snake_case `Usage`."""
    return Usage(
        input_tokens=accumulated.get("inputTokens", 0),
        output_tokens=accumulated.get("outputTokens", 0),
        cache_creation_input_tokens=accumulated.get("cacheWriteInputTokens", 0),
        cache_read_input_tokens=accumulated.get("cacheReadInputTokens", 0),
    )


def call_usages(metrics: Any) -> list[Usage]:
    """Each model request's usage, from Strands' per-cycle metrics; [] when the
    metrics carry no cycles (scripted invokers, test doubles)."""
    return [usage_from(cycle.usage) for inv in getattr(metrics, "agent_invocations", None) or []
            for cycle in inv.cycles]


def estimate_cost(model: str, max_output_tokens: int, estimated_input_tokens: int = 0) -> int:
    """Worst-case cost of a call that hasn't happened yet, in micro-USD.

    Treats `max_output_tokens` as fully spent -- the real call will almost
    always cost less. This is a reservation ceiling, not a bill.

    This is the function whose zero-rate bug disabled budget gating: `reserve()`
    admits a call when this estimate fits in what's left, so an input rate that
    truncated to 0 made input-heavy calls look free and the ceiling stopped
    being a ceiling.
    """
    if max_output_tokens < 0 or estimated_input_tokens < 0:
        raise ValueError("token counts must be non-negative")
    price = _price_for(model)
    nano = (
        estimated_input_tokens * price.input_per_token_nano
        + max_output_tokens * price.output_per_token_nano
    )
    return _nano_to_micro(nano)


@dataclass(frozen=True)
class Reservation:
    """A pending charge returned by Budget.reserve(). Opaque to callers --
    pass it to settle() once the call finishes, and nowhere else."""

    role: str
    task_id: str | None
    model: str
    reserved_micro_usd: int
    reserved_output_tokens: int = 0
    """Output-token hold placed against the investigation-level ceiling, if one
    is set. Mirrors `reserved_micro_usd`: `settle()` credits back the unused
    portion, `release()` credits back all of it. Zero when no ceiling is
    configured, in which case `Budget` never reads it."""


class LedgerEntry(BaseModel):
    """One settled charge -- the unit the 'where did the tokens go' report
    is built from."""

    role: str
    task_id: str | None
    model: str
    usage: Usage
    cost_micro_usd: int
    at: datetime
    calls: int = 1
    """Model requests behind `usage` (a loop settles once for all of them)."""


class Budget:
    """One shared instance per investigation. Never per-domain, never
    per-subagent -- every role and every subagent call threads through the
    same instance, which is what makes `spend_by_role` meaningful.
    """

    def __init__(
        self,
        total_micro_usd: int,
        *,
        max_output_tokens_total: int | None = None,
    ) -> None:
        self._lock = asyncio.Lock()
        self._remaining = total_micro_usd
        self._output_remaining = max_output_tokens_total
        self._ledger: list[LedgerEntry] = []

    @classmethod
    def from_usd(
        cls,
        dollars: float,
        *,
        max_output_tokens_total: int | None = None,
    ) -> Budget:
        return cls(
            total_micro_usd=round(dollars * 1_000_000),
            max_output_tokens_total=max_output_tokens_total,
        )

    @property
    def remaining(self) -> int:
        """Micro-USD not yet reserved or spent. Read-only -- the only way
        to change it is through reserve()/settle()."""
        return self._remaining

    @property
    def output_tokens_remaining(self) -> int | None:
        """Output tokens left under the investigation-level ceiling, or None
        when no ceiling is configured.

        Why a second dimension at all: the USD reservation is sized from an
        *optimistic* input estimate (`_estimated_input_tokens` holds for ~8
        expected turns, not the 25-turn worst case), so `settle()` debiting the
        real cost can carry total spend past the USD ceiling when several long
        subagents run at once. Output tokens are the dominant cost and are already
        hard-capped per call by `Limits(output_tokens=...)`, so holding them
        against a single investigation-wide ceiling turns "roughly $N" into a
        genuine upper bound on the biggest cost driver, without tightening the
        input-side hold that keeps parallel subagents from colliding.
        """
        return self._output_remaining

    @property
    def ledger(self) -> list[LedgerEntry]:
        return list(self._ledger)

    async def reserve(
        self,
        *,
        role: str,
        model: str,
        max_output_tokens: int,
        task_id: str | None = None,
        estimated_input_tokens: int = 0,
    ) -> Reservation | None:
        """Atomic check-and-decrement against a worst-case estimate.
        Returns None (leaving `remaining` untouched) if it can't be
        covered -- the caller must stop immediately, not retry.

        Two ceilings are checked, not one: the USD budget always, and the
        output-token ceiling when configured. BOTH must fit before EITHER is
        decremented -- decrementing USD and only then finding the output ceiling
        blocks the call would leak the USD hold, so the checks precede the
        decrements inside the single lock acquisition.
        """
        amount = estimate_cost(model, max_output_tokens, estimated_input_tokens)
        async with self._lock:
            if amount > self._remaining:
                return None
            if (
                self._output_remaining is not None
                and max_output_tokens > self._output_remaining
            ):
                return None
            self._remaining -= amount
            if self._output_remaining is not None:
                self._output_remaining -= max_output_tokens
        return Reservation(
            role=role,
            task_id=task_id,
            model=model,
            reserved_micro_usd=amount,
            reserved_output_tokens=max_output_tokens,
        )

    async def release(self, reservation: Reservation) -> None:
        """Void a reservation that never resulted in a call -- e.g. the model/tool
        invocation raised before any response came back. Credits back the full
        reserved amount with no ledger entry, since nothing was actually spent.

        Callers must use this, not `settle()`, on the exception path: `settle()`
        always appends a ledger entry, which would misrepresent a call that never
        happened as a zero-cost one that did.
        """
        async with self._lock:
            self._remaining += reservation.reserved_micro_usd
            if self._output_remaining is not None:
                self._output_remaining += reservation.reserved_output_tokens

    async def settle(self, reservation: Reservation, usage: Usage, calls: list[Usage] | None = None) -> int:
        """Reconcile a reservation against what the call actually cost:
        credits back the unused portion of the reservation (or debits the
        shortfall, if real cost exceeded the estimate), and records the
        charge in the ledger. Returns the real cost in micro-USD."""
        # Per request when known: a tier judged on the summed loop would bill a
        # Haiku 5.5 loop of small prompts at its long-context rate.
        actual = sum(cost_of(reservation.model, c) for c in calls) if calls else cost_of(reservation.model, usage)
        async with self._lock:
            self._remaining += reservation.reserved_micro_usd - actual
            if self._output_remaining is not None:
                # Credit back the over-hold: the reservation withheld the
                # per-call output cap, the call produced fewer. Net effect over a
                # full reserve+settle cycle is `-= usage.output_tokens`, so
                # committed actuals plus outstanding holds can never exceed the
                # ceiling -- a hard upper bound on total output regardless of how
                # optimistic the USD-side input estimate was.
                self._output_remaining += (
                    reservation.reserved_output_tokens - usage.output_tokens
                )
            self._ledger.append(
                LedgerEntry(
                    role=reservation.role,
                    task_id=reservation.task_id,
                    model=reservation.model,
                    usage=usage,
                    cost_micro_usd=actual,
                    at=datetime.now(UTC),
                    calls=len(calls) if calls else 1,
                )
            )
        return actual

    def spend_by_role(self) -> dict[str, int]:
        """Total micro-USD spent so far, grouped by role -- e.g. planner
        vs. analyst vs. critic vs. subagent:edr. This is the report the
        whole redesign was for: where are the tokens actually going."""
        totals: dict[str, int] = {}
        for entry in self._ledger:
            totals[entry.role] = totals.get(entry.role, 0) + entry.cost_micro_usd
        return totals

    def usage_by_role(self) -> dict[str, dict[str, int]]:
        """Tokens and model requests per role (B30): whether caching hit, and
        output per request against `OUTPUT_TOKENS_PER_TURN`."""
        totals: dict[str, dict[str, int]] = {}
        for entry in self._ledger:
            t = totals.setdefault(entry.role, dict.fromkeys(
                ("calls", "input", "output", "cache_read", "cache_write"), 0))
            t["calls"] += entry.calls
            t["input"] += entry.usage.input_tokens
            t["output"] += entry.usage.output_tokens
            t["cache_read"] += entry.usage.cache_read_input_tokens
            t["cache_write"] += entry.usage.cache_creation_input_tokens
        return totals

    def spend_by_task(self) -> dict[str, int]:
        """Total micro-USD spent so far, grouped by task_id. Entries with
        no task_id -- planner/analyst/critic calls that aren't tied to a
        SubagentMission -- are excluded."""
        totals: dict[str, int] = {}
        for entry in self._ledger:
            if entry.task_id is None:
                continue
            totals[entry.task_id] = totals.get(entry.task_id, 0) + entry.cost_micro_usd
        return totals

    def spend_for_task(self, task_id: str) -> int:
        """Micro-USD settled against one task: its own entry and every mission
        minted under it (`<task_id>:<family>:…`, see `smartops.broker`). A batch
        shares one Budget, so this is the only per-task figure; c7dbf51d's
        reports read the bare key and dropped every subagent's spend."""
        prefix = f"{task_id}:"
        return sum(
            spend
            for key, spend in self.spend_by_task().items()
            if key == task_id or key.startswith(prefix)
        )

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
from dataclasses import dataclass
from datetime import datetime, timezone

from pydantic import BaseModel, Field


@dataclass(frozen=True)
class ModelPrice:
    """USD per million tokens -- which is, not by coincidence, also
    micro-USD per token. Every amount in this module is an integer number
    of micro-USD (1e-6 USD), so money is never a float.

    Cache multipliers are relative to `input_per_mtok`: a 5-minute-TTL
    cache write costs ~1.25x normal input price, a cache read ~0.1x.
    """

    input_per_mtok: int
    output_per_mtok: int
    cache_write_multiplier: float = 1.25
    cache_read_multiplier: float = 0.1


PRICING: dict[str, ModelPrice] = {
    "claude-opus-5": ModelPrice(input_per_mtok=5, output_per_mtok=25),
    "claude-sonnet-5": ModelPrice(input_per_mtok=3, output_per_mtok=15),
    "claude-sonnet-4-6": ModelPrice(input_per_mtok=3, output_per_mtok=15),
    "claude-haiku-4-5": ModelPrice(input_per_mtok=1, output_per_mtok=5),
}
"""Anthropic **first-party** rates, in USD per million tokens.

⚠️ These are NOT Bedrock rates. Amazon Bedrock is partner-operated with its own
separate price list, so every figure a `ModelChoice` bills through a Bedrock
`model_id` is an approximation until re-baselined against
https://aws.amazon.com/bedrock/pricing/. Relative ordering between tiers holds;
absolute numbers do not. `spend_by_role()` is therefore directionally correct on
Bedrock and not an invoice.
"""


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

    def __post_init__(self) -> None:
        if not self.model_id.strip():
            raise ValueError("model_id must not be blank")
        if self.pricing_key not in PRICING:
            raise ValueError(
                f"no pricing entry for pricing_key {self.pricing_key!r} -- "
                f"known keys: {sorted(PRICING)}"
            )


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
    """Real cost of a completed call, in micro-USD."""
    price = _price_for(model)
    return (
        usage.input_tokens * price.input_per_mtok
        + usage.output_tokens * price.output_per_mtok
        + round(usage.cache_creation_input_tokens * price.input_per_mtok * price.cache_write_multiplier)
        + round(usage.cache_read_input_tokens * price.input_per_mtok * price.cache_read_multiplier)
    )


def estimate_cost(model: str, max_output_tokens: int, estimated_input_tokens: int = 0) -> int:
    """Worst-case cost of a call that hasn't happened yet, in micro-USD.

    Treats `max_output_tokens` as fully spent -- the real call will almost
    always cost less. This is a reservation ceiling, not a bill.
    """
    if max_output_tokens < 0 or estimated_input_tokens < 0:
        raise ValueError("token counts must be non-negative")
    price = _price_for(model)
    return estimated_input_tokens * price.input_per_mtok + max_output_tokens * price.output_per_mtok


@dataclass(frozen=True)
class Reservation:
    """A pending charge returned by Budget.reserve(). Opaque to callers --
    pass it to settle() once the call finishes, and nowhere else."""

    role: str
    task_id: str | None
    model: str
    reserved_micro_usd: int


class LedgerEntry(BaseModel):
    """One settled charge -- the unit the 'where did the tokens go' report
    is built from."""

    role: str
    task_id: str | None
    model: str
    usage: Usage
    cost_micro_usd: int
    at: datetime


class Budget:
    """One shared instance per investigation. Never per-domain, never
    per-subagent -- every role and every subagent call threads through the
    same instance, which is what makes `spend_by_role` meaningful.
    """

    def __init__(self, total_micro_usd: int) -> None:
        self._lock = asyncio.Lock()
        self._remaining = total_micro_usd
        self._ledger: list[LedgerEntry] = []

    @classmethod
    def from_usd(cls, dollars: float) -> Budget:
        return cls(total_micro_usd=round(dollars * 1_000_000))

    @property
    def remaining(self) -> int:
        """Micro-USD not yet reserved or spent. Read-only -- the only way
        to change it is through reserve()/settle()."""
        return self._remaining

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
        covered -- the caller must stop immediately, not retry."""
        amount = estimate_cost(model, max_output_tokens, estimated_input_tokens)
        async with self._lock:
            if amount > self._remaining:
                return None
            self._remaining -= amount
        return Reservation(role=role, task_id=task_id, model=model, reserved_micro_usd=amount)

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

    async def settle(self, reservation: Reservation, usage: Usage) -> int:
        """Reconcile a reservation against what the call actually cost:
        credits back the unused portion of the reservation (or debits the
        shortfall, if real cost exceeded the estimate), and records the
        charge in the ledger. Returns the real cost in micro-USD."""
        actual = cost_of(reservation.model, usage)
        async with self._lock:
            self._remaining += reservation.reserved_micro_usd - actual
            self._ledger.append(
                LedgerEntry(
                    role=reservation.role,
                    task_id=reservation.task_id,
                    model=reservation.model,
                    usage=usage,
                    cost_micro_usd=actual,
                    at=datetime.now(timezone.utc),
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

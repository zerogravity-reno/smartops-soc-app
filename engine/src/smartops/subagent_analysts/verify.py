"""B52 E: does a cited row state what a sub-analyst line says it does?

The grounding gate (`analyze._apply_grounding`, `_drop_unsupported_figures`)
checks that a citation resolves and that its figures are in the rows. It cannot
see a line that cites real rows and misreads them. One call per finding, on the
cheapest Broker role's model, sends each presence line beside its rows and asks
only that. The verifier is as blind as the sub-analyst: no goal, no hypothesis.

Skipped (returns None) when the Budget refuses or the call fails: the lines then
cross unchecked, and the skip is logged and kept in traces.json, never sent on.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel, Field

from smartops.budget import Budget, call_usages, usage_from

logger = logging.getLogger(__name__)

VERIFY_ROLE = "verify"
_MAX_OUTPUT_TOKENS = 2_000
_CHARS_PER_TOKEN = 4

_SYSTEM = """\
You check claims against log rows. Each claim below is followed by the rows it cites.
For each claim, decide only this: do the rows state what the claim says? A claim that
names a value, process, account, address, command or action the rows do not contain is
unsupported. Do not judge whether the activity is good or bad, and do not weigh what it
means; wording and order do not matter, only whether the rows say it.
For an unsupported claim, the reason quotes the part of the row that differs."""


class Verdict(BaseModel):
    index: int = Field(description="The claim's number, as given.")
    supported: bool
    reason: str = Field(default="", description="Unsupported only: what the row says instead.")


class Verdicts(BaseModel):
    verdicts: list[Verdict]


ClaimVerifier = Callable[[list[tuple[str, str]]], Awaitable[list[Verdict] | None]]


def _prompt(claims: list[tuple[str, str]]) -> str:
    return "\n\n".join(f"CLAIM {i}: {line}\nROWS:\n{rows}" for i, (line, rows) in enumerate(claims))


async def _invoke(choice: Any, prompt: str) -> Any:
    from strands import Agent

    agent = Agent(model=choice.build(), system_prompt=_SYSTEM, structured_output_model=Verdicts,
                  callback_handler=None)
    return await agent.invoke_async(prompt)


def claim_verifier(choice: Any, budget: Budget, *, invoke=None) -> ClaimVerifier:
    """A `ClaimVerifier` billed to `budget` under the "verify" role."""
    invoke = invoke or _invoke

    async def verify(claims: list[tuple[str, str]]) -> list[Verdict] | None:
        prompt = _prompt(claims)
        reservation = await budget.reserve(
            role=VERIFY_ROLE, model=choice.pricing_key, max_output_tokens=_MAX_OUTPUT_TOKENS,
            estimated_input_tokens=(len(_SYSTEM) + len(prompt)) // _CHARS_PER_TOKEN,
        )
        if reservation is None:
            logger.warning("claim check skipped: the budget cannot cover a verify call")
            return None
        try:
            result = await invoke(choice, prompt)
        except Exception:
            await budget.release(reservation)
            logger.warning("claim check skipped: the verify call failed", exc_info=True)
            return None
        except BaseException:
            await budget.release(reservation)
            raise
        await budget.settle(reservation, usage_from(result.metrics.accumulated_usage), calls=call_usages(result.metrics))
        out = result.structured_output
        return out.verdicts if out is not None else None

    return verify

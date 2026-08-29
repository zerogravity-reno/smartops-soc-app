"""What the imported analyst model costs, which is not a function of tokens.

`smartops.budget` prices the Broker and the fetch subagents per token, because
that is how on-demand Bedrock bills a foundation model. The three domain analysts
run on a **custom-imported** model, and Bedrock bills those a different way
entirely:

> "Price per Custom Model Unit per min $0.05718" ... "You are billed in 5-minute
> windows for the duration your model copy is active starting from the first
> successful invocation." ... "If there are no invocations for a 5-minute period,
> Bedrock will scale down to zero and scale back up when you invoke your model."
> -- https://aws.amazon.com/bedrock/pricing/ (checked 2026-08-29)

So the bill is wall-clock on active model copies, and a token-priced estimate for
this model would not be an approximation of it -- it would be measuring the wrong
quantity. Three consequences worth knowing before reading a number out of here:

1. **Three analysts in one window cost the same as one.** `analyze.gather()` fans
   out with `asyncio.gather`, so all three land inside a single window. That is
   already the cost-optimal shape; serialising them would be strictly worse.
2. **Idle time between runs is free, and the first call after it is not.** A cold
   model must load, which is the `ModelNotReadyException` that
   `model._invoke_with_warmup` waits out. Those retry minutes are before the
   first *successful* invocation, so by the quoted rule they are not billed --
   but the scale-up they trigger opens a fresh window.
3. **A long gap costs more than a tight loop.** Ten calls spread over an hour can
   touch ten windows; ten calls in ninety seconds touch one.

This module deliberately does NOT reach into `Budget`. That ledger is
micro-USD-per-token keyed by role, and every entry in it answers "what did these
tokens cost". A per-minute charge shares no field with that question beyond the
currency, and forcing it in would make `spend_by_role()` mean two different
things depending on the row.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime

CMU_PRICE_PER_MINUTE_USD = 0.05718
"""us-east-1 / us-west-2 list price per Custom Model Unit per minute.

Frankfurt is $0.07144. Override with `SMARTOPS_ANALYST_CMU_PRICE` for another
region rather than editing this -- the figure is a list price that moves, and a
hardcoded edit is invisible to anyone reading a stored cost afterwards.
"""

BILLING_WINDOW_SECONDS = 300
"""The 5-minute window Bedrock bills in, and also the idle period after which it
scales the model copy to zero. One constant because it is one number in the
pricing text serving both roles: a gap longer than this both ends billing and
means the next call re-opens a window."""

CMU_COUNT_ENV_VAR = "SMARTOPS_ANALYST_CMU_COUNT"
CMU_PRICE_ENV_VAR = "SMARTOPS_ANALYST_CMU_PRICE"

DEFAULT_CMU_COUNT = 0
"""Zero, so an unconfigured deployment reports "unknown" rather than a wrong number.

How many CMUs a copy of an 8B model occupies is a property of the import job, not
something derivable from the model id -- read it from
`aws bedrock get-imported-model --model-identifier <arn>` and set
`SMARTOPS_ANALYST_CMU_COUNT`. Defaulting to a guess of 1 would produce a
plausible dollar figure that nobody would think to check, which is the failure
mode this whole module exists to avoid.
"""


@dataclass
class AnalystSpend:
    """Billed windows for one run's analyst calls.

    Records the instant of each *successful* invocation and derives the windows
    from them. Timestamps rather than a running total because the window
    arithmetic is not associative: whether two calls share a window depends on
    the gap between them, which a counter has already thrown away.
    """

    invocations: list[datetime] = field(default_factory=list)

    def record(self, at: datetime | None = None) -> None:
        """Note one successful invocation. Call AFTER the response returns.

        Before-the-call would count a `ModelNotReadyException` retry as billable;
        the pricing text starts the window at the first *successful* invocation,
        and a cold model that never answers is not one.
        """
        self.invocations.append(at or datetime.now(UTC))

    def billed_windows(self) -> int:
        """How many 5-minute windows these invocations opened.

        Walks the sorted instants and starts a new window whenever a call lands
        after the current window has closed. A call inside an open window is free
        -- which is what makes the concurrent fan-out in `gather()` cost the same
        as a single analyst.
        """
        if not self.invocations:
            return 0

        windows = 0
        window_ends_at = None
        for at in sorted(self.invocations):
            if window_ends_at is None or at >= window_ends_at:
                windows += 1
                window_ends_at = at.timestamp() + BILLING_WINDOW_SECONDS
                window_ends_at = datetime.fromtimestamp(window_ends_at, tz=UTC)
        return windows

    def billed_minutes(self) -> int:
        """Whole minutes billed. Each window bills its full 5 minutes even if the
        call took two seconds -- that is the point of a minimum window."""
        return self.billed_windows() * (BILLING_WINDOW_SECONDS // 60)

    def cost_usd(self, *, cmu_count: int | None = None) -> float | None:
        """Dollar cost, or `None` when the CMU count is unknown.

        `None` rather than 0.0: a run that spent money on an unconfigured
        deployment must not report as free. Callers render the difference.
        """
        cmus = cmu_count if cmu_count is not None else cmu_count_from_env()
        if cmus <= 0:
            return None
        return self.billed_minutes() * cmus * cmu_price_from_env()

    def summary(self, *, cmu_count: int | None = None) -> str:
        """One operator-readable line."""
        windows = self.billed_windows()
        if not windows:
            return "analyst model: no calls billed"

        cost = self.cost_usd(cmu_count=cmu_count)
        billed = f"{windows} window(s) x 5 min = {self.billed_minutes()} min"
        if cost is None:
            return (
                f"analyst model: {len(self.invocations)} call(s), {billed}; "
                f"cost unknown -- set {CMU_COUNT_ENV_VAR} (see "
                f"`aws bedrock get-imported-model`)"
            )
        return f"analyst model: {len(self.invocations)} call(s), {billed} = ${cost:.4f}"


def cmu_count_from_env() -> int:
    raw = os.environ.get(CMU_COUNT_ENV_VAR, "").strip()
    if not raw:
        return DEFAULT_CMU_COUNT
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_CMU_COUNT


def cmu_price_from_env() -> float:
    raw = os.environ.get(CMU_PRICE_ENV_VAR, "").strip()
    if not raw:
        return CMU_PRICE_PER_MINUTE_USD
    try:
        return float(raw)
    except ValueError:
        return CMU_PRICE_PER_MINUTE_USD

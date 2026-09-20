"""Exceptions shared across layers.

Lives apart from `broker.py` and the tool modules to avoid a cycle: the broker
imports the registry, which imports the tools, so a tool cannot import the
broker.
"""

from __future__ import annotations


class NotConfigured(Exception):
    """A domain's credential or connection is absent, so nothing was attempted.

    Deliberately distinct from a failed attempt, because the two map to
    different `SubtaskStatus` values with different downstream meanings:

    - `NotConfigured`  -> `REJECTED`: never attempted, and per the enum's
      docstring not retryable. Correct for "no API key yet".
    - anything else    -> `ERROR`: attempted and failed, which a retry layer may
      reasonably try again. Correct for a rate limit or a transport blip.

    Raising a distinct type is what lets the dispatch layer tell them apart
    without matching on error message text.
    """

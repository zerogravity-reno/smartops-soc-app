"""Decode PowerShell `-EncodedCommand` arguments in rows the Broker already fetched (B10).

On `e1461da6` the Analyst asked the Broker to "decode base64-encoded arguments in
PowerShell commands" (FU1). The rows held `-EncodedCommand JABlAG4AdgA6AHUAcwBl…`
24 times and nothing could decode them, so FU1 came back as "encoded commands"
again and synthesis called them a payload. They decode to `$env:username`.

The Broker never sees rows -- `broker._digest` hands it counts, not content -- so
the tool works by reference: the Broker names a step it already ran, code decodes
every encoded argument in that step's rows and writes the plain text onto the row
as `decoded_command`, where the sub-analysts read it. The Broker gets a count back.

Decoding is code, not a model: PowerShell's `-EncodedCommand` is always base64 of
UTF-16LE, so there is nothing to judge.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import TYPE_CHECKING, Any

from strands import ToolContext, tool

if TYPE_CHECKING:
    from smartops.broker import BrokerRequest

# `-e`, `-ec`, `-enc`, `-encodedcommand` and every prefix PowerShell accepts, with
# `-` or `/`. The argument check below, not this pattern, rejects `-ExecutionPolicy`.
_FLAG = re.compile(r"(?i)(?:^|[\s\"'])[-/](e[a-z]*)\s+[\"']?([A-Za-z0-9+/]{4,}={0,2})")

DECODED_FIELD = "decoded_command"
"""The row key the decoded text is written to; first in the row so a generic,
key-capped row rendering (`formatting._format_generic`) still shows it."""


def _is_encoded_flag(flag: str) -> bool:
    flag = flag.lower()
    return flag == "ec" or "encodedcommand".startswith(flag)


def decode_powershell(text: str) -> list[str]:
    """Plain text of every `-EncodedCommand` argument in `text`, in order, deduplicated.

    An argument that is not valid base64 of printable UTF-16LE is skipped rather
    than guessed at: `-e Bypass` is base64-shaped and decodes to noise.

    ponytail: one transform (base64 of UTF-16LE). Layered obfuscation (gzip inside
    base64, `-bxor`, `[char]` arrays) needs a real deobfuscator such as CyberChef.
    """
    out: list[str] = []
    for flag, blob in _FLAG.findall(text or ""):
        if not _is_encoded_flag(flag):
            continue
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            decoded = raw.decode("utf-16-le")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if len(raw) % 2 or not decoded.strip() or not all(c.isprintable() or c in "\r\n\t" for c in decoded):
            continue
        # A script is mostly ASCII; `-e Bypass` decodes to two printable CJK characters.
        if sum(c.isascii() for c in decoded) < 0.9 * len(decoded):
            continue
        if decoded not in out:
            out.append(decoded)
    return out


def annotate_rows(rows: list[dict[str, Any]]) -> int:
    """Write `decoded_command` onto every row with an encoded argument; return how many."""
    annotated = 0
    for i, row in enumerate(rows):
        found = [d for v in row.values() if isinstance(v, str) for d in decode_powershell(v)]
        if found:
            rows[i] = {DECODED_FIELD: " ; ".join(dict.fromkeys(found)), **row}
            annotated += 1
    return annotated


@tool(
    name="decode_encoded_commands",
    description=(
        "Decode PowerShell -EncodedCommand (-enc, -e) arguments in the rows a step you already "
        "dispatched retrieved. Use it when the goal asks what an encoded command does: dispatch "
        "the step that fetches the process command lines first, then call this with its step_id. "
        "The decoded text is recorded on the rows for the analysts; you get a count back."
    ),
    context=True,
)
def decode_encoded_commands(step_id: str, tool_context: ToolContext) -> str:
    """Decode the encoded PowerShell arguments in one dispatched step's rows.

    Args:
        step_id: The id of a planned step that has already been dispatched.
    """
    req: BrokerRequest = tool_context.invocation_state["smartops"]
    outcome = req.step_outcomes.get(step_id)
    if outcome is None or not outcome.result_ids:
        return (
            f"status=refused | step {step_id!r} has no dispatched results to decode. "
            "Dispatch the step that retrieves the command lines first, then name it here."
        )
    ids = set(outcome.result_ids)
    rows = decoded = 0
    for result in req.collected:
        if result.task_id not in ids or result.findings is None:
            continue
        for value in vars(result.findings).values():
            for result_set in value if isinstance(value, list) else ():
                if hasattr(result_set, "rows"):
                    rows += len(result_set.rows)
                    decoded += annotate_rows(result_set.rows)
    return f"status=ok | step={step_id} rows={rows} decoded={decoded}"

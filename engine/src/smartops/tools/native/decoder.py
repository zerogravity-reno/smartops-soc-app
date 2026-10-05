"""Encoded PowerShell: tagged by code on arrival, decoded by the Broker on request (B10).

On `e1461da6` the Analyst asked the Broker to "decode base64-encoded arguments in
PowerShell commands" (FU1). The rows held `-EncodedCommand JABlAG4AdgA6AHUAcwBl…`
24 times and nothing could decode them. They decode to `$env:username`.

The first fix decoded by step id, which needed the Broker to know which step held
the command. It cannot: `broker._digest` hands it counts, not rows. On `67da804d`
the encoded rows were in T1, T2 and T4 and it decoded T3, the one goal that
mentioned encoding.

So code finds them instead. Every encoded argument in a task's rows is recorded
in the run's `encoded.json` under a signature (`enc#3f2a1b`), and the sub-analyst
handoff lists the signatures it saw. A later task that asks to decode one names
it; the Broker calls `decode_encoded_commands` with the refs and code writes
"enc#… decodes to: …" into that loop's handoff. The Broker gets a count back.

Decoding is code, not a model: PowerShell's `-EncodedCommand` is always base64 of
UTF-16LE, so there is nothing to judge.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from strands import ToolContext, tool

from smartops.subagent_analysts.formatting import _CMDLINE_LIMIT, _field, _row_weight, _sanitise, _truncate

if TYPE_CHECKING:
    from contracts import SubtaskResult

    from smartops.broker import BrokerRequest

# `-e`, `-ec`, `-enc`, `-encodedcommand` and every prefix PowerShell accepts, with
# `-` or `/`. The argument check below, not this pattern, rejects `-ExecutionPolicy`.
_FLAG = re.compile(r"(?i)(?:^|[\s\"'])[-/](e[a-z]*)\s+[\"']?([A-Za-z0-9+/]{4,}={0,2})")

REGISTRY_NAME = "encoded.json"
"""The run-level file, `<runs_root>/<run_id>/encoded.json`: `{sig: {blob, parents}}`.
A file because each loop's Broker is its own subprocess."""


def _is_encoded_flag(flag: str) -> bool:
    flag = flag.lower()
    return flag == "ec" or "encodedcommand".startswith(flag)


def _decode(blob: str) -> str | None:
    """Plain text of one `-EncodedCommand` argument, or None when it is not one.

    Not valid base64 of printable UTF-16LE is skipped rather than guessed at:
    `-e Bypass` is base64-shaped and decodes to noise.

    ponytail: one transform (base64 of UTF-16LE). Layered obfuscation (gzip inside
    base64, `-bxor`, `[char]` arrays) needs a real deobfuscator such as CyberChef.
    """
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        decoded = raw.decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError):
        return None
    if len(raw) % 2 or not decoded.strip() or not all(c.isprintable() or c in "\r\n\t" for c in decoded):
        return None
    # A script is mostly ASCII; `-e Bypass` decodes to two printable CJK characters.
    if sum(c.isascii() for c in decoded) < 0.9 * len(decoded):
        return None
    return decoded


def encoded(text: str) -> dict[str, str]:
    """Every real `-EncodedCommand` argument in `text`: blob -> plain text, in order."""
    out: dict[str, str] = {}
    for flag, blob in _FLAG.findall(text or ""):
        if _is_encoded_flag(flag) and blob not in out and (plain := _decode(blob)) is not None:
            out[blob] = plain
    return out


def signature(blob: str) -> str:
    """Stable across loops and tasks, so the handoff line and the registry agree."""
    return "enc#" + hashlib.sha1(blob.encode()).hexdigest()[:6]


def encoded_in(rows: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Signatures in `rows`: `{sig: {blob, events, parents: {parent: events}}}`."""
    found: dict[str, dict[str, Any]] = {}
    for row in rows:
        blobs = {b for v in row.values() if isinstance(v, str) for b in encoded(v)}
        for blob in blobs:
            entry = found.setdefault(signature(blob), {"blob": blob, "events": 0, "parents": {}})
            weight = _row_weight(row)
            entry["events"] += weight
            parent = _field(row, "processes", "parent")
            if parent != "-":
                entry["parents"][parent] = entry["parents"].get(parent, 0) + weight
    return found


def _rows(results: Iterable[SubtaskResult]) -> Iterator[dict[str, Any]]:
    for result in results:
        if result.findings is None:
            continue
        for value in vars(result.findings).values():
            for result_set in value if isinstance(value, list) else ():
                if hasattr(result_set, "rows"):
                    yield from result_set.rows


def load(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None or not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def record(path: Path, results: Iterable[SubtaskResult]) -> int:
    """Merge every encoded argument in `results` into the registry; return how many are new.

    Parents only, no counts: tasks and loops refetch the same rows, so a summed
    count would be a count of fetches.
    """
    found = encoded_in(_rows(results))
    if not found:
        return 0
    registry = load(path)
    new = 0
    for sig, entry in found.items():
        if sig not in registry:
            registry[sig] = {"blob": entry["blob"], "parents": []}
            new += 1
        registry[sig]["parents"] = sorted({*registry[sig]["parents"], *entry["parents"]})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    return new


def _decoded_line(sig: str, entry: dict[str, Any]) -> str:
    plain = _truncate(_sanitise(_decode(entry["blob"]) or ""), _CMDLINE_LIMIT)
    parents = ", ".join(entry["parents"]) or "unknown"
    return f"~ {sig} (parent {parents}) decodes to: {plain}"


@tool(
    name="decode_encoded_commands",
    description=(
        "Decode encoded PowerShell commands an earlier loop recorded. Use it when the goal names "
        "enc# references (e.g. enc#3f2a1b) or asks what encoded commands say; no dispatch is "
        "needed. Pass the refs the goal names, or an empty list for every recorded command. "
        "The decoded text goes to the analysts; you get a count back."
    ),
    context=True,
)
def decode_encoded_commands(refs: list[str], tool_context: ToolContext) -> str:
    """Decode recorded encoded commands by reference.

    Args:
        refs: enc# references from the goal; empty means every recorded command.
    """
    req: BrokerRequest = tool_context.invocation_state["smartops"]
    registry = load(req.encoded_registry)
    wanted = [r.strip() for r in refs if r.strip()] or list(registry)
    known = [r for r in wanted if r in registry]
    unknown = [r for r in wanted if r not in registry]
    if not known:
        return (
            f"status=refused | no recorded encoded command matches {unknown or 'the request'}. "
            "Encoded commands are recorded when an earlier loop's rows contain them."
        )
    for ref in known:
        line = _decoded_line(ref, registry[ref])
        if line not in req.decoded:
            req.decoded.append(line)
    return f"status=ok | refs={len(known)} decoded={len(known)}" + (f" | unknown={','.join(unknown)}" if unknown else "")

"""Encoded PowerShell, decoded by code in the loop whose rows hold it (B10).

On `e1461da6` the Analyst asked to "decode base64-encoded arguments in PowerShell
commands" and nothing could. The rows held `-EncodedCommand JABlAG4AdgA6AHUAcwBl…`
24 times; it decodes to `$env:username`.

B10b tagged each command `enc#…` and decoded it only when a later task asked. On
`9322c93a` no task asked: the Analyst reached TRUE_POSITIVE 98 in one loop on
"obfuscated PowerShell" it never read, across 32 tagged commands. So the handoff
now carries the plain text next to each signature, in the same loop.

Decoding is code, not a model: PowerShell's `-EncodedCommand` is always base64 of
UTF-16LE, so there is nothing to judge.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import html
import re
from collections.abc import Iterable
from typing import Any

from smartops.subagent_analysts.formatting import _CMDLINE_LIMIT, _field, _first, _row_weight, _sanitise, _truncate
from smartops.tools.native.virustotal import is_private_ip

# `-e`, `-ec`, `-enc`, `-encodedcommand` and every prefix PowerShell accepts, with
# `-` or `/`. The argument check below, not this pattern, rejects `-ExecutionPolicy`.
_FLAG = re.compile(r"(?i)(?:^|[\s\"'])[-/](e[a-z]*)\s+[\"']?([A-Za-z0-9+/]{4,}={0,2})")

def _is_encoded_flag(flag: str) -> bool:
    flag = flag.lower()
    return flag == "ec" or "encodedcommand".startswith(flag)


def _decode(blob: str, lenient: bool = False) -> str | None:
    """Plain text of one `-EncodedCommand` argument, or None when it is not one.

    Not valid base64 of printable UTF-16LE is skipped rather than guessed at:
    `-e Bypass` is base64-shaped and decodes to noise.

    `lenient` is for an inner blob that Splunk cut off with its outer one: trim to
    whole base64 quanta and whole UTF-16 units, then the same checks.

    ponytail: one transform (base64 of UTF-16LE). Layered obfuscation (gzip inside
    base64, `-bxor`, `[char]` arrays) needs a real deobfuscator such as CyberChef.
    """
    if lenient:
        blob = blob[: len(blob) // 4 * 4]
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        if lenient:
            raw = raw[: len(raw) // 2 * 2]
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


def _unnest(plain: str) -> str:
    """Show an inner `-EncodedCommand` blob (often cut by Splunk) as its plain text."""
    def sub(m: re.Match[str]) -> str:
        flag, blob = m.groups()
        if not _is_encoded_flag(flag) or (inner := _decode(blob, lenient=True)) is None:
            return m.group(0)
        cut = "" if _decode(blob) is not None else "… (truncated)"
        return m.group(0)[: -len(blob)] + f"«{inner}{cut}»"

    return _FLAG.sub(sub, plain)


def signature(blob: str) -> str:
    """Stable across loops and tasks, so the handoff line and the registry agree."""
    return "enc#" + hashlib.sha1(blob.encode()).hexdigest()[:6]


# Script interpreters and LOLBins: the images whose arguments are the action.
# ponytail: a fixed list, not LOLBAS; widen it when a run shows a missed binary.
_INTERPRETERS = frozenset(
    "powershell pwsh cmd wscript cscript mshta rundll32 regsvr32 certutil bitsadmin curl wget wmic msiexec".split()
)


# A `| table _raw` row: Sysmon's XML, where the command line is one `<Data>` element.
_RAW_CMDLINE = re.compile(r"<Data Name='CommandLine'>(.*?)</Data>", re.S)


def commands_in(rows: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Plain interpreter/LOLBin command lines in `rows`: `{command: {events, parents}}`, rarest first.

    On 148b0e69 four tasks held `Invoke-WebRequest … -OutFile $env:TEMP\\svcupdate.dat`
    and no narrative named it. Lines with an encoded blob are left to `encoded_in`;
    a bare image path carries no arguments and says nothing. `events` sums row
    weights, so a set overlapping another counts the same event twice."""
    found: dict[str, dict[str, Any]] = {}
    for row in rows:
        cmd = _field(row, "processes", "cmdline").strip()
        if cmd == "-" and (m := _RAW_CMDLINE.search(str(row.get("_raw", "")))):
            cmd = _sanitise(html.unescape(m.group(1))).strip()
        image, _, args = cmd[1:].partition('"') if cmd.startswith('"') else cmd.partition(" ")
        if re.split(r"[\\/]", image)[-1].lower().removesuffix(".exe") not in _INTERPRETERS or not args.strip() or encoded(cmd):
            continue
        entry = found.setdefault(cmd, {"events": 0, "parents": {}})
        weight = _row_weight(row)
        entry["events"] += weight
        parent = _field(row, "processes", "parent")
        if parent != "-":
            entry["parents"][parent] = entry["parents"].get(parent, 0) + weight
    return dict(sorted(found.items(), key=lambda kv: kv[1]["events"]))


def encoded_in(rows: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Signatures in `rows`: `{sig: {blob, plain, events, parents: {parent: events}}}`.

    `plain` is sanitised and truncated: it goes into prompt text."""
    found: dict[str, dict[str, Any]] = {}
    for row in rows:
        blobs = {b: plain for v in row.values() if isinstance(v, str) for b, plain in encoded(v).items()}
        for blob, plain in blobs.items():
            entry = found.setdefault(
                signature(blob),
                {"blob": blob, "plain": _truncate(_sanitise(_unnest(plain)), _CMDLINE_LIMIT), "events": 0, "parents": {}},
            )
            weight = _row_weight(row)
            entry["events"] += weight
            parent = _field(row, "processes", "parent")
            if parent != "-":
                entry["parents"][parent] = entry["parents"].get(parent, 0) + weight
    return found


_SHA256 = re.compile(r"\b[0-9A-Fa-f]{64}\b")


def hashes_in(rows: Iterable[dict[str, Any]]) -> dict[tuple[str, str], int]:
    """`(file, SHA256) -> events` in `rows`, rarest first (B22).

    On c90ca5f9 six rows held OneDrive.exe's own SHA256 and none reached the
    Analyst, so VirusTotal was never asked about the parent that ran the download.
    Sysmon's `Hashes` belongs to the loaded image (EID 7) or written file when the
    row names one, else to the process `Image`."""
    found: dict[tuple[str, str], int] = {}
    for row in rows:
        sha = _SHA256.search(_first(row, "Hashes", "Hash", "process_hash", "file_hash", "sha256", default=""))
        if not sha:
            continue
        file = _first(row, "ImageLoaded", "TargetFilename", "Image", default="") or _field(row, "processes", "process")
        key = (file, sha.group(0).upper())
        found[key] = found.get(key, 0) + _row_weight(row)
    return dict(sorted(found.items(), key=lambda kv: kv[1]))


# ponytail: IPv4 only, and a dotted version string like `10.0.0.1` reads as an address.
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def private_addresses_in(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Private (not internet-routable) IPv4 addresses anywhere in `rows`: address -> events (B21).

    VirusTotal no longer looks these up (B18), so nothing said what they were, and
    c90ca5f9's round 2 called 192.168.40.211 "external". It sat in a download URL,
    not an address field, hence every value is searched."""
    found: dict[str, int] = {}
    for row in rows:
        addresses = {a for v in row.values() if isinstance(v, str) for a in _IPV4.findall(v) if is_private_ip(a)}
        for a in addresses:
            found[a] = found.get(a, 0) + _row_weight(row)
    return dict(sorted(found.items(), key=lambda kv: kv[1]))

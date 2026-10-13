"""Every time a stored run hands between parts is UTC with `Z` (or marked zone-unknown).

Walks the newest run under `.smartops/runs/` (or `SMARTOPS_CHECK_RUN`): its
`tasks.json` and `analyst-payload.json` files. Skipped when there is none.
"""

import os
import re

import pytest

from smartops.broker import runs_root

# ISO date-times and Splunk's `ctime` (`10/05/2026 14:38:58`), with whatever follows.
_TIME = re.compile(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d(?::\d\d)?(?:\.\d+)?([^\s\"',\]]{0,14})"
                   r"|\d\d/\d\d/\d{4} \d\d:\d\d(?::\d\d)?([^\s\"',\]]{0,14})")


def _newest_run():
    root = runs_root()
    name = os.environ.get("SMARTOPS_CHECK_RUN")
    runs = [root / name] if name else sorted(
        (p for p in root.glob("*") if p.is_dir() and any(p.rglob("tasks.json"))),
        key=lambda p: p.stat().st_mtime) if root.is_dir() else []
    return runs[-1] if runs else None


def non_utc_times(text: str) -> list[str]:
    return [m.group(0) for m in _TIME.finditer(text)
            if not (m.group(1) or m.group(2) or "").startswith(("Z", "(zone-unknown)"))]


def test_the_checker_tells_utc_from_local():
    assert non_utc_times('"2026-10-06T11:51:16Z" "2026-10-06T11:51:16.123Z" "2026-10-06T14:51:16(zone-unknown)"') == []
    assert non_utc_times('"2026-10-06T14:51:16+03:00" "2026-10-06 11:51:16" "10/05/2026 14:38:58"') == [
        "2026-10-06T14:51:16+03:00", "2026-10-06 11:51:16", "10/05/2026 14:38:58"]


def test_the_newest_run_hands_over_only_utc_times():
    run = _newest_run()
    if run is None:
        pytest.skip("no stored run")
    bad = {str(f.relative_to(run)): found for name in ("tasks.json", "analyst-payload.json")
           for f in run.rglob(name) if (found := non_utc_times(f.read_text(encoding="utf-8")))}
    assert not bad, f"{run.name}: times not in UTC Z: {bad}"

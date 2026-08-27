"""Check that every `file:line` anchor in a doc still names the symbol it points at.

    uv run python docs/check_anchors.py [page.md ...]

Defaults to the Confluence pages under `docs/`. Exits non-zero on a stale anchor.

Why this is stricter than "does that line exist": these anchors rot whenever a
cited file gains a line above one, and a stale anchor still points at a REAL line
-- just the wrong one. An earlier version of this check only verified the line was
in range. It reported "no unresolvable anchors" while every `analyze.py` anchor on
the page had slid onto a fragment of an unrelated docstring, twice in one session.
So the test here is that the anchored line DEFINES the symbol named beside it.

Anchor forms handled, both of which the pages use:

    `projection.py:307`   -- explicit file
    (`:183`)              -- relative to the nearest filename to its left

An anchor is only checked when a symbol is *adjacent* to it -- see
`adjacent_symbol`. Anchors the prose merely describes ("the answer-tool skip
(`:314`)") have nothing to check against and are counted as unchecked, so the
number of them stays visible rather than being quietly treated as passing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PAGES = sorted((REPO / "docs").glob("confluence-*.md"))
SKIP_DIRS = {".venv", ".claude", "graphify-out", "__pycache__", "build", "node_modules"}

FILE_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_/\.]*\.py)")
ANCHOR_RE = re.compile(r"`(?:[A-Za-z_][A-Za-z0-9_/\.]*\.py)?:(\d+)`")
SYMBOL_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_.]*)\(?\)?`")
DEF_RE = re.compile(r"^\s*(?:async\s+)?(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)")
ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]")
"""A module-level constant or a field declaration.

Matches a bare annotation as well as an assignment, because a pydantic field
often declares its type on one line and its `= Field(...)` on the next --
`findings: Annotated[` is the line an anchor should point at.
"""


def index_python_files() -> dict[str, list[Path]]:
    """basename -> every matching path, so an ambiguous cite can be reported as one."""
    index: dict[str, list[Path]] = {}
    for path in REPO.rglob("*.py"):
        if SKIP_DIRS & set(path.parts):
            continue
        index.setdefault(path.name, []).append(path)
    return index


def adjacent_symbol(raw: str, anchor_start: int) -> str | None:
    """The symbol this anchor is attached to, or None if the prose only describes it.

    "Attached" is deliberately strict: the last ``backticked`` symbol before the
    anchor counts only when nothing alphabetic separates the two. That accepts the
    two forms the pages use --

        `projection.project()` -- `projection.py:307`
        `load_evidence_from_run()` (`:115`)

    -- and rejects an anchor the prose merely points at, like "the answer-tool
    skip (`:314`)", where the nearest symbol belongs to an earlier clause. Without
    that rule an Appendix row naming a dozen symbols would let any anchor in the
    row match any of them, which is exactly how a stale anchor hides.
    """
    before = raw[:anchor_start]
    matches = list(SYMBOL_RE.finditer(before))
    if not matches:
        return None
    last = matches[-1]
    if any(char.isalpha() for char in before[last.end() :]):
        return None
    return last.group(1).split(".")[-1]


def resolve_file(raw: str, anchor: re.Match[str], index: dict[str, list[Path]]) -> Path | str:
    """The file an anchor refers to, or a string explaining why it cannot be found."""
    inner = FILE_RE.search(anchor.group(0))
    if inner:
        name = inner.group(1)
    else:
        before = [m.group(1) for m in FILE_RE.finditer(raw) if m.start() < anchor.start()]
        if not before:
            return "has no filename to its left"
        name = before[-1]

    candidates = index.get(Path(name).name, [])
    if "/" in name:
        candidates = [c for c in candidates if str(c).replace("\\", "/").endswith(name)]
    if not candidates:
        return f"no such file: {name}"
    if len(candidates) > 1:
        return f"ambiguous {name}: {[str(c.relative_to(REPO)) for c in candidates]}"
    return candidates[0]


def defined_name(line: str) -> str | None:
    """The symbol a source line defines or assigns, if it does either."""
    defined = DEF_RE.match(line)
    if defined:
        return defined.group(1)
    assigned = ASSIGN_RE.match(line)
    return assigned.group(1) if assigned else None


def check(page: Path, index: dict[str, list[Path]]) -> tuple[int, int, list[str]]:
    problems: list[str] = []
    checked = unchecked = 0

    for lineno, raw in enumerate(page.read_text(encoding="utf-8").splitlines(), 1):
        if ":" not in raw or not FILE_RE.search(raw):
            continue

        for anchor in ANCHOR_RE.finditer(raw):
            symbol = adjacent_symbol(raw, anchor.start())
            if symbol is None:
                unchecked += 1
                continue

            resolved = resolve_file(raw, anchor, index)
            if isinstance(resolved, str):
                problems.append(f"{page.name}:{lineno} `{symbol}` {resolved}")
                continue

            target = int(anchor.group(1))
            source = resolved.read_text(encoding="utf-8").splitlines()
            if not 1 <= target <= len(source):
                problems.append(
                    f"{page.name}:{lineno} `{symbol}` -> {resolved.name}:{target}, "
                    f"out of range ({len(source)} lines)"
                )
                continue

            line = source[target - 1]
            if defined_name(line) == symbol:
                checked += 1
                continue

            problems.append(
                f"{page.name}:{lineno} `{symbol}` -> {resolved.name}:{target}, "
                f"which is {line.strip()[:64]!r}"
            )

    return checked, unchecked, problems


def main() -> int:
    pages = [Path(a) for a in sys.argv[1:]] or DEFAULT_PAGES
    index = index_python_files()
    total_checked = total_unchecked = 0
    all_problems: list[str] = []

    for page in pages:
        if not page.is_file():
            all_problems.append(f"no such page: {page}")
            continue
        checked, unchecked, problems = check(page, index)
        total_checked += checked
        total_unchecked += unchecked
        all_problems.extend(problems)
        print(
            f"{page.name}: {checked} verified, {unchecked} unchecked, "
            f"{len(problems)} stale"
        )

    print(f"\n{total_checked} anchors verified against the symbol named beside them")
    if total_unchecked:
        print(f"{total_unchecked} anchors have no adjacent symbol to check against")
    if all_problems:
        print(f"\n{len(all_problems)} STALE:")
        for problem in all_problems:
            print("  " + problem)
        return 1
    print("no stale anchors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

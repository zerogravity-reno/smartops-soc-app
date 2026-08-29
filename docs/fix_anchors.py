"""Repoint the `file:line` anchors in the docs after code moves.

`check_anchors.py` reports anchors that no longer name what they point at. This
repairs them, and exists because the failure it fixes is not occasional: every
refactor that adds or removes a line above a cited symbol invalidates every
anchor below it. One session's work broke 23 anchors in one page, then 3 more an
hour later. Repairing that by hand is both tedious and the kind of edit where a
slip goes unnoticed, because the result still *looks* like a line number.

    uv run python docs/fix_anchors.py            # repair the default page set
    uv run python docs/fix_anchors.py --check    # report only, exit 1 if any stale

**Symbol-aware, not numeric.** Each symbol's real defining line is resolved by
parsing the source with `ast`, and only an anchor sitting next to that symbol's
own name is rewritten. A blind numeric substitution would hit unrelated figures
in the same tables -- these pages quote row counts, token budgets and percentages
in the same sentences as anchors.

**What it cannot fix, on purpose.** An anchor whose symbol this tool cannot
resolve is left exactly as it was and merely noted. Two cases look alike and are
not: a symbol that was DELETED needs the prose around it rewritten rather than a
new line number (`combine()`'s anchors were not stale, they were describing
removed code, and the honest repair was to mark that section closed); a symbol
this tool simply does not index -- an imported name, say -- is fine as it stands.

`check_anchors.py` is the authority on whether an anchor is actually wrong. This
tool repairs only what it can prove and never returns a verdict of its own.

Anchor forms understood, matching what the pages actually use:

    `pack_evidence` ... `packing.py:194`      qualified target
    `packing.pack_evidence()` — `packing.py:194`   module-qualified name
    `valid_citation_ids` (`:176`)             short form, file from context
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
SRC_ROOTS = (REPO / "backend" / "src", REPO / "contracts" / "src")

DEFAULT_PAGES = sorted(DOCS.glob("confluence-*.md")) + [DOCS / "architecture.md"]

# `symbol` [anything short] `basename.py:NNN`
_QUALIFIED = re.compile(r"(`[\w.]*?(\w+)(?:\(\))?`[^`\n]{0,40}?`(\w+\.py):)(\d+)(`)")
# `symbol` (`:NNN`)
_SHORT = re.compile(r"(`([\w.]*?(?:\w+))(?:\(\))?`\s*\(`:)(\d+)(`\))")


def _defining_lines(py: Path) -> dict[str, int]:
    """symbol -> the line that DEFINES it.

    Module-level assignments are included alongside def/class because the pages
    cite constants too (`RUNS_DIR_ENV_VAR`, `DEFAULT_RUNS_DIR`). `setdefault` so
    the FIRST definition wins -- a name rebound later in a module is still
    introduced at the line a reader should be sent to.
    """
    out: dict[str, int] = {}
    for node in ast.walk(ast.parse(py.read_text(encoding="utf-8"))):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.setdefault(node.name, node.lineno)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out.setdefault(target.id, node.lineno)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            # Pydantic model FIELDS land here, and the pages anchor them
            # (`SubtaskResult.findings`). Without this they read as deleted.
            out.setdefault(node.target.id, node.lineno)
    return out


def _source_index() -> dict[str, dict[str, int]]:
    """basename -> {symbol: line}, over every source file in the workspace."""
    index: dict[str, dict[str, int]] = {}
    for root in SRC_ROOTS:
        for py in root.rglob("*.py"):
            if "__pycache__" in py.parts:
                continue
            # First writer wins; two files sharing a basename would be ambiguous
            # anyway, and the pages always name the module they mean.
            index.setdefault(py.name, {}).update(_defining_lines(py))
    return index


def repair(page: Path, index: dict[str, dict[str, int]], *, check: bool) -> tuple[int, int]:
    """Returns (repaired, unresolvable)."""
    text = original = page.read_text(encoding="utf-8")
    repaired = unresolvable = 0

    def fix_qualified(m: re.Match) -> str:
        nonlocal repaired, unresolvable
        prefix, symbol, basename, old, suffix = (
            m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
        )
        real = index.get(basename, {}).get(symbol)
        if real is None:
            unresolvable += 1
            print(f"  left alone  {page.name}: `{symbol}` not indexed in {basename}")
            return m.group(0)
        if str(real) == old:
            return m.group(0)
        repaired += 1
        print(f"  {page.name}: {symbol} {basename}:{old} -> :{real}")
        return f"{prefix}{real}{suffix}"

    text = _QUALIFIED.sub(fix_qualified, text)

    # The short form carries no filename, so resolve it only when the symbol is
    # unambiguous across the whole index. Ambiguous ones are left for a human.
    def fix_short(m: re.Match) -> str:
        nonlocal repaired
        prefix, symbol, old, suffix = m.group(1), m.group(2), m.group(3), m.group(4)
        symbol = symbol.rsplit(".", 1)[-1]
        hits = {b: syms[symbol] for b, syms in index.items() if symbol in syms}
        if len(hits) != 1:
            return m.group(0)
        real = next(iter(hits.values()))
        if str(real) == old:
            return m.group(0)
        repaired += 1
        print(f"  {page.name}: {symbol} :{old} -> :{real}")
        return f"{prefix}{real}{suffix}"

    text = _SHORT.sub(fix_short, text)

    if text != original and not check:
        page.write_text(text, encoding="utf-8")
    return repaired, unresolvable


def main() -> int:
    check = "--check" in sys.argv
    pages = [Path(a) for a in sys.argv[1:] if not a.startswith("--")] or DEFAULT_PAGES
    index = _source_index()

    total = unresolvable = 0
    for page in pages:
        if not page.exists():
            print(f"  skipped (missing): {page}")
            continue
        r, u = repair(page, index, check=check)
        total += r
        unresolvable += u

    verb = "would repair" if check else "repaired"
    print(f"\n{verb} {total} anchor(s); {unresolvable} left alone")
    if unresolvable:
        print("Anchors left alone name something this tool cannot resolve -- an")
        print("imported name, or a symbol that was deleted. check_anchors.py decides")
        print("which: if it calls one stale, the prose needs rewriting, not a number.")
    print("\nVerify: uv run python docs/check_anchors.py docs/architecture.md docs/confluence-*.md")
    # Deliberately does NOT fail on `unresolvable`. check_anchors.py is the
    # authority on what is broken, and a tool that reports its own verdict
    # alongside it would eventually disagree with it. Non-zero only for --check
    # with repairs outstanding, so this is usable as a "docs are current" gate.
    return 1 if (check and total) else 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Skill Pack Integration for SmartOps SOC App.

Implements lazy-loading reference skill packs (e.g. `superman-splunk`),
system prompt routing table injection, and the `read_reference` `@tool`.

The whole pack is behind one off-by-default switch, `SMARTOPS_SKILLS_ENABLED`
-- see `skills_enabled()` for why.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from strands import tool

logger = logging.getLogger(__name__)

VENDED_DIR = Path(__file__).parent / "vended"

SKILLS_ENABLED_ENV_VAR = "SMARTOPS_SKILLS_ENABLED"

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def skills_enabled() -> bool:
    """Whether the skill pack is attached to a domain subagent at all.

    Off unless `SMARTOPS_SKILLS_ENABLED` is explicitly truthy. Two things ride
    on this single answer -- the routing table injected into the `siem` system
    prompt, and the `read_reference` tool appended to the `siem` toolset. They
    are one switch on purpose: a run with the table but not the tool (or the
    reverse) is a configuration nobody can name afterwards.

    Off is the default because the A/B experiment between the hierarchical
    Broker (Arm S) and the flat Broker (Arm F) compares tool count, token cost,
    and sequential turns -- and only Arm S ever got this pack. Leaving it on by
    default meant every comparison measured topology *plus* a skill pack *plus*
    an extra tool, with no way to attribute a difference to any one of them. So
    the confounded configuration is the one you have to ask for; a run that sets
    nothing is a clean run. The code stays, to be evaluated on its own once a
    topology has won.
    """
    return os.environ.get(SKILLS_ENABLED_ENV_VAR, "").strip().lower() in _TRUTHY


@dataclass
class SkillPack:
    """A collection of specialized technical reference guides and a routing table.

    Reference skill packs are lazy-loaded via `read_reference(name)` to keep
    initial LLM context windows minimal while providing deep domain knowledge on demand.
    """

    name: str
    description: str
    routing_table: str
    references: dict[str, str] = field(default_factory=dict)

    def load_reference(self, name: str) -> str:
        """Retrieve a specific reference by name (case-insensitive, with or without .md extension)."""
        key = name.strip().lower()
        if key.endswith(".md"):
            key = key[:-3]

        if key in self.references:
            return self.references[key]

        # Match by partial or stripped name
        for ref_key, content in self.references.items():
            if ref_key == key or ref_key.replace("_", "") == key.replace("_", ""):
                return content

        available = ", ".join(sorted(self.references.keys()))
        return (
            f"Reference '{name}' not found in skill pack '{self.name}'. "
            f"Available references: {available}"
        )


_SKILL_PACK_CACHE: dict[str, SkillPack] = {}


def load_skill_pack_from_dir(path: Path | str) -> SkillPack:
    """Load a SkillPack from a directory containing SKILL.md and reference markdown files."""
    dir_path = Path(path)
    skill_md = dir_path / "SKILL.md"
    if not skill_md.exists():
        raise FileNotFoundError(f"Skill pack directory missing SKILL.md: {dir_path}")

    skill_text = skill_md.read_text(encoding="utf-8")
    name = dir_path.name.replace("_", "-")

    # Read references
    references: dict[str, str] = {}
    for md_file in dir_path.glob("*.md"):
        if md_file.name == "SKILL.md":
            continue
        ref_key = md_file.stem.lower()
        references[ref_key] = md_file.read_text(encoding="utf-8")

    return SkillPack(
        name=name,
        description=f"Vended reference skill pack: {name}",
        routing_table=skill_text,
        references=references,
    )


def get_skill_pack(name: str = "superman-splunk") -> SkillPack:
    """Retrieve or load a cached skill pack by name."""
    cache_key = name.lower().replace("-", "_")
    if cache_key in _SKILL_PACK_CACHE:
        return _SKILL_PACK_CACHE[cache_key]

    pack_dir = VENDED_DIR / cache_key
    if not pack_dir.exists():
        # Try hyphens
        pack_dir = VENDED_DIR / name
    if not pack_dir.exists():
        raise FileNotFoundError(f"Skill pack '{name}' not found at {pack_dir}")

    pack = load_skill_pack_from_dir(pack_dir)
    _SKILL_PACK_CACHE[cache_key] = pack
    return pack


@tool(name="read_reference", description="Lazy-load a specialized technical reference guide from the domain skill pack into context by name.")
def read_reference(name: str) -> str:
    """Read a specialized domain reference guide on demand.

    Args:
        name: Identifier of the reference guide to load (e.g. 'spl_syntax', 'cim_data_models', 'botsv3_sourcetypes', 'investigation_playbooks', 'performance_optimization').
    """
    try:
        pack = get_skill_pack("superman-splunk")
        return pack.load_reference(name)
    except Exception as exc:
        logger.error("Failed to read reference '%s': %s", name, exc)
        return f"Error loading reference '{name}': {exc}"


def inject_skill_routing_table(system_prompt: str, skill_pack: SkillPack | None = None) -> str:
    """Inject the skill pack routing table into a system prompt if not already present."""
    if skill_pack is None:
        try:
            skill_pack = get_skill_pack("superman-splunk")
        except FileNotFoundError:
            return system_prompt

    routing_header = f"SKILL PACK ROUTING TABLE ({skill_pack.name}):"
    if routing_header in system_prompt or "read_reference" in system_prompt:
        return system_prompt

    table_block = (
        f"\n\n{routing_header}\n"
        f"You have access to the `read_reference(name: str)` tool to load specialized technical guides on demand.\n"
        f"Available references in `{skill_pack.name}`:\n"
    )
    for ref_name in sorted(skill_pack.references.keys()):
        table_block += f"- `{ref_name}`: Consult via `read_reference(name='{ref_name}')`\n"

    table_block += "Call `read_reference(name)` whenever you need detailed guidance on syntax, CIM schemas, sourcetypes, playbooks, or performance tuning.\n"

    return system_prompt + table_block

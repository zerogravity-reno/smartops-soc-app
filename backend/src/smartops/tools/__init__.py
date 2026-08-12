"""Tool resolution. Import from `smartops.tools.registry` directly.

Deliberately re-exports nothing: an eager `from .registry import tools_for` here
made `registry -> domains -> tools.native.virustotal` re-enter this module while
`registry` was still initialising, which is a circular import.
"""

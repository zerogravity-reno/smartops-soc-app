"""Shared fixtures for the backend suite."""

from __future__ import annotations

import pytest

from smartops.broker import RUNS_DIR_ENV_VAR


@pytest.fixture(autouse=True)
def _isolate_run_artifacts(tmp_path, monkeypatch):
    """Keep run artifacts out of the repository.

    `save_run_artifacts()` writes to a path that is relative by default, so any
    test driving a real `broker_task()` -- the scripted bench runs especially --
    dropped its artifacts into the working directory. That was invisible while
    the path was keyed on `task_id` and each run overwrote the last; once runs
    became timestamped they started accumulating instead, and the suite left 179
    artifact directories behind, including 112 for a fixture task called `t1`.

    Worse than the mess: those directories sit alongside real measured runs under
    the same tree, so a scripted fixture run and a live one that cost money are
    indistinguishable by location. Pointing the suite at `tmp_path` keeps the
    real tree meaning "runs that actually happened".
    """
    monkeypatch.setenv(RUNS_DIR_ENV_VAR, str(tmp_path / "runs"))


@pytest.fixture(autouse=True)
def _fresh_vt_cache():
    """VirusTotal answers are cached per process; no test may see another's."""
    from smartops.tools.native import virustotal

    virustotal._CACHE.clear()


@pytest.fixture(autouse=True)
def _fresh_run_ledger():
    """The Broker's run ledger is process-wide; no test may see another's fetches."""
    from smartops import broker

    broker._RUN_STATE.clear()
    broker._VT_SEEN.clear()


@pytest.fixture(autouse=True)
def _isolate_mcp_registry(tmp_path, monkeypatch):
    """Start every test with no MCP clients registered, and no real servers to load.

    `registry._clients_by_family` is process-global, and any test that drives
    `main._run()` loads the MCP config into it. Once splunk became a local stdio
    server that always builds, those tests spawned the real Splunk process, and a
    later test asserting "no tools resolved" saw it -- order-dependent, passing
    alone. Tests that exercise the shipped config read it by path, not this var.
    """
    from smartops.tools import registry

    empty = tmp_path / "mcp_servers.empty.json"
    empty.write_text('{"mcpServers": {}}', encoding="utf-8")
    monkeypatch.setenv(registry.CONFIG_PATH_ENV_VAR, str(empty))
    monkeypatch.setattr(registry, "_clients_by_family", {})


@pytest.fixture(autouse=True)
def _every_family_plannable(monkeypatch):
    """Let `plan_fetch` accept every family, with no MCP servers loaded.

    `plan_fetch` refuses a step for a family nothing serves, and the fixture above
    leaves every MCP family unserved -- so without this, every broker test that
    plans a `siem` step would be refused. Only the plan-time gate is opened:
    `server_count()` is untouched, so dispatch and domain-gap tests still see
    the families as unconfigured. Tests of the gate itself restore it.
    """
    from smartops import broker

    monkeypatch.setattr(broker, "_plannable", lambda family: True)

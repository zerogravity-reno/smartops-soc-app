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

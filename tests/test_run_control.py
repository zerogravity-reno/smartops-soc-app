import os
import threading
from queue import Queue

import pytest

# webapp.main runs load_dotenv at import; restore the environment so the real .env
# (e.g. the Bedrock token) never leaks into other tests in the same session.
_env = dict(os.environ)
from webapp import main  # noqa: E402
os.environ.clear()
os.environ.update(_env)


def _ctrl(run_id):
    go = threading.Event()
    go.set()
    main._run_ctrl[run_id] = {"stop": threading.Event(), "go": go, "cancel": None}
    return main._run_ctrl[run_id]


def test_checkpoint_passes_when_running():
    c, q = _ctrl("t-run"), Queue()
    main._checkpoint("t-run", q)
    assert q.empty()
    main._run_ctrl.pop("t-run")


def test_stop_releases_a_paused_run():
    c, q = _ctrl("t-pause"), Queue()
    c["go"].clear()
    threading.Timer(0.3, lambda: main.stop_run("t-pause")).start()
    with pytest.raises(main.RunStopped):
        main._checkpoint("t-pause", q)
    assert q.get_nowait()["type"] == "paused"
    assert q.empty()  # stopped, so no "resumed"
    main._run_ctrl.pop("t-pause")


def test_resume_continues_a_paused_run():
    c, q = _ctrl("t-resume"), Queue()
    main.pause_run("t-resume")
    threading.Timer(0.3, lambda: main.resume_run("t-resume")).start()
    main._checkpoint("t-resume", q)
    assert [q.get_nowait()["type"], q.get_nowait()["type"]] == ["paused", "resumed"]
    main._run_ctrl.pop("t-resume")


def test_control_on_unknown_run_is_404():
    assert main.stop_run("nope").status_code == 404


def test_stop_cancels_a_running_broker_round():
    c = _ctrl("t-cancel")
    cancelled = []
    c["cancel"] = lambda: cancelled.append(True)
    main.stop_run("t-cancel")
    assert cancelled == [True] and c["stop"].is_set()
    main._run_ctrl.pop("t-cancel")

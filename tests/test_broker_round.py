"""The Analyst's in-process Broker round (`analyst._broker_round`): Stop, teardown and the audit on failure."""

import asyncio
import threading
import time
from queue import Queue

import pytest

from smartops import analyst

TASK = {"task_id": "T1", "question": "q", "entity": {"type": "host", "value": "h1"},
        "time_window": {"start": "2026-10-01T00:00:00Z", "end": "2026-10-01T02:00:00Z"}}


@pytest.fixture
def round_(monkeypatch, tmp_path):
    monkeypatch.setenv("SMARTOPS_RUNS_DIR", str(tmp_path))

    def go(fake_run_round, ctrl):
        monkeypatch.setattr(analyst, "run_round", fake_run_round)
        q = Queue()
        out = analyst._broker_round([TASK], "r1", 2, q, ctrl)
        return out, [q.get_nowait() for _ in range(q.qsize())], tmp_path / "r1" / "L2" / "broker.log"

    return go


def _ctrl():
    return {"stop": threading.Event(), "cancel": None}


def test_stop_mid_round_cancels_it_and_a_late_worker_print_is_dropped(round_):
    ctrl, worker_done = _ctrl(), threading.Event()

    def late_worker():  # a sub-analyst call still running when Stop lands
        time.sleep(0.3)
        print("late line")
        worker_done.set()

    async def slow(tasks, args):
        print("fetching 1/1")
        threading.Thread(target=late_worker).start()  # outlives the round, with the print sink
        ctrl["stop"].set()
        ctrl["cancel"]()
        await asyncio.sleep(30)

    with pytest.raises(analyst.RunStopped):
        round_(slow, ctrl)
    assert ctrl["cancel"] is None
    worker_done.wait(2)  # wrote into a closed log: dropped, not a ValueError


def test_a_stop_before_the_cancel_is_armed_skips_the_round(round_):
    ctrl, ran = _ctrl(), []
    ctrl["stop"].set()

    async def never(tasks, args):
        ran.append(True)

    with pytest.raises(analyst.RunStopped):
        round_(never, ctrl)
    assert ran == []


def test_a_cancel_after_the_round_ended_is_a_no_op():
    loop = asyncio.new_event_loop()
    holder = {}

    async def arm():
        me, running = asyncio.current_task(), asyncio.get_running_loop()

        def cancel():
            try:
                running.call_soon_threadsafe(me.cancel)
            except RuntimeError:
                pass
        holder["cancel"] = cancel

    loop.run_until_complete(arm())
    loop.close()
    holder["cancel"]()  # Stop on another thread that read the lambda just before it was cleared


def test_a_broker_that_fails_to_start_says_why_in_its_log_and_keeps_the_audit(round_):
    async def unusable(tasks, args):
        print("model:    bedrock")
        raise ValueError("provider 'bedrock' is selected but not usable: no credentials")

    (payload, link), events, log = round_(unusable, _ctrl())

    assert payload == {} and link["error"].startswith("broker failed: provider 'bedrock' is selected")
    assert link["broker_runs"] == [{"task_id": "r1-L2-T1", "run_dir": None}]
    assert link["handshake"]["not_fetched"] == ["r1-L2-T1"]
    assert "error: broker failed: provider 'bedrock' is selected" in log.read_text(encoding="utf-8")
    assert events[-1]["type"] == "broker_log" and events[-1]["data"]["line"].startswith("error: ")

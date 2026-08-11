import argparse
import os
from datetime import datetime, timezone

import pytest

from smartops.main import _build_parser, _load_env_file, _parse_entity, _parse_instant, _resolve_window


class TestEnvFileLoading:
    """Every setting is read from os.environ, so a `.env` file only works
    because the CLI loads one. These pin that it does, and that it loses to a
    real environment variable."""

    def test_a_shell_variable_beats_the_file(self, tmp_path, monkeypatch):
        # The failure this prevents: a stale local .env silently overriding a
        # deployment's real credentials.
        (tmp_path / ".env").write_text("SMARTOPS_MODEL_ID=id-from-file\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("SMARTOPS_MODEL_ID", "id-from-shell")

        _load_env_file()

        assert os.environ["SMARTOPS_MODEL_ID"] == "id-from-shell"

    def test_the_file_supplies_what_the_environment_does_not(self, tmp_path, monkeypatch):
        (tmp_path / ".env").write_text("VT_API_KEY=key-from-file\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("VT_API_KEY", raising=False)

        assert _load_env_file() is not None
        assert os.environ["VT_API_KEY"] == "key-from-file"

    def test_no_env_file_is_not_an_error(self, tmp_path, monkeypatch):
        # Running with no .env at all is the documented default state.
        monkeypatch.chdir(tmp_path)

        assert _load_env_file() is None

    def test_found_by_searching_upward_from_the_working_directory(self, tmp_path, monkeypatch):
        # So it works run from the repo root or from backend/.
        (tmp_path / ".env").write_text("VT_API_KEY=from-parent\n", encoding="utf-8")
        nested = tmp_path / "backend" / "src"
        nested.mkdir(parents=True)
        monkeypatch.chdir(nested)
        monkeypatch.delenv("VT_API_KEY", raising=False)

        assert _load_env_file() is not None
        assert os.environ["VT_API_KEY"] == "from-parent"


class TestEntityParsing:
    def test_kind_value_pairs_parse(self):
        entity = _parse_entity("ip:10.2.4.9")

        assert (entity.kind, entity.value) == ("ip", "10.2.4.9")

    def test_only_the_first_colon_splits(self):
        # So IPv6 addresses and URLs survive intact.
        assert _parse_entity("url:https://example.com/a?b=c").value == "https://example.com/a?b=c"
        assert _parse_entity("ip:2001:db8::1").value == "2001:db8::1"

    def test_a_missing_colon_is_rejected_with_an_example(self):
        import argparse

        try:
            _parse_entity("nocolon")
        except argparse.ArgumentTypeError as exc:
            assert "kind:value" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected a readable error")

    def test_an_unknown_kind_lists_the_valid_ones(self):
        import argparse

        try:
            _parse_entity("registry_key:HKLM")
        except argparse.ArgumentTypeError as exc:
            assert "file_hash" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected a readable error")

    def test_an_empty_value_is_rejected(self):
        import argparse

        try:
            _parse_entity("ip:")
        except argparse.ArgumentTypeError as exc:
            assert "empty" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected a readable error")


class TestTimeWindow:
    """Absolute windows exist because the data under test is historical.

    `index=botsv3` holds one day in 2018. A relative window -- the only kind the
    CLI could express before `--since` -- returns zero events, which is
    indistinguishable from a domain having nothing to say. Every test here guards
    that distinction.
    """

    def _args(self, argv):
        return _build_parser().parse_args(
            ["--goal", "g", "--entity", "host:h", *argv]
        )

    def test_naive_values_are_read_as_utc(self):
        # Scope requires tz-aware datetimes; a naive string would otherwise fail
        # validation complaining about tzinfo rather than about the argument.
        assert _parse_instant("2018-08-20T00:00:00").tzinfo is timezone.utc

    def test_trailing_z_is_accepted(self):
        assert _parse_instant("2018-08-20T00:00:00Z") == datetime(
            2018, 8, 20, tzinfo=timezone.utc
        )

    def test_a_non_iso_value_is_rejected_with_an_example(self):
        with pytest.raises(argparse.ArgumentTypeError, match="2018-08-20"):
            _parse_instant("last tuesday")

    def test_since_runs_forward_by_hours_rather_than_to_now(self):
        # "from 2018-08-20 for 24 hours" is what is meant; running to now would
        # sweep eight years of empty index.
        start, end = _resolve_window(self._args(["--since", "2018-08-20T00:00:00Z", "--hours", "24"]))

        assert start == datetime(2018, 8, 20, tzinfo=timezone.utc)
        assert end == datetime(2018, 8, 21, tzinfo=timezone.utc)

    def test_since_and_until_are_used_verbatim(self):
        start, end = _resolve_window(
            self._args(["--since", "2018-08-20T06:00:00Z", "--until", "2018-08-20T18:00:00Z"])
        )

        assert (start.hour, end.hour) == (6, 18)

    def test_hours_alone_still_ends_at_now(self):
        # The default behaviour has to survive: this is what every existing
        # invocation relies on.
        start, end = _resolve_window(self._args(["--hours", "6"]))

        assert (end - start).total_seconds() == 6 * 3600
        assert (datetime.now(timezone.utc) - end).total_seconds() < 60

    def test_until_alone_walks_back_by_hours(self):
        start, end = _resolve_window(self._args(["--until", "2018-08-21T00:00:00Z", "--hours", "12"]))

        assert start == datetime(2018, 8, 20, 12, tzinfo=timezone.utc)
        assert end == datetime(2018, 8, 21, tzinfo=timezone.utc)


class TestOutputEncoding:
    """A finished investigation must not be lost at the print step.

    Windows consoles default to cp1252 and cannot encode much of what a model
    writes. `_print_outcome` raised UnicodeEncodeError *after* the run had been
    billed -- the findings existed, were paid for, and were replaced by a stack
    trace.
    """

    def test_streams_are_reconfigured_to_utf8_with_replacement(self, monkeypatch):
        from smartops.main import _force_utf8_output

        calls = []

        class FakeStream:
            def reconfigure(self, **kwargs):
                calls.append(kwargs)

        monkeypatch.setattr("sys.stdout", FakeStream())
        monkeypatch.setattr("sys.stderr", FakeStream())

        _force_utf8_output()

        assert len(calls) == 2
        # `replace` matters as much as utf-8: a terminal that still cannot show a
        # character must degrade it, not discard the report.
        assert all(c == {"encoding": "utf-8", "errors": "replace"} for c in calls)

    def test_a_stream_that_refuses_reconfiguration_is_survivable(self, monkeypatch):
        from smartops.main import _force_utf8_output

        class Detached:
            def reconfigure(self, **kwargs):
                raise ValueError("underlying buffer has been detached")

        monkeypatch.setattr("sys.stdout", Detached())
        monkeypatch.setattr("sys.stderr", Detached())

        _force_utf8_output()  # must not raise

    def test_a_stream_without_reconfigure_is_ignored(self, monkeypatch):
        from smartops.main import _force_utf8_output

        monkeypatch.setattr("sys.stdout", object())
        monkeypatch.setattr("sys.stderr", object())

        _force_utf8_output()  # must not raise

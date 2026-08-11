import os

from smartops.main import _load_env_file, _parse_entity


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

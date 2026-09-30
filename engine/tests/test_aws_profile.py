"""A stale `AWS_PROFILE` must not break a run that supplied explicit credentials.

This was documented three times across the handovers as "clear any shell
AWS_PROFILE before a live probe", which is a defect with good manners. The
failure is also badly disguised: an unusable profile surfaces as
`The config profile (...) could not be found` from deep inside botocore at
model-construction time, reading as "your Bedrock setup is wrong" rather than
"an unrelated shell variable is set".
"""

from __future__ import annotations

import os

from smartops.main import AWS_PROFILE_ENV_VAR, _neutralise_aws_profile

_KEYS = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")


def _with_explicit_keys(monkeypatch):
    for name in _KEYS:
        monkeypatch.setenv(name, "AKIAEXAMPLE")


def _without_explicit_keys(monkeypatch):
    for name in _KEYS:
        monkeypatch.delenv(name, raising=False)


class TestAnEmptyProfileIsAlwaysUnset:
    """`env AWS_PROFILE= smartops-broker ...` produces an empty value, and
    botocore takes it literally -- it looks for a profile *named* empty string.
    An empty profile name is never valid, so it can only mean unset. This is the
    exact failure that broke the first live verification run."""

    def test_it_is_removed_even_with_no_explicit_keys(self, monkeypatch):
        _without_explicit_keys(monkeypatch)
        monkeypatch.setenv(AWS_PROFILE_ENV_VAR, "")

        assert _neutralise_aws_profile() == ""
        assert AWS_PROFILE_ENV_VAR not in os.environ

    def test_whitespace_counts_as_empty(self, monkeypatch):
        _without_explicit_keys(monkeypatch)
        monkeypatch.setenv(AWS_PROFILE_ENV_VAR, "   ")

        _neutralise_aws_profile()

        assert AWS_PROFILE_ENV_VAR not in os.environ


class TestExplicitKeysWin:
    def test_a_named_profile_is_dropped_when_keys_are_set(self, monkeypatch):
        """`AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` are a direct statement of
        which credentials to use. A profile named alongside them is the ambient
        leftover -- and it does not merely lose the race, it can break the run
        outright, because botocore resolves the profile for CONFIG before it
        reaches the credential chain the keys would win."""
        _with_explicit_keys(monkeypatch)
        monkeypatch.setenv(AWS_PROFILE_ENV_VAR, "some-sso-profile")

        assert _neutralise_aws_profile() == "some-sso-profile"
        assert AWS_PROFILE_ENV_VAR not in os.environ

    def test_it_says_so_rather_than_doing_it_silently(self, monkeypatch, caplog):
        """Overriding an operator's environment variable without saying so is its
        own confusing failure."""
        _with_explicit_keys(monkeypatch)
        monkeypatch.setenv(AWS_PROFILE_ENV_VAR, "some-sso-profile")

        with caplog.at_level("WARNING"):
            _neutralise_aws_profile()

        assert "some-sso-profile" in caplog.text
        assert "ignored" in caplog.text


class TestItLeavesAProfileThatIsTheOnlyCredential:
    def test_a_named_profile_survives_when_no_keys_are_set(self, monkeypatch):
        """Then the profile IS the intent -- there is nothing else to
        authenticate with, and dropping it would break the very setup it
        describes. The fix is scoped to the ambiguous case, not to AWS_PROFILE
        as a concept."""
        _without_explicit_keys(monkeypatch)
        monkeypatch.setenv(AWS_PROFILE_ENV_VAR, "the-only-credential")

        assert _neutralise_aws_profile() is None
        assert os.environ[AWS_PROFILE_ENV_VAR] == "the-only-credential"

    def test_a_half_set_key_pair_does_not_count_as_explicit(self, monkeypatch):
        """An access key with no secret authenticates nothing, so it must not be
        read as intent and used to discard a working profile."""
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
        monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
        monkeypatch.setenv(AWS_PROFILE_ENV_VAR, "the-only-credential")

        assert _neutralise_aws_profile() is None
        assert os.environ[AWS_PROFILE_ENV_VAR] == "the-only-credential"

    def test_an_empty_key_does_not_count_as_set(self, monkeypatch):
        """`AWS_SECRET_ACCESS_KEY=` in a .env is present-but-useless. Treating it
        as explicit credentials would discard the profile and leave the run with
        nothing at all."""
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "  ")
        monkeypatch.setenv(AWS_PROFILE_ENV_VAR, "the-only-credential")

        assert _neutralise_aws_profile() is None
        assert os.environ[AWS_PROFILE_ENV_VAR] == "the-only-credential"


class TestNoProfileAtAll:
    def test_it_is_a_no_op(self, monkeypatch):
        _with_explicit_keys(monkeypatch)
        monkeypatch.delenv(AWS_PROFILE_ENV_VAR, raising=False)

        assert _neutralise_aws_profile() is None
        assert AWS_PROFILE_ENV_VAR not in os.environ

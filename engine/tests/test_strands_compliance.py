"""Guards on how this codebase depends on Strands.

These tests do not exercise SmartOps behaviour. They exist because two classes of
breakage in the Strands dependency are silent by default:

- a deprecated API keeps working while warning, and the warning scrolls past
- a private helper we import changes or disappears with no deprecation at all

Both are cheap to catch here and expensive to find in a live run.
"""

import warnings

import pytest


class TestDeprecationGuardIsArmed:
    """Proves the `filterwarnings` config in the root pyproject.toml actually fires.

    A warning filter that matches nothing reads as protection while providing
    none, so the config is asserted rather than assumed. The Broker passed
    `smartops=request` through Strands' deprecating `**kwargs` channel on every
    invocation and nothing surfaced it -- this is what makes the next one loud.
    """

    def test_a_deprecation_warning_is_an_error(self):
        with pytest.raises(DeprecationWarning):
            warnings.warn("probe", DeprecationWarning, stacklevel=1)

    def test_a_user_warning_is_an_error(self):
        # Not redundant with the above. `models/bedrock.py` warns with UserWarning.
        with pytest.raises(UserWarning):
            warnings.warn("probe", UserWarning, stacklevel=1)

    def test_a_warning_with_no_category_is_an_error(self):
        """The case that actually bit us.

        Strands' two `**kwargs` deprecations pass no category, which defaults to
        UserWarning -- so a DeprecationWarning-only filter would have missed the
        exact warning this guard exists for.
        """
        with pytest.raises(UserWarning):
            warnings.warn("probe", stacklevel=1)


class TestPrivateSdkApiWeDependOn:
    """`tools/registry.py` imports `_interpolate_env_vars`, a private Strands helper.

    Keeping it is the right call -- reimplementing `${VAR}` interpolation would be
    a second dialect of the same feature and would drift from it. But a private
    symbol carries no stability guarantee, and this one is reached only on the
    TLS-no-verify branch, so an upstream change would surface late and in an
    unusual code path. These assertions turn that into a suite failure instead.
    """

    def test_the_helper_is_still_importable(self):
        from strands.tools.mcp.mcp_client import _interpolate_env_vars

        assert callable(_interpolate_env_vars)

    def test_it_still_interpolates_the_syntax_our_config_uses(self, monkeypatch):
        from strands.tools.mcp.mcp_client import _interpolate_env_vars

        monkeypatch.setenv("SMARTOPS_GUARD_PROBE", "interpolated")

        assert _interpolate_env_vars({"url": "https://${SMARTOPS_GUARD_PROBE}/mcp"}) == {
            "url": "https://interpolated/mcp"
        }

    def test_it_still_raises_on_an_unset_variable(self, monkeypatch):
        """`registry.py` relies on this raising, because `continue_on_error` is what
        turns the failure into a skip. If it started returning the literal instead,
        an unset credential would reach a live MCP server as the string `${VAR}`."""
        from strands.tools.mcp.mcp_client import _interpolate_env_vars

        monkeypatch.delenv("SMARTOPS_GUARD_UNSET", raising=False)

        with pytest.raises(ValueError):
            _interpolate_env_vars({"url": "https://${SMARTOPS_GUARD_UNSET}/mcp"})

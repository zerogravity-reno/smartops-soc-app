"""Suite-wide isolation from the developer's live model configuration."""

import pytest

from smartops.budget import PROVIDER_ENV_VAR


@pytest.fixture(autouse=True)
def _no_live_model(monkeypatch):
    """No test reaches a real model, whatever `.env` holds.

    `main._run()` loads `.env` into `os.environ` for the rest of the process
    (`load_dotenv`, not monkeypatch), so one test leaked the developer's keys into
    every later one. Since B52 E that built a real claim verifier and made paid
    calls from unit tests: slow, and flaky on the verdict. `none` is the existing
    K2 switch, and `override=False` keeps the file from replacing it.
    """
    monkeypatch.setenv(PROVIDER_ENV_VAR, "none")

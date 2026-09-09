"""Shared fixtures. Exposes the repo root and a locator for the built
`kmto` binary so tests can run it when CI has built it and skip cleanly
otherwise (the build is toolchain-specific and not done by pytest)."""
import os

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)


@pytest.fixture(scope="session")
def repo_root():
    return _REPO_ROOT


@pytest.fixture(scope="session")
def kmto_binary():
    for name in ("kmto", "kmto.exe"):
        path = os.path.join(_REPO_ROOT, "bin", name)
        if os.path.isfile(path):
            return path
    pytest.skip("bin/kmto not built — run `make` first (built in CI)")

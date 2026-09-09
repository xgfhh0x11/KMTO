"""Structure check — asserts the source tree matches what the README
documents, and that the Makefile's user-mode source list stays in sync
with the files on disk. Pure-Python; no toolchain required."""
import os
import re

import pytest

HEADERS = [
    "config_manager.h",
    "kmto_kernel_state.h",
    "kmto_protocol.h",
    "mitigation_detector.h",
    "mitigation_types.h",
    "reporting.h",
    "telemetry.h",
    "test_harness.h",
]

# User-mode core sources built into bin/kmto (Makefile KMTO_SOURCES).
CORE_SOURCES = [
    "main.c",
    "mitigation_detector.c",
    "telemetry.c",
    "test_harness.c",
    "config_manager.c",
    "reporting.c",
]

# Windows-only handshake console (built only when OS=Windows_NT).
WINDOWS_SOURCES = ["kmto_cli.c"]

DRIVER_SOURCES = ["kmto_driver.c", "cr4_observer.c", "event_ring.c"]


@pytest.mark.parametrize("name", HEADERS)
def test_header_present(repo_root, name):
    assert os.path.isfile(os.path.join(repo_root, "include", name)), f"missing include/{name}"


@pytest.mark.parametrize("name", CORE_SOURCES + WINDOWS_SOURCES)
def test_source_present(repo_root, name):
    assert os.path.isfile(os.path.join(repo_root, "src", name)), f"missing src/{name}"


@pytest.mark.parametrize("name", DRIVER_SOURCES)
def test_driver_source_present(repo_root, name):
    assert os.path.isfile(os.path.join(repo_root, "driver", name)), f"missing driver/{name}"


def test_makefile_core_sources_match_disk(repo_root):
    """Every core source the Makefile compiles into bin/kmto must exist,
    and every .c in src/ except the Windows-only CLI must be in that list
    — so a new source can't silently drop out of the build."""
    with open(os.path.join(repo_root, "Makefile"), "r", encoding="utf-8") as fh:
        makefile = fh.read()
    for src in CORE_SOURCES:
        assert f"$(SRC_DIR)/{src}" in makefile, f"Makefile KMTO_SOURCES missing {src}"

    on_disk = {
        f for f in os.listdir(os.path.join(repo_root, "src")) if f.endswith(".c")
    }
    accounted = set(CORE_SOURCES) | set(WINDOWS_SOURCES)
    assert on_disk == accounted, (
        f"src/ .c files not accounted for by the Makefile lists: "
        f"{on_disk ^ accounted}"
    )

"""Behavioural check — runs the built telemetry tool and asserts it
produces well-formed output. Skips cleanly when bin/kmto has not been
built (so it is meaningful locally and runs for real in CI after the
build step). This upgrades the old `make test` smoke run (which only
confirmed "did not crash") into an output-correctness assertion, as
called for in BUILD_AND_VERIFY §2.4 / §3.3."""
import json
import os
import subprocess

import pytest


def _run(binary, *args):
    return subprocess.run(
        [binary, *args], capture_output=True, text=True, timeout=120
    )


def test_help_exits_clean(kmto_binary):
    res = _run(kmto_binary, "-h")
    assert res.returncode == 0, f"-h exited {res.returncode}"
    assert "Usage" in res.stdout, f"-h missing usage text:\n{res.stdout}"


def test_run_all_produces_output(kmto_binary, tmp_path):
    out_dir = str(tmp_path / "out")
    res = _run(kmto_binary, "-t", "all", "-o", out_dir)
    assert res.returncode == 0, f"`-t all` exited {res.returncode}:\n{res.stderr}"
    assert os.path.isdir(out_dir), "output directory was not created"
    produced = os.listdir(out_dir)
    assert produced, "`-t all` produced no output files"


def test_json_outputs_are_valid(kmto_binary, tmp_path):
    out_dir = str(tmp_path / "out")
    _run(kmto_binary, "-t", "all", "-o", out_dir)
    json_files = [f for f in os.listdir(out_dir) if f.endswith(".json")] if os.path.isdir(out_dir) else []
    if not json_files:
        pytest.skip("no .json output files produced by this build")
    for name in json_files:
        with open(os.path.join(out_dir, name), "r", encoding="utf-8") as fh:
            json.load(fh)  # raises on malformed JSON -> test failure

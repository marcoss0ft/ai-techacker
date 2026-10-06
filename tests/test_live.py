"""Coletor ao vivo: só roda em GNU/Linux (VM Kali, WSL...)."""

import os
import sys

import pytest

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requer /proc (Linux)")


def test_live_collect_uses_same_model_and_rules():
    from endpoint_investigator import engine
    from endpoint_investigator.collectors import live

    snap = live.collect(log_hours=1)
    me = next(p for p in snap.processes if p.pid == os.getpid())
    assert me.uid == os.getuid() and "pytest" in me.cmd
    assert snap.coverage["/proc"].startswith("ok")
    inv = engine.investigate(snap)          # mesmas regras usadas nos datasets
    assert inv.conclusion and inv.limitations

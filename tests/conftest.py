import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
GEN = ROOT / "tools" / "generate_dataset.py"
GEN_ORIG = ROOT / "tools" / "generate_dataset_original.py"

from endpoint_investigator import engine  # noqa: E402
from endpoint_investigator.collectors import dataset  # noqa: E402


def generate(out: Path, *args: str, script: Path = GEN) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(script), "--output", str(out), *args],
                          capture_output=True, text=True, encoding="utf-8")


def investigate(path):
    return engine.investigate(dataset.collect(path))


@pytest.fixture
def make(tmp_path):
    """Gera o cenário pedido com o gerador e devolve a investigação."""
    def _make(scenario: str, seed: int = 7):
        out = tmp_path / f"{scenario}-{seed}"
        r = generate(out, "--scenario", scenario, "--seed", str(seed))
        assert r.returncode == 0, r.stderr
        return investigate(out)
    return _make


def by_rule(inv, rule, severity=None):
    return [f for f in inv.findings if f.rule == rule and (severity is None or f.severity == severity)]


def relevant(inv):
    """Findings de severidade alta ou média."""
    return [f for f in inv.findings if f.severity in ("alto", "medio")]

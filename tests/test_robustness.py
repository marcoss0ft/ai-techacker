"""Robustez: script original, muitas seeds, arquivos ausentes, linhas inválidas, CLI."""

import json

import pytest

from conftest import GEN_ORIG, by_rule, generate, investigate
from endpoint_investigator import cli
from endpoint_investigator.collectors import dataset


def test_original_generator_bug_and_fix(tmp_path):
    crashed = False
    for seed in range(1, 15):
        r = generate(tmp_path / f"o{seed}", "--level", "challenge", "--seed", str(seed), script=GEN_ORIG)
        if r.returncode != 0:
            assert "too many values to unpack" in r.stderr
            crashed = True
    assert crashed
    assert generate(tmp_path / "fixed", "--scenario", "random", "--seed", "1").returncode == 0


def test_datasets_from_original_generator_are_supported(tmp_path):
    ok = 0
    for level in ("basic", "intermediate", "challenge"):
        for seed in range(1, 12):
            out = tmp_path / f"{level}-{seed}"
            if generate(out, "--level", level, "--seed", str(seed), script=GEN_ORIG).returncode == 0:
                assert investigate(out).conclusion
                ok += 1
    assert ok >= 15


@pytest.mark.parametrize("level", ["basic", "intermediate", "challenge"])
def test_many_random_seeds_never_crash(tmp_path, level):
    assert generate(tmp_path / level, "--level", level, "--batch", "15", "--seed", "100").returncode == 0
    for d in sorted((tmp_path / level).iterdir()):
        investigate(d)


def test_missing_journal_degrades_gracefully(tmp_path):
    out = tmp_path / "c"
    generate(out, "--scenario", "correlation", "--seed", "1")
    (out / "journal.log").unlink()
    (out / "metadata.json").unlink()
    inv = investigate(out)
    assert inv.snapshot.coverage["journal.log"] == "ausente"
    assert any("journal.log" in c for c in inv.conclusion)
    assert by_rule(inv, "CORR-01", "alto")


def test_missing_permissions_makes_result_inconclusive(tmp_path):
    out = tmp_path / "c"
    generate(out, "--scenario", "correlation", "--seed", "1")
    (out / "permissions.csv").unlink()
    inv = investigate(out)
    assert not by_rule(inv, "CORR-01")
    assert any("nem descartar" in c.reason for c in inv.clean_checks)


def test_invalid_rows_are_skipped(tmp_path):
    out = tmp_path / "c"
    generate(out, "--scenario", "correlation", "--seed", "1")
    with (out / "processes.csv").open("a", encoding="utf-8") as fh:
        fh.write("lixo,abc,def,root,S,/bin/true\n")
    with (out / "permissions.csv").open("a", encoding="utf-8") as fh:
        fh.write("/x,file,root,root,99999,\n")
    with (out / "journal.log").open("a", encoding="utf-8") as fh:
        fh.write("linha sem formato\n")
    cov = investigate(out).snapshot.coverage
    assert "inválidas" in cov["processes.csv"] and "inválidas" in cov["permissions.csv"]
    assert "não reconhecidas" in cov["journal.log"]


def test_empty_or_missing_directory_is_an_error(tmp_path):
    with pytest.raises(ValueError):
        dataset.collect(tmp_path)
    assert cli.main(["dataset", str(tmp_path / "nao-existe")]) == 1


def test_cli_writes_json(tmp_path, capsys):
    out = tmp_path / "c"
    generate(out, "--scenario", "correlation", "--seed", "1")
    report = tmp_path / "rel" / "r.json"
    assert cli.main(["dataset", str(out), "-o", str(report), "--no-color"]) == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["findings"][0]["rule"] == "CORR-01" and data["clean_checks"] and data["timeline"]
    assert "CONCLUSÃO" in capsys.readouterr().out


# ------------------------------------------------------------------ variações montadas à mão
def _edit(path, old, new):
    path.write_text(path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")


def test_group_writable_is_medium_because_members_are_unknown(tmp_path):
    out = tmp_path / "c"
    generate(out, "--scenario", "correlation", "--seed", "1")
    _edit(out / "permissions.csv", "/opt/backup/backup.sh,file,root,root,0777", "/opt/backup/backup.sh,file,root,backup,0775")
    f = by_rule(investigate(out), "CORR-01")
    assert len(f) == 1 and f[0].severity == "medio"
    assert any("getent group backup" in m for m in f[0].missing_evidence)


def test_privilege_transition_without_sudo(tmp_path):
    """Processo root filho do bash de um usuário comum, rodando de /tmp oculto: CORR-02 alto."""
    out = tmp_path / "n"
    generate(out, "--scenario", "normal", "--seed", "1")
    with (out / "processes.csv").open("a", encoding="utf-8") as fh:
        fh.write("2026-09-14T09:00:20-03:00,5510,1212,root,S,/tmp/.cache/bash -p\n")
    f = by_rule(investigate(out), "CORR-02", "alto")
    assert f and "'aluno' -> root" in f[0].title

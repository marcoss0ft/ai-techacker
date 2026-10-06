"""Cada cenário do gerador é um caso de teste com expectativas POSITIVAS e NEGATIVAS.

As negativas importam tanto quanto as positivas: o enunciado pede que a
ferramenta não conclua demais a partir de um indicador isolado.
"""

import pytest

from conftest import by_rule, relevant


# ------------------------------------------------------------------ negativos
def test_normal_has_no_relevant_findings(make):
    inv = make("normal")
    assert relevant(inv) == []
    explained = " ".join(c.subject + c.reason for c in inv.clean_checks)
    assert "sessão aluno@pts/0" in explained and "/home/aluno/check.py" in explained


def test_privileged_service_is_not_vulnerable_by_itself(make):
    inv = make("privileged_service")
    assert relevant(inv) == [] and by_rule(inv, "CORR-01") == []
    clean = [c for c in inv.clean_checks if c.rule == "CORR-01" and c.subject == "backup-agent.service"]
    assert clean and "0700" in clean[0].reason and "não é vulnerabilidade" in clean[0].reason


def test_ambiguous_external_connection_is_not_c2(make):
    inv = make("ambiguous")
    assert relevant(inv) == []
    net = [f for f in by_rule(inv, "CORR-02") if "curl" in f.title]
    assert net and net[0].severity == "informativo"
    assert "NÃO caracteriza C2" in net[0].not_proven
    assert any("reputação" in m for m in net[0].missing_evidence)


def test_permission_is_hygiene_not_escalation(make):
    inv = make("permission")
    perm = by_rule(inv, "PERM-01")
    assert [f.entities["paths"] for f in perm] == [["/opt/reports/report.sh"]]
    assert perm[0].severity == "baixo"
    assert relevant(inv) == []


# ------------------------------------------------------------------ positivos
def test_correlation_scenario_generates_high_risk(make):
    inv = make("correlation")
    f = by_rule(inv, "CORR-01", "alto")
    assert len(f) == 1 and f[0].entities["paths"] == ["/opt/backup/backup.sh"] and f[0].confidence == "alta"
    refs = " ".join(e.ref for e in f[0].evidence)
    for src in ("services.txt", "processes.csv", "permissions.csv", "journal.log"):   # 4 fontes cruzadas
        assert src in refs
    assert "Não prova exploração" in f[0].not_proven


def test_random_scenario_follows_the_drawn_mode(make):
    """O random sorteia o modo do script: a expectativa segue o modo observado, não o nome."""
    for seed in range(1, 25):
        inv = make("random", seed)
        script = next(p for p in inv.snapshot.files if p.endswith("/run.sh"))
        high = [f for f in by_rule(inv, "CORR-01", "alto") if f.entities["paths"] == [script]]
        assert bool(high) == bool(inv.snapshot.files[script].mode & 0o002), seed


def test_writable_dir(make):
    f = by_rule(make("writable_dir"), "CORR-01", "alto")
    assert [x.entities["paths"] for x in f] == [["/srv/sync"]]
    assert any("substituir" in i for i in f[0].interpretation)


def test_webshell_chain(make):
    inv = make("webshell")
    assert by_rule(inv, "CORR-05", "alto")                  # shell com socket externo
    chain = by_rule(inv, "CORR-02", "alto")
    assert len(chain) == 1 and "www-data" in chain[0].title  # cadeia reportada uma vez só


def test_bruteforce_timeline(make):
    f = by_rule(make("bruteforce"), "CORR-04", "alto")
    assert f and "203.0.113.25" in f[0].title
    assert any("sudo" in e.statement for e in f[0].evidence)


# ------------------------------------------------------------------ formato do finding
ALL = ["normal", "permission", "privileged_service", "correlation", "ambiguous", "random",
       "writable_dir", "webshell", "bruteforce"]


@pytest.mark.parametrize("scenario", ALL)
def test_every_finding_separates_evidence_interpretation_hypothesis(make, scenario):
    inv = make(scenario)
    for f in inv.findings:
        assert f.evidence and all(e.ref for e in f.evidence), f.title        # evidência com fonte
        assert f.interpretation and f.missing_evidence and f.not_proven, f.title
        assert len(f.hypotheses) >= 2, f.title                                # sempre há alternativa
    assert inv.conclusion and inv.limitations

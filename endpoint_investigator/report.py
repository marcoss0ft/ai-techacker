"""Saídas: relatório no terminal e JSON estruturado (``-o arquivo.json``)."""

from __future__ import annotations

import json
import os
import sys

from .model import Investigation, fmt

COLORS = {"alto": "\033[1;31m", "medio": "\033[1;33m", "baixo": "\033[36m", "informativo": "\033[2m"}


def to_json(inv: Investigation) -> dict:
    s = inv.snapshot
    return {
        "origin": s.origin,
        "collected_at": s.collected_at.isoformat() if s.collected_at else None,
        "metadata": s.metadata,
        "inventory": {"processes": len(s.processes), "services": len(s.services), "files": len(s.files),
                      "log_events": len(s.logs), "connections": len(s.connections)},
        "coverage": s.coverage,
        "conclusion": inv.conclusion,
        "findings": [f.to_dict() for f in inv.findings],
        "clean_checks": [c.__dict__ for c in inv.clean_checks],
        "timeline": [{"timestamp": e.timestamp.isoformat() if e.timestamp else None, "source": e.source,
                      "event": e.text, "links": e.links} for e in inv.timeline],
        "limitations": inv.limitations,
    }


def write_json(inv: Investigation, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_json(inv), fh, indent=2, ensure_ascii=False, default=str)


def print_text(inv: Investigation, verbose: bool = False, color: bool | None = None, out=None) -> None:
    out = out or sys.stdout
    if color is None:
        color = out.isatty() and "NO_COLOR" not in os.environ
    paint = (lambda code, t: f"{code}{t}\033[0m") if color else (lambda code, t: t)
    w, s = out.write, inv.snapshot

    w("=" * 78 + f"\n ENDPOINT INVESTIGATOR: {s.origin}\n")
    w(f" snapshot {fmt(s.collected_at)} | {len(s.processes)} processos, {len(s.services)} serviços, "
      f"{len(s.files)} objetos, {len(s.logs)} logs, {len(s.connections)} sockets\n" + "=" * 78 + "\n\nCONCLUSÃO\n")
    for line in inv.conclusion:
        w(f"  • {line}\n")
    w("\n")
    for f in inv.findings:
        if f.severity == "informativo" and not verbose:
            continue
        w(paint(COLORS[f.severity], f"[{f.severity.upper():<11}]") + f" {f.id} {f.title}\n")
        w(f"   confiança: {f.confidence} | regra: {f.rule}\n   EVIDÊNCIA (observado):\n")
        for e in f.evidence:
            w(f"     - {e.statement}  [{e.ref}]\n")
        for label, items in (("INTERPRETAÇÃO", f.interpretation), ("HIPÓTESES", f.hypotheses),
                             ("EVIDÊNCIA AUSENTE", f.missing_evidence)):
            w(f"   {label}:\n" + "".join(f"     - {x}\n" for x in items))
        w(f"   NÃO PROVA: {f.not_proven}\n\n")
    hidden = sum(f.severity == "informativo" for f in inv.findings)
    if hidden and not verbose:
        w(f"  ({hidden} finding(s) informativo(s) oculto(s); use -v)\n\n")

    w("VERIFICAÇÕES SEM ACHADO\n")
    for c in inv.clean_checks[: None if verbose else 12]:
        w(f"  ✓ [{c.rule}] {c.subject}: {c.reason}\n")
    if len(inv.clean_checks) > 12 and not verbose:
        w(f"  … mais {len(inv.clean_checks) - 12} (use -v)\n")
    if verbose:
        w("\nLINHA DO TEMPO\n")
        for e in inv.timeline:
            w(f"  {fmt(e.timestamp)}  {e.text}" + (f"  -> {'; '.join(e.links)}" if e.links else "") + "\n")
        w("\nLIMITAÇÕES\n" + "".join(f"  - {x}\n" for x in inv.limitations))
    w("\nCOBERTURA\n" + "".join(f"  {k}: {v}\n" for k, v in s.coverage.items()))

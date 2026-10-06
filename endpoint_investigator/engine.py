"""Orquestra: NORMALIZAÇÃO -> CORRELAÇÃO -> EVIDÊNCIAS -> HIPÓTESES -> RESULTADO."""

from __future__ import annotations

from collections import Counter

from . import context, rules
from .context import ACCEPTED_RE, FAILED_RE
from .model import CONFIDENCES, SEVERITIES, Investigation, Snapshot, TimelineEntry

MAX_TIMELINE = 250


def investigate(snap: Snapshot) -> Investigation:
    ctx = context.build(snap)
    findings, clean = [], []
    for rule in rules.RULES:
        f, c = rule(ctx)
        findings += f
        clean += c
    # PERM-01 só olha o que ainda não foi explicado por uma correlação mais forte
    f, c = rules.perm01_contrast(ctx, {p for x in findings for p in x.entities.get("paths", [])})
    findings += f
    clean += c
    findings.sort(key=lambda x: (SEVERITIES.index(x.severity), CONFIDENCES.index(x.confidence), x.rule))
    for i, f in enumerate(findings, 1):
        f.id = f"F-{i:03d}"
    return Investigation(snap, findings, clean, timeline(ctx, findings),
                         conclusion(snap, findings), limitations(snap))


def timeline(ctx, findings) -> list[TimelineEntry]:
    """Junta logs, mtimes de arquivos citados e horários de processos numa só ordem.
    Em coletas grandes (live), mantém só o que se relaciona a findings ou a autenticação."""
    snap = ctx.snap
    pids = {int(p) for f in findings for p in f.entities.get("pids", [])}
    units = {u for f in findings for u in f.entities.get("services", [])}
    small, live = len(snap.logs) <= MAX_TIMELINE, snap.origin.startswith("live")
    out = []
    for i, lg in enumerate(snap.logs):
        pid, unit = ctx.log_proc.get(i), ctx.log_service.get(i)
        auth = ACCEPTED_RE.search(lg.message) or FAILED_RE.search(lg.message) or lg.ident in ("sudo", "su")
        if small or auth or pid in pids or unit in units:
            links = ([f"PID {pid} ({ctx.procs[pid].user})"] if pid else []) + ([unit] if unit else [])
            out.append(TimelineEntry(lg.timestamp, str(lg.ref), f"{lg.ident}: {lg.message}", links))
    for f in findings:
        for path in f.entities.get("paths", []):
            if (m := snap.files.get(path)) and m.mtime:
                out.append(TimelineEntry(m.mtime, str(m.ref), f"mtime de {path} ({m.mode_str})", [f.id]))
    for p in snap.processes:
        if p.timestamp and (not live or p.pid in pids):
            svc = ctx.proc_service.get(p.pid)
            verb = "início do processo" if live else "processo observado no snapshot"
            out.append(TimelineEntry(p.timestamp, str(p.ref), f"{verb}: PID {p.pid} ({p.user}) {p.cmd[:60]}",
                                     [svc.service.unit] if svc else []))
    out.sort(key=lambda e: (e.timestamp is None, e.timestamp.timestamp() if e.timestamp else 0))
    return out


def conclusion(snap: Snapshot, findings) -> list[str]:
    c = Counter(f.severity for f in findings)
    lines = [f"{len(findings)} finding(s): " + ", ".join(f"{c[s]} {s}" for s in SEVERITIES) + "."]
    high = [f for f in findings if f.severity == "alto"]
    if high:
        lines.append("Relações de risco que merecem investigação prioritária: "
                     + "; ".join(f"{f.id} {f.title}" for f in high[:5]) + ".")
    elif any(f.severity == "medio" for f in findings):
        lines.append("Sem achados de severidade alta; há pontos de atenção de severidade média.")
    else:
        lines.append("Com as evidências disponíveis, não foram encontradas relações de risco relevantes.")
    lines.append("Nenhum finding, isoladamente, prova exploração: cada um lista a evidência que falta.")
    gaps = [k for k, v in snap.coverage.items() if v.startswith(("ausente", "indispon"))]
    if gaps:
        lines.append(f"Fontes não disponíveis: {', '.join(gaps)}. Conclusões que dependem delas ficam em aberto.")
    return lines


def limitations(snap: Snapshot) -> list[str]:
    out = list(snap.notes)
    if snap.origin.startswith("dataset"):
        out.append("Dataset sintético: mtimes são artificiais; nenhuma conclusão depende só deles.")
    out += ["Snapshot pontual: processos de vida curta entre coletas não são vistos.",
            "Membros de grupos não são coletados: escrita por grupo gera severidade média.",
            "Destinos de rede são classificados de forma descritiva (privado/público), não por reputação."]
    return out

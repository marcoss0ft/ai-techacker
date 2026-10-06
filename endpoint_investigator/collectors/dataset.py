"""Coletor offline: lê um diretório no formato do ``generate_dataset.py``.

Arquivos: processes.csv, permissions.csv, services.txt (pelo menos um),
journal.log, metadata.json e connections.csv (opcionais). Arquivos ausentes
e linhas inválidas vão para ``coverage``/``notes`` em vez de abortar.
"""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime
from pathlib import Path

from ..analysis import exe_and_script, parse_mode, split_cmd
from ..model import Connection, FileMeta, LogEvent, Process, Service, Snapshot, SourceRef

# "Sep 14 09:01:03 srv-app-01 backup-agent[2417]: backup job started"
# ou, no formato do journalctl -o short-iso, "2026-09-14T09:01:03-0300 host ident[pid]: msg"
LOG_RE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\dT[\d:]{8}\S*|[A-Z][a-z]{2}\s+\d{1,2}\s+[\d:]{8})\s+\S+\s+"
                    r"(?P<ident>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")


def parse_iso(value: str | None) -> datetime | None:
    value = (value or "").strip().replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", value):                      # -0300 -> -03:00
        value = value[:-2] + ":" + value[-2:]
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def parse_log_line(line: str, year: int, tz, ref: SourceRef) -> LogEvent | None:
    """O formato syslog não tem ano nem fuso: usamos os do snapshot (ver notes)."""
    m = LOG_RE.match(line.rstrip("\n"))
    if not m:
        return None
    if m["ts"][0].isdigit():
        ts = parse_iso(m["ts"])
    else:
        ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S").replace(tzinfo=tz)
    return LogEvent(ts, m["ident"], int(m["pid"]) if m["pid"] else None, m["msg"], ref)


def _rows(path: Path):
    with path.open(newline="", encoding="utf-8-sig") as fh:
        for i, row in enumerate(csv.DictReader(fh)):
            yield i + 2, {(k or "").strip(): (v or "").strip() for k, v in row.items()}   # linha 1 = cabeçalho


def _load_csv(snap: Snapshot, d: Path, name: str, parse) -> None:
    """Lê um CSV linha a linha; linhas que não fazem sentido são contadas e ignoradas."""
    p = d / name
    if not p.exists():
        snap.coverage[name] = "ausente"
        return
    bad = 0
    for line, row in _rows(p):
        try:
            parse(row, SourceRef(name, line))
        except (KeyError, ValueError):
            bad += 1
    snap.coverage[name] = "ok" + (f" ({bad} linhas inválidas ignoradas)" if bad else "")


def collect(directory: str | Path) -> Snapshot:
    d = Path(directory)
    if not d.is_dir():
        raise FileNotFoundError(f"diretório de dataset não encontrado: {d}")
    snap = Snapshot(origin=f"dataset:{d}", collected_at=None)

    if (d / "metadata.json").exists():
        snap.metadata = json.loads((d / "metadata.json").read_text(encoding="utf-8"))

    def process(row, ref):
        argv = split_cmd(row["cmd"])
        exe, script = exe_and_script(argv)
        snap.processes.append(Process(int(row["pid"]), int(row["ppid"]), row["user"], row["cmd"], argv,
                                      exe=exe, script=script, timestamp=parse_iso(row.get("timestamp")), ref=ref))

    def permission(row, ref):
        snap.files[row["path"]] = FileMeta(row["path"], row["type"], row["owner"], row["group"],
                                           parse_mode(row["mode"]), parse_iso(row.get("mtime")), ref=ref)

    def connection(row, ref):
        snap.connections.append(Connection(row["proto"], row["state"], row["laddr"], int(row["lport"] or 0),
                                           row["raddr"], int(row["rport"] or 0),
                                           int(row["pid"]) if row.get("pid") else None, ref))

    _load_csv(snap, d, "processes.csv", process)
    _load_csv(snap, d, "permissions.csv", permission)
    _load_csv(snap, d, "connections.csv", connection)

    # services.txt: separado por espaços (nomes longos estouram a coluna fixa do gerador)
    p = d / "services.txt"
    snap.coverage["services.txt"] = "ok" if p.exists() else "ausente"
    for n, raw in enumerate(p.read_text(encoding="utf-8").splitlines() if p.exists() else [], start=1):
        parts = raw.split(None, 3)
        if raw.startswith("UNIT") or len(parts) < 3:
            continue
        execstart = parts[3] if len(parts) > 3 else ""
        argv = split_cmd(execstart)
        exe, script = exe_and_script(argv)
        snap.services.append(Service(parts[0], parts[1], parts[2], execstart, argv, exe, script,
                                     ref=SourceRef("services.txt", n)))

    if not (snap.processes or snap.files or snap.services):
        raise ValueError(f"{d}: nenhum dado de processos, permissões ou serviços")

    # referência temporal: o horário dos processos define ano/fuso dos logs
    stamps = [pr.timestamp for pr in snap.processes if pr.timestamp]
    snap.collected_at = max(stamps) if stamps else None
    ref_dt = min(stamps) if stamps else datetime.now().astimezone()
    if len(stamps) > 1 and max(stamps) > min(stamps):
        snap.notes.append(f"snapshot de processos não é atômico: timestamps de {min(stamps)} a {max(stamps)}.")

    p = d / "journal.log"
    if p.exists():
        bad = 0
        for n, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
            ev = parse_log_line(raw, ref_dt.year, ref_dt.tzinfo, SourceRef("journal.log", n)) if raw.strip() else None
            if ev:
                snap.logs.append(ev)
            elif raw.strip():
                bad += 1
        snap.coverage["journal.log"] = "ok" + (f" ({bad} linhas não reconhecidas)" if bad else "")
        snap.notes.append(f"journal.log não tem ano nem fuso: assumidos {ref_dt.year} e {ref_dt.tzinfo} "
                          "(derivados de processes.csv).")
    else:
        snap.coverage["journal.log"] = "ausente"
    return snap

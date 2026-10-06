"""Modelo normalizado.

Os dois coletores (dataset e live) produzem um ``Snapshot`` com estas mesmas
estruturas. As regras de correlação só enxergam o Snapshot, nunca a origem.
Toda entidade guarda ``ref`` (arquivo/comando e linha de onde veio), para que
cada evidência possa citar a sua fonte.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class SourceRef:
    source: str              # ex.: "processes.csv", "/proc/1234", "systemctl show ssh.service"
    line: int | None = None

    def __str__(self) -> str:
        return f"{self.source}:{self.line}" if self.line is not None else self.source


# ------------------------------------------------------------------ dados coletados
@dataclass
class Process:
    pid: int
    ppid: int
    user: str
    cmd: str
    argv: list[str]
    uid: int | None = None
    euid: int | None = None
    exe: str | None = None               # executável (argv[0] ou /proc/<pid>/exe)
    script: str | None = None            # script interpretado (ex.: bash /opt/x.sh)
    timestamp: datetime | None = None    # observação (dataset) ou início (live)
    unit: str | None = None              # unit systemd pelo cgroup (só live)
    ref: SourceRef = SourceRef("?")


@dataclass
class FileMeta:
    path: str
    type: str                            # file | directory | symlink | other
    owner: str
    group: str
    mode: int
    mtime: datetime | None = None
    target: str | None = None            # destino, se for symlink (só live)
    ref: SourceRef = SourceRef("?")

    @property
    def mode_str(self) -> str:
        return f"{self.mode:04o}"


@dataclass
class Service:
    unit: str
    active: str
    user: str
    execstart: str
    argv: list[str]
    exe: str | None = None
    script: str | None = None
    main_pid: int | None = None          # só live
    fragment_path: str | None = None     # arquivo .service (só live)
    description: str | None = None       # systemd antigo loga "Started <Description>"
    ref: SourceRef = SourceRef("?")

    @property
    def base_name(self) -> str:
        return self.unit[:-8] if self.unit.endswith(".service") else self.unit


@dataclass
class LogEvent:
    timestamp: datetime | None
    ident: str                           # ex.: sshd, systemd, backup-agent
    pid: int | None
    message: str
    ref: SourceRef = SourceRef("?")


@dataclass
class Connection:
    proto: str
    state: str                           # LISTEN | ESTABLISHED | ...
    laddr: str
    lport: int
    raddr: str
    rport: int
    pid: int | None
    ref: SourceRef = SourceRef("?")


@dataclass
class Snapshot:
    origin: str                          # "dataset:<dir>" ou "live:<host>"
    collected_at: datetime | None
    processes: list[Process] = field(default_factory=list)
    files: dict[str, FileMeta] = field(default_factory=dict)
    services: list[Service] = field(default_factory=list)
    logs: list[LogEvent] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    coverage: dict[str, str] = field(default_factory=dict)   # fonte -> ok / ausente / erro
    notes: list[str] = field(default_factory=list)           # suposições da coleta


def fmt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "?"


# ------------------------------------------------------------------ resultado
SEVERITIES = ["alto", "medio", "baixo", "informativo"]
CONFIDENCES = ["alta", "media", "baixa"]


@dataclass
class Evidence:
    statement: str       # o que foi observado
    ref: str             # de onde veio


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    confidence: str
    evidence: list[Evidence]
    interpretation: list[str]
    hypotheses: list[str]
    missing_evidence: list[str]
    not_proven: str
    entities: dict[str, list[str]] = field(default_factory=dict)
    id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CleanCheck:
    """Verificação feita que NÃO gerou finding, com o motivo."""
    rule: str
    subject: str
    reason: str


@dataclass
class TimelineEntry:
    timestamp: datetime | None
    source: str
    text: str
    links: list[str] = field(default_factory=list)


@dataclass
class Investigation:
    snapshot: Snapshot
    findings: list[Finding]
    clean_checks: list[CleanCheck]
    timeline: list[TimelineEntry]
    conclusion: list[str]
    limitations: list[str]

"""Normalização relacional: transforma as listas do Snapshot num grafo.

  * árvore de processos (PID -> PPID) e cadeia de ancestrais;
  * serviço <-> processo, registrando COMO o vínculo foi obtido;
  * sessões SSH (``sshd: user@pts/N``) e o login correspondente no log;
  * recursos de cada serviço (executável, script, unit file, diretórios pais);
  * evento de log -> processo / serviço.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .analysis import basename, parent_dirs, referenced_paths
from .model import FileMeta, LogEvent, Process, Service, Snapshot

SESSION_RE = re.compile(r"^sshd: (?P<user>[^@\s]+)@(?P<tty>\S+)")
ACCEPTED_RE = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port \d+")
FAILED_RE = re.compile(r"(?:Failed \S+ for (?:invalid user )?|Invalid user )(?P<user>\S+) from (?P<ip>\S+)")


@dataclass
class ServiceLink:
    service: Service
    process: Process
    method: str      # "cgroup" | "MainPID" | "ExecStart == cmd" | "nome ... (heurística)" | "descendente de N"

    @property
    def is_main(self) -> bool:
        return not self.method.startswith("descendente")


@dataclass
class Session:
    pid: int
    user: str
    tty: str
    source_ip: str | None = None
    login_event: LogEvent | None = None


@dataclass
class Resource:
    path: str
    role: str        # executável | script | unit file | argumento | diretório pai
    meta: FileMeta | None
    via: str         # de onde veio (serviço, processo ou arquivo que contém)


@dataclass
class Context:
    snap: Snapshot
    procs: dict[int, Process] = field(default_factory=dict)
    children: dict[int, list[int]] = field(default_factory=dict)
    proc_service: dict[int, ServiceLink] = field(default_factory=dict)
    service_procs: dict[str, list[ServiceLink]] = field(default_factory=dict)
    sessions: dict[int, Session] = field(default_factory=dict)
    proc_session: dict[int, Session] = field(default_factory=dict)
    service_resources: dict[str, list[Resource]] = field(default_factory=dict)
    log_proc: dict[int, int] = field(default_factory=dict)        # índice do log -> PID
    log_service: dict[int, str] = field(default_factory=dict)     # índice do log -> unit

    def ancestry(self, pid: int) -> list[Process]:
        chain, cur = [], self.procs.get(pid)
        while cur and cur not in chain:
            chain.append(cur)
            cur = self.procs.get(cur.ppid)
        return chain

    def chain_str(self, pid: int) -> str:
        return " <- ".join(f"{p.pid}:{p.cmd[:45]}({p.user})" for p in self.ancestry(pid))

    def descendants(self, pid: int) -> list[Process]:
        out, stack = [], list(self.children.get(pid, []))
        while stack:
            p = self.procs[stack.pop()]
            out.append(p)
            stack.extend(self.children.get(p.pid, []))
        return out

    def file(self, path: str | None) -> FileMeta | None:
        return self.snap.files.get(path) if path else None

    def processes_using(self, path: str) -> list[Process]:
        """Processos que executam ``path`` ou o recebem como argumento.
        Código inline (``sh -c '...'``) não conta: ali o caminho é só texto."""
        return [p for p in self.procs.values() if path in (p.exe, p.script)
                or ("-c" not in p.argv[1:3] and path in referenced_paths(p.argv))]

    def services_using(self, path: str) -> list[Service]:
        return [s for s in self.snap.services if any(r.path == path for r in self.service_resources[s.unit])]

    def main_links(self, unit: str) -> list[ServiceLink]:
        """Processos principais do serviço: vínculo direto e pai fora do serviço (exclui filhos como sleep)."""
        links = self.service_procs.get(unit, [])
        pids = {l.process.pid for l in links}
        return [l for l in links if l.is_main and l.process.ppid not in pids]

    def logs_for_pid(self, pid: int) -> list[LogEvent]:
        return [self.snap.logs[i] for i, p in self.log_proc.items() if p == pid]

    def logs_for_service(self, unit: str) -> list[LogEvent]:
        return [self.snap.logs[i] for i, u in self.log_service.items() if u == unit]


def build(snap: Snapshot) -> Context:
    ctx = Context(snap=snap)
    ctx.procs = {p.pid: p for p in snap.processes}
    for p in snap.processes:
        if p.ppid in ctx.procs and p.ppid != p.pid:
            ctx.children.setdefault(p.ppid, []).append(p.pid)
    _map_services(ctx)
    _map_sessions(ctx)
    _map_resources(ctx)
    _map_logs(ctx)
    return ctx


def _map_services(ctx: Context) -> None:
    """Vincula processos a serviços, do método mais forte para o mais fraco."""
    def link(svc, proc, method):
        if proc.pid not in ctx.proc_service:
            ctx.proc_service[proc.pid] = sl = ServiceLink(svc, proc, method)
            ctx.service_procs.setdefault(svc.unit, []).append(sl)

    norm = lambda c: " ".join(c.split())   # noqa: E731
    by_unit = {s.unit: s for s in ctx.snap.services}
    for p in ctx.procs.values():                                     # 1) cgroup (live)
        if p.unit in by_unit:
            link(by_unit[p.unit], p, "cgroup")
    for s in ctx.snap.services:
        if s.main_pid in ctx.procs:                                  # 2) MainPID (live)
            link(s, ctx.procs[s.main_pid], "MainPID")
        for p in ctx.procs.values():                                 # 3) linha de comando == ExecStart
            parent = ctx.procs.get(p.ppid)
            if s.execstart and norm(p.cmd) == norm(s.execstart) and not (parent and norm(parent.cmd) == norm(p.cmd)):
                link(s, p, "ExecStart == cmd")
    for s in ctx.snap.services:                     # 4) heurística: apache2.service ~ /usr/sbin/apache2
        if s.unit not in ctx.service_procs:
            for p in ctx.procs.values():
                if p.ppid in (0, 1) and p.exe and basename(p.exe) == s.base_name:
                    link(s, p, "nome da unit == executável (heurística)")
    # 5) descendentes herdam o serviço. Sessões SSH não herdam (no systemd ficam em
    #    session-N.scope) e, se houver cgroup (live), ele prevalece.
    cgroup_known = any(p.unit for p in ctx.procs.values())
    for sl in list(ctx.proc_service.values()):
        stack = list(ctx.children.get(sl.process.pid, []))
        while stack:
            d = ctx.procs[stack.pop()]
            if SESSION_RE.match(d.cmd) or ((d.unit or cgroup_known) and d.unit != sl.service.unit):
                continue
            link(sl.service, d, f"descendente de {sl.process.pid}")
            stack.extend(ctx.children.get(d.pid, []))


def _map_sessions(ctx: Context) -> None:
    for p in ctx.procs.values():
        if m := SESSION_RE.match(p.cmd):
            ctx.sessions[p.pid] = Session(p.pid, m["user"], m["tty"])
    for ev in ctx.snap.logs:                   # "sshd[PID]: Accepted ..." -> sessão com esse PID
        m = ACCEPTED_RE.search(ev.message)
        if m and ev.pid in ctx.sessions:
            ctx.sessions[ev.pid].source_ip, ctx.sessions[ev.pid].login_event = m["ip"], ev
    for s in ctx.sessions.values():
        for d in ctx.descendants(s.pid):
            ctx.proc_session[d.pid] = s


def _map_resources(ctx: Context) -> None:
    for s in ctx.snap.services:
        res: list[Resource] = []

        def add(path, role, via):
            if path and path.startswith("/") and path not in [r.path for r in res]:
                res.append(Resource(path, role, ctx.file(path), via))

        add(s.exe, "executável", s.unit)
        add(s.script, "script", s.unit)
        add(s.fragment_path, "unit file", s.unit)
        for a in referenced_paths(s.argv[1:]):
            add(a, "argumento", s.unit)
        for sl in ctx.service_procs.get(s.unit, []):     # o que o processo realmente executa
            if sl.is_main:
                add(sl.process.exe, "executável", f"PID {sl.process.pid}")
                add(sl.process.script, "script", f"PID {sl.process.pid}")
        for r in list(res):                              # symlink: vale o destino
            if r.meta and r.meta.type == "symlink" and r.meta.target:
                add(r.meta.target, r.role, f"destino de {r.path}")
        for r in list(res):
            for d in parent_dirs(r.path):
                add(d, "diretório pai", r.path)
        ctx.service_resources[s.unit] = res


def _map_logs(ctx: Context) -> None:
    """Liga cada linha de log a um processo (pelo PID) e/ou a um serviço (pelo nome)."""
    ident_unit = {s.base_name: s.unit for s in ctx.snap.services}
    for s in ctx.snap.services:
        if s.exe:
            ident_unit.setdefault(basename(s.exe), s.unit)
    units = {s.unit for s in ctx.snap.services}
    for i, ev in enumerate(ctx.snap.logs):
        if ev.ident == "systemd":
            # "Started foo.service" ou, no systemd < 250, "Started <Description>."
            m = re.search(r"([\w@.\-]+\.service)", ev.message)
            if m and m.group(1) in units:
                ctx.log_service[i] = m.group(1)
            for s in ctx.snap.services:
                if s.description and re.match(rf"(Started|Starting|Stopped|Stopping) {re.escape(s.description)}",
                                              ev.message):
                    ctx.log_service[i] = s.unit
            continue
        if ev.pid in ctx.procs:
            ctx.log_proc[i] = ev.pid
            if ev.pid in ctx.proc_service:
                ctx.log_service[i] = ctx.proc_service[ev.pid].service.unit
                continue
        if ev.ident in ident_unit:
            ctx.log_service[i] = ident_unit[ev.ident]

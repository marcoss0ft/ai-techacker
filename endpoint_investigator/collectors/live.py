"""Coletor ao vivo para GNU/Linux (snapshot sob demanda, sem dependências).

    /proc/<pid>/{stat,status,cmdline,exe,cwd,cgroup}   processos
    systemctl list-units + systemctl show               serviços
    os.lstat()                                          permissões (só do que é usado)
    journalctl -o short-iso                             logs
    /proc/net/{tcp,tcp6,udp,udp6} + /proc/*/fd          sockets -> PID

Com root a visibilidade é completa. Sem root, o que não pôde ser lido fica
registrado em ``coverage``.
"""

from __future__ import annotations

import glob
import grp
import os
import pwd
import re
import shutil
import socket
import stat as st
import subprocess
from datetime import datetime, timezone

from ..analysis import exe_and_script, parent_dirs, referenced_paths, split_cmd
from ..model import Connection, FileMeta, Process, Service, Snapshot, SourceRef
from .dataset import parse_log_line


def _read(path: str, mode: str = "r"):
    try:
        with open(path, mode) as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return None


def _run(cmd: list[str]) -> str | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.stdout if r.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _name(lookup, ident) -> str:
    try:
        return lookup(ident)[0]
    except (KeyError, TypeError):
        return str(ident)


# ------------------------------------------------------------------ processos
def _collect_processes(snap: Snapshot) -> None:
    clk = os.sysconf("SC_CLK_TCK")
    btime = next((int(line.split()[1]) for line in (_read("/proc/stat") or "").splitlines()
                  if line.startswith("btime")), 0)
    denied = 0
    for d in glob.glob("/proc/[0-9]*"):
        pid = int(d.rsplit("/", 1)[1])
        stat_raw, status = _read(f"{d}/stat"), _read(f"{d}/status")
        if not stat_raw or not status:
            continue                                   # terminou durante a coleta
        comm = stat_raw[stat_raw.find("(") + 1: stat_raw.rfind(")")]
        fields = stat_raw[stat_raw.rfind(")") + 2:].split()
        uid_line = next(line.split() for line in status.splitlines() if line.startswith("Uid:"))
        argv = [a.decode(errors="replace") for a in (_read(f"{d}/cmdline", "rb") or b"").split(b"\0") if a]
        kthread = not argv
        argv = argv or [f"[{comm}]"]
        try:
            exe = os.readlink(f"{d}/exe").replace(" (deleted)", "")
        except OSError:
            exe = None
            denied += not kthread
        cg = re.search(r"/([^/]+\.service)(?:/|$)", _read(f"{d}/cgroup") or "", re.M)
        argv_exe, script = exe_and_script(argv)
        if script and not script.startswith("/"):      # script relativo: resolve pelo cwd
            try:
                script = os.path.normpath(os.path.join(os.readlink(f"{d}/cwd"), script))
            except OSError:
                pass
        start = datetime.fromtimestamp(btime + int(fields[19]) / clk, tz=timezone.utc).astimezone()
        snap.processes.append(Process(
            pid, int(fields[1]), _name(pwd.getpwuid, int(uid_line[1])), " ".join(argv), argv,
            uid=int(uid_line[1]), euid=int(uid_line[2]), exe=None if kthread else (exe or argv_exe),
            script=script, timestamp=start, unit=cg.group(1) if cg else None, ref=SourceRef(f"/proc/{pid}")))
    snap.processes.sort(key=lambda p: p.pid)
    snap.coverage["/proc"] = "ok" + (f" (exe ilegível em {denied} processos: sem privilégio)" if denied else "")


# ------------------------------------------------------------------ serviços
def canon(path: str | None) -> str | None:
    """Caminho canônico: /bin, /lib e /sbin costumam ser symlinks para /usr."""
    return os.path.realpath(path) if path and path.startswith("/") else path


def _collect_services(snap: Snapshot) -> None:
    listing = _run(["systemctl", "list-units", "--type=service", "--state=running",
                    "--no-legend", "--plain", "--no-pager"])
    if listing is None:
        snap.coverage["systemctl"] = "indisponível (sem systemd?)"
        return
    units = [line.split()[0] for line in listing.splitlines() if line.strip()]
    shown = _run(["systemctl", "show", "--no-pager", "-p",
                  "Id,SubState,User,ExecStart,MainPID,FragmentPath,Description", *units]) or ""
    for block in shown.strip().split("\n\n"):
        props = dict(line.partition("=")[::2] for line in block.splitlines())
        if not props.get("Id"):
            continue
        m = re.search(r"argv\[\]=(.*?) ;", props.get("ExecStart", ""))
        execstart = m.group(1).strip() if m else ""
        argv = split_cmd(execstart)
        exe, script = exe_and_script(argv)
        real = re.search(r"path=(\S+)", props.get("ExecStart", ""))   # argv[0] pode ter prefixo @/-/+
        snap.services.append(Service(
            props["Id"], props.get("SubState", "?"), props.get("User") or "root",   # sem User= => root
            execstart, argv, canon(real.group(1) if real else exe), canon(script),
            main_pid=int(props.get("MainPID") or 0) or None, fragment_path=canon(props.get("FragmentPath") or None),
            description=props.get("Description") or None, ref=SourceRef(f"systemctl show {props['Id']}")))
    snap.coverage["systemctl"] = f"ok ({len(snap.services)} serviços em execução)"


# ------------------------------------------------------------------ permissões
def _stat(snap: Snapshot, path: str) -> None:
    if path in snap.files:
        return
    try:
        s = os.lstat(path)
    except OSError:
        return
    typ = ("directory" if st.S_ISDIR(s.st_mode) else "symlink" if st.S_ISLNK(s.st_mode)
           else "file" if st.S_ISREG(s.st_mode) else "other")
    meta = FileMeta(path, typ, _name(pwd.getpwuid, s.st_uid), _name(grp.getgrgid, s.st_gid), st.S_IMODE(s.st_mode),
                    datetime.fromtimestamp(s.st_mtime, tz=timezone.utc).astimezone(), ref=SourceRef(f"lstat {path}"))
    snap.files[path] = meta
    if typ == "symlink":
        meta.target = os.path.realpath(path)
        for p in [meta.target, *parent_dirs(meta.target)]:
            _stat(snap, p)


def _collect_permissions(snap: Snapshot) -> None:
    """Orientado a contexto: só o que serviços e processos usam, e seus diretórios pais."""
    targets = set()
    for s in snap.services:
        targets.update(p for p in [s.exe, s.script, s.fragment_path, *referenced_paths(s.argv)] if p)
    for pr in snap.processes:
        targets.update(p for p in (pr.exe, pr.script) if p and p.startswith("/"))
    for p in sorted(targets | {d for t in targets for d in parent_dirs(t)}):
        _stat(snap, p)
    snap.coverage["permissions (lstat)"] = f"ok ({len(snap.files)} objetos)"


# ------------------------------------------------------------------ logs
def _collect_logs(snap: Snapshot, hours: int, max_lines: int = 5000) -> None:
    # -r: com --since, "-n N" devolveria as N entradas MAIS ANTIGAS; em ordem
    # reversa pegamos as mais recentes e depois voltamos à ordem cronológica.
    out = _run(["journalctl", "-o", "short-iso", "--no-pager", "-q", "-r",
                "--since", f"-{hours}h", "-n", str(max_lines)])
    if not out:
        snap.coverage["journalctl"] = "indisponível (journal ilegível sem privilégio?)"
        return
    now = datetime.now().astimezone()
    for i, line in enumerate(reversed(out.splitlines()), start=1):
        ev = parse_log_line(line, now.year, now.tzinfo, SourceRef("journalctl", i))
        if ev:
            snap.logs.append(ev)
    snap.coverage["journalctl"] = f"ok ({len(snap.logs)} eventos, últimas {hours}h)"


# ------------------------------------------------------------------ rede
TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "0A": "LISTEN", "06": "TIME_WAIT", "07": "CLOSE"}


def _addr(value: str) -> tuple[str, int]:
    host, port = value.split(":")
    raw = bytes.fromhex(host)
    if len(raw) == 4:
        addr = socket.inet_ntop(socket.AF_INET, raw[::-1])
    else:
        addr = socket.inet_ntop(socket.AF_INET6, b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
        addr = addr[7:] if addr.startswith("::ffff:") else addr
    return addr, int(port, 16)


def _collect_connections(snap: Snapshot) -> None:
    inode_pid = {}
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            link = os.readlink(fd)
        except OSError:
            continue
        if link.startswith("socket:["):
            inode_pid[link[8:-1]] = int(fd.split("/")[2])
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        for line in (_read(f"/proc/net/{proto}") or "").splitlines()[1:]:
            f = line.split()
            (la, lp), (ra, rp) = _addr(f[1]), _addr(f[2])
            state = TCP_STATES.get(f[3], f[3]) if proto.startswith("tcp") else (
                "LISTEN" if ra in ("0.0.0.0", "::") else "UNCONN")
            if state not in ("TIME_WAIT", "CLOSE"):
                snap.connections.append(Connection(proto.rstrip("6"), state, la, lp, ra, rp,
                                                   inode_pid.get(f[9]), SourceRef(f"/proc/net/{proto}")))
    unmapped = sum(c.pid is None for c in snap.connections)
    snap.coverage["/proc/net"] = f"ok ({len(snap.connections)} sockets" + (
        f"; {unmapped} sem PID: sem permissão ou socket do kernel)" if unmapped else ")")


def collect(log_hours: int = 24) -> Snapshot:
    if not os.path.isdir("/proc/self"):
        raise RuntimeError("coleta ao vivo requer GNU/Linux (/proc indisponível)")
    now = datetime.now().astimezone()
    snap = Snapshot(origin=f"live:{socket.gethostname()}", collected_at=now,
                    metadata={"collector": "live", "euid": os.geteuid(), "kernel": os.uname().release})
    if os.geteuid() != 0:
        snap.notes.append("coleta sem root: exe/fd de processos de outros usuários e parte do journal "
                          "podem estar invisíveis.")
    _collect_processes(snap)
    _collect_services(snap)
    _collect_permissions(snap)
    _collect_logs(snap, log_hours)
    _collect_connections(snap)
    return snap

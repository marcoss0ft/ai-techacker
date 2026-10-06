#!/usr/bin/env bash
# Cria situações CONTROLADAS para validar o Endpoint Investigator numa VM
# (Kali/Ubuntu). Não gera incidente real: apenas configurações inseguras e
# processos inofensivos que a ferramenta deve correlacionar.
#
#   sudo bash lab/lab_setup.sh up      # cria o cenário (partes com root se executado com sudo)
#   sudo bash lab/lab_setup.sh down    # remove tudo
#
# Sem sudo, apenas os cenários de usuário (listener e script gravável) são criados.
set -euo pipefail
ACTION="${1:-up}"
LAB_USER="${SUDO_USER:-$(id -un)}"

as_user() { if [ "$(id -u)" -eq 0 ]; then sudo -u "$LAB_USER" "$@"; else "$@"; fi; }

up() {
  # 1) listener sem serviço a partir de diretório oculto em /dev/shm (CORR-05 alto).
  #    Se /dev/shm estiver montado com noexec, usa /var/tmp/.lab (também volátil).
  LAB_BIN=/dev/shm/.lab
  as_user mkdir -p "$LAB_BIN" && as_user cp /usr/bin/python3 "$LAB_BIN/python3"
  if ! as_user "$LAB_BIN/python3" -c 'pass' 2>/dev/null; then
    as_user rm -rf "$LAB_BIN"; LAB_BIN=/var/tmp/.lab
    as_user mkdir -p "$LAB_BIN" && as_user cp /usr/bin/python3 "$LAB_BIN/python3"
  fi
  as_user bash -c "nohup $LAB_BIN/python3 -m http.server 8099 --bind 0.0.0.0 >/dev/null 2>&1 &"
  # 2) script 0777 executado só por usuário comum (PERM-01 baixo: higiene)
  as_user bash -c 'mkdir -p /tmp/lab && printf "#!/bin/bash\nwhile true; do sleep 60; done\n" > /tmp/lab/job.sh && chmod 0777 /tmp/lab/job.sh'
  as_user bash -c 'nohup /bin/bash /tmp/lab/job.sh >/dev/null 2>&1 &'

  if [ "$(id -u)" -eq 0 ]; then
    # 3) serviço root que executa script gravável por todos (CORR-01 alto)
    mkdir -p /opt/lab-backup
    printf '#!/bin/bash\nwhile true; do logger -t lab-backup "backup ok"; sleep 30; done\n' > /opt/lab-backup/backup.sh
    chmod 0777 /opt/lab-backup/backup.sh
    cat > /etc/systemd/system/lab-backup.service <<'EOF'
[Unit]
Description=Lab backup agent (Endpoint Investigator)
[Service]
ExecStart=/bin/bash /opt/lab-backup/backup.sh
[Install]
WantedBy=multi-user.target
EOF
    # 4) serviço root com script 0700 (deve gerar verificação sem achado, não finding)
    mkdir -p /opt/lab-ok
    printf '#!/bin/bash\nwhile true; do sleep 30; done\n' > /opt/lab-ok/run.sh
    chmod 0700 /opt/lab-ok/run.sh
    cat > /etc/systemd/system/lab-ok.service <<'EOF'
[Unit]
Description=Lab restricted service (Endpoint Investigator)
[Service]
ExecStart=/bin/bash /opt/lab-ok/run.sh
EOF
    systemctl daemon-reload
    systemctl start lab-backup.service lab-ok.service
  fi
  echo "cenário de laboratório criado (usuário: $LAB_USER)"
}

down() {
  pkill -f '/(dev/shm|var/tmp)/.lab/python3' || true
  pkill -f '/tmp/lab/job.sh' || true
  rm -rf /dev/shm/.lab /var/tmp/.lab /tmp/lab
  if [ "$(id -u)" -eq 0 ]; then
    systemctl stop lab-backup.service lab-ok.service 2>/dev/null || true
    rm -f /etc/systemd/system/lab-backup.service /etc/systemd/system/lab-ok.service
    rm -rf /opt/lab-backup /opt/lab-ok
    systemctl daemon-reload
  fi
  echo "cenário de laboratório removido"
}

case "$ACTION" in up) up ;; down) down ;; *) echo "uso: $0 up|down"; exit 1 ;; esac

#!/usr/bin/env bash
# Roteiro da demonstração (cerca de 5 min). Uso: bash demo.sh (em Linux; a parte "live" pede sudo)
set -e
cd "$(dirname "$0")"
pause() { read -rp $'\n[enter] '"$1"$'\n' _; }

pause "1) Serviço root com script 0777 + sessão de usuário comum: CORR-01 alto (4 fontes cruzadas)"
python3 -m endpoint_investigator dataset datasets/correlation | less -R

pause "2) Serviço root com script 0700: NÃO é vulnerabilidade (verificação sem achado)"
python3 -m endpoint_investigator dataset datasets/privileged_service -v | less -R

pause "3) Conexão externa de serviço root: hipótese, não conclusão (NÃO caracteriza C2)"
python3 -m endpoint_investigator dataset datasets/ambiguous -v | less -R

pause "4) Apache abrindo shell com conexão externa: CORR-02 + CORR-05"
python3 -m endpoint_investigator dataset datasets/webshell | less -R

pause "5) Falhas de SSH -> login do mesmo IP -> sudo: CORR-04 + linha do tempo"
python3 -m endpoint_investigator dataset datasets/bruteforce -v | less -R

pause "6) Laboratório real (sudo): cria o cenário, coleta ao vivo, remove tudo"
sudo bash lab/lab_setup.sh up
sleep 5
sudo python3 -m endpoint_investigator live -o /tmp/demo-live.json
sudo bash lab/lab_setup.sh down
echo "JSON estruturado em /tmp/demo-live.json"

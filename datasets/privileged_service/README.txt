ENDPOINT INVESTIGATOR - DATASET DE TREINAMENTO

Este dataset é sintético e foi criado para testar ferramentas de investigação de endpoints Linux.
Não representa um incidente real.

Nível: basic
Cenário: privileged_service

Arquivos:
- processes.csv: snapshot de processos.
- permissions.csv: metadados de arquivos e diretórios.
- services.txt: serviços em execução.
- journal.log: eventos de sistema.
- metadata.json: metadados de geração.

Orientação: não assuma que um único indicador é suficiente para concluir que houve comprometimento.
Procure correlações e diferencie evidência, interpretação e hipótese.

Nota didática do cenário:
O serviço executa como root, mas o script está restrito a root. O objetivo é evitar a regra simplista 'serviço root = vulnerabilidade'.

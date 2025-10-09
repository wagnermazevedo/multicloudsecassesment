#!/usr/bin/env bash
set -Eeuo pipefail

echo "=== Inicializando EntryPoint do MultiCloud Prowler Runner ==="
date

# 1. Caminhos padrão
RUNNER_SCRIPT="/usr/local/bin/run-prowler.sh"
PROWLER_BIN="/root/.pyenv/versions/3.11.13/bin/prowler"

# 2. PATH fixo para garantir acesso aos binários
export PATH="/root/.pyenv/versions/3.11.13/bin:/usr/local/bin:/usr/bin:/bin"

# 3. Verificações de pré-execução
echo "=== Verificando binários essenciais ==="

for bin in "$PROWLER_BIN" /usr/local/bin/aws /usr/bin/az /usr/bin/gcloud /usr/bin/pwsh; do
  if [[ ! -x "$bin" ]]; then
    echo "AVISO: Binário ausente ou não executável -> $bin"
  else
    echo "OK: $(basename "$bin") disponível em $bin"
  fi
done

if [[ ! -x "$RUNNER_SCRIPT" ]]; then
  echo "ERRO: Script principal não encontrado em $RUNNER_SCRIPT"
  exit 127
fi

# 4. Exibe variáveis principais
echo "=== Variáveis de ambiente ==="
echo "CLOUD_PROVIDER=${CLOUD_PROVIDER:-não definido}"
echo "TARGET_ACCOUNTS=${TARGET_ACCOUNTS:-não definido}"
echo "AWS_REGION=${AWS_REGION:-us-east-1}"
echo "S3_BUCKET=${S3_BUCKET:-my-prowler-results}"
echo "PROWLER_DEBUG=${PROWLER_DEBUG:-0}"
echo "PATH=$PATH"
echo

# 5. Validação mínima antes da execução
if [[ -z "${CLOUD_PROVIDER:-}" || -z "${TARGET_ACCOUNTS:-}" ]]; then
  echo "ERRO: As variáveis CLOUD_PROVIDER e TARGET_ACCOUNTS são obrigatórias."
  echo "Exemplo: docker run -e CLOUD_PROVIDER=aws -e TARGET_ACCOUNTS=123456789012 multicloud-prowler"
  exit 1
fi

# 6. Execução principal
echo "=== Iniciando execução principal ==="
/bin/bash "$RUNNER_SCRIPT"

# 7. Mantém container ativo em modo debug
if [[ "${PROWLER_DEBUG:-0}" == "1" ]]; then
  echo "PROWLER_DEBUG=1 ativo. Mantendo container em execução para depuração."
  tail -f /dev/null
fi

echo "=== Execução concluída ==="

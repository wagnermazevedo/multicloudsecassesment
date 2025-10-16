#!/usr/bin/env bash
set -euo pipefail

# Wrapper que garante parâmetros seguros para o runner.
# Autor: Wagner Azevedo
# Criado em: 2025-10-16T00:55:00Z
# Uso:
#   ./run-multicloud-wrapper.sh acme aws 767397997901
#   ou export CLIENT_NAME, CLOUD_PROVIDER, ACCOUNT_ID e execute sem args.

CLIENT_NAME="${CLIENT_NAME:-${1:-undefined}}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-${2:-undefined}}"
ACCOUNT_ID="${ACCOUNT_ID:-${3:-undefined}}"

echo "[WRAPPER] 🧭 Executando runner com:"
echo "  CLIENT_NAME=$CLIENT_NAME"
echo "  CLOUD_PROVIDER=$CLOUD_PROVIDER"
echo "  ACCOUNT_ID=$ACCOUNT_ID"

if [ ! -x /usr/local/bin/run-multicloudassessment.sh ]; then
  echo "[WRAPPER] ❌ Runner não encontrado ou sem permissão de execução."
  exit 1
fi

# Executa o runner com argumentos sempre definidos
exec /usr/local/bin/run-multicloudassessment.sh "$CLIENT_NAME" "$CLOUD_PROVIDER" "$ACCOUNT_ID"

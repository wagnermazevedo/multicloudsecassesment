#!/bin/bash
set -euo pipefail

echo "[RUNNER] Iniciando execução do Prowler Runner"

# === Localiza o binário do Prowler ===
if command -v prowler >/dev/null 2>&1; then
  PROWLER_BIN="$(command -v prowler)"
else
  PROWLER_BIN=$(find /home/prowler/.cache/pypoetry/virtualenvs -type f -name "prowler" | head -n 1 || true)
fi

if [ -z "$PROWLER_BIN" ]; then
  echo "[RUNNER] ERRO: Não foi possível localizar o binário do Prowler!"
  exit 1
else
  echo "[RUNNER] Prowler encontrado em: $PROWLER_BIN"
fi

# === Exemplo de execução (substituir depois pelos loops multi-cloud) ===
if [ -z "${CLOUD_PROVIDER:-}" ]; then
  echo "[RUNNER] ERRO: Variável CLOUD_PROVIDER não definida!"
  exit 1
fi

if [ -z "${TARGET_ACCOUNTS:-}" ]; then
  echo "[RUNNER] ERRO: Variável TARGET_ACCOUNTS não definida!"
  exit 1
fi

echo "[RUNNER] Rodando Prowler para ${CLOUD_PROVIDER^^}..."
IFS=',' read -ra ACCOUNTS <<< "$TARGET_ACCOUNTS"
for ACCOUNT in "${ACCOUNTS[@]}"; do
  echo "[RUNNER] --- Rodando Prowler para conta $ACCOUNT ---"
  "$PROWLER_BIN" "$CLOUD_PROVIDER" --account-id "$ACCOUNT" --list-categories || true
done

echo "[RUNNER] Execução concluída com sucesso."


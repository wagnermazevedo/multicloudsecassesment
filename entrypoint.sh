#!/usr/bin/env bash
set -Eeuo pipefail

echo "🛰️ Iniciando container $(date -u)"
echo "🔧 Executando run-prowler.sh ..."

# Executa o script principal
/usr/local/bin/run-prowler.sh "$@" || {
  echo "⚠️ Falha detectada (exit code $?). Entrando em modo debug..."
}

# Mantém o processo PID 1 vivo sempre
echo "💤 Container permanecerá ativo para depuração."
trap 'echo "🚪 Interrompido manualmente, encerrando..."; exit 0' SIGINT SIGTERM
while true; do sleep 300; done

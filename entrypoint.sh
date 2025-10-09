#!/usr/bin/env bash
set -Eeuo pipefail

# Roda o runner; se falhar, mantém o container vivo para debug
/usr/local/bin/run-prowler.sh || {
  ec=$?
  echo "⚠️ Runner falhou (exit $ec). Entrando em modo debug…"
  # Se quiser abrir um shell direto quando falhar:
  if [[ "${PROWLER_DEBUG:-0}" == "1" ]]; then
    echo "💡 PROWLER_DEBUG=1 → abrindo shell interativo."
    exec bash -l
  fi
  # Caso contrário, apenas fica vivo
  tail -f /dev/null
}

# Caso queira manter vivo mesmo quando der certo:
if [[ "${PROWLER_DEBUG:-0}" == "1" ]]; then
  echo "✅ Runner finalizado, mas PROWLER_DEBUG=1 → mantendo container vivo."
  tail -f /dev/null
fi

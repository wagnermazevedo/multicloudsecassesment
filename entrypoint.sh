#!/bin/bash
set -euo pipefail

echo "[ENTRYPOINT] Iniciando container..."

# === Detecta virtualenv do prowler dinamicamente ===
if [ -d "/home/prowler/.cache/pypoetry/virtualenvs" ]; then
  VENV_PATH=$(find /home/prowler/.cache/pypoetry/virtualenvs -type d -name "prowler-*-py3.*" | head -n 1)
  if [ -n "$VENV_PATH" ]; then
    echo "[ENTRYPOINT] Virtualenv detectado em: $VENV_PATH"
    export PATH="$VENV_PATH/bin:$PATH"
  else
    echo "[ENTRYPOINT] Nenhum virtualenv do prowler encontrado em /home/prowler/.cache/pypoetry/virtualenvs"
  fi
else
  echo "[ENTRYPOINT] Diretório /home/prowler/.cache/pypoetry/virtualenvs não existe."
fi

# === Garante execução do PowerShell ===
chmod +x /usr/bin/pwsh || true

# === Executa script principal ===
echo "[ENTRYPOINT] Executando run-prowler.sh..."
/usr/local/bin/run-prowler.sh "$@"

# === Mantém o container vivo em modo debug ===
if [ "${PROWLER_DEBUG:-0}" = "1" ]; then
  echo "[ENTRYPOINT] Modo DEBUG ativo - mantendo container vivo."
  tail -f /dev/null
fi

#!/usr/bin/env bash
set -euo pipefail

echo "[ENTRYPOINT] Iniciando container em $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# ==============================
# Função: Instalar dependências básicas
# ==============================
install_base_deps() {
  echo "[ENTRYPOINT] Instalando dependências básicas..."
  apt-get update -y && \
  apt-get install -y --no-install-recommends \
    jq curl unzip bash wget ca-certificates gnupg lsb-release apt-transport-https dos2unix && \
  rm -rf /var/lib/apt/lists/*
  echo "[ENTRYPOINT] Dependências básicas instaladas."
}

# ==============================
# Função: Instalar AWS CLI
# ==============================
install_aws_cli() {
  echo "[ENTRYPOINT] Instalando AWS CLI..."
  curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip -q awscliv2.zip
  ./aws/install
  rm -rf awscliv2.zip ./aws
  aws --version || echo "[ENTRYPOINT] Aviso: AWS CLI não encontrada após instalação."
}

# ==============================
# Função: Instalar Azure CLI
# ==============================
install_azure_cli() {
  echo "[ENTRYPOINT] Instalando Azure CLI..."
  curl -sL https://aka.ms/InstallAzureCLIDeb | bash || {
    echo "[ENTRYPOINT] Falha ao instalar Azure CLI."
    return 1
  }
  az version | head -n 5 || echo "[ENTRYPOINT] Azure CLI instalada, mas falha ao obter versão."
}

# ==============================
# Função: Instalar PowerShell
# ==============================
install_powershell() {
  local POWERSHELL_VERSION=7.5.0
  local ARCH
  ARCH=$(uname -m)
  echo "[ENTRYPOINT] Instalando PowerShell ($POWERSHELL_VERSION)..."

  if [ "$ARCH" = "x86_64" ]; then
    wget -q "https://github.com/PowerShell/PowerShell/releases/download/v${POWERSHELL_VERSION}/powershell-${POWERSHELL_VERSION}-linux-x64.tar.gz" -O /tmp/pwsh.tar.gz
  else
    wget -q "https://github.com/PowerShell/PowerShell/releases/download/v${POWERSHELL_VERSION}/powershell-${POWERSHELL_VERSION}-linux-arm64.tar.gz" -O /tmp/pwsh.tar.gz
  fi

  mkdir -p /opt/microsoft/powershell/7
  tar zxf /tmp/pwsh.tar.gz -C /opt/microsoft/powershell/7
  chmod +x /opt/microsoft/powershell/7/pwsh
  ln -sf /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh
  rm /tmp/pwsh.tar.gz

  pwsh -Command '$PSVersionTable' || echo "[ENTRYPOINT] PowerShell instalado, mas falha ao executar."
}

# ==============================
# Função: Instalar Google Cloud SDK
# ==============================
install_gcloud() {
  echo "[ENTRYPOINT] Instalando Google Cloud SDK..."
  echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
    | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
  curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg \
    | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
  apt-get update -y
  apt-get install -y --no-install-recommends google-cloud-cli
  gcloud version | head -n 5 || echo "[ENTRYPOINT] GCloud SDK instalado, mas falha ao obter versão."
  rm -rf /var/lib/apt/lists/*
}

# ==============================
# Função: Detectar e adicionar virtualenv do Prowler
# ==============================
configure_virtualenv_path() {
  echo "[ENTRYPOINT] Detectando virtualenv do Prowler..."
  VENV_PATH=$(find /home/prowler/.cache/pypoetry/virtualenvs -type d -name "prowler-*-py3.*" | head -n 1 || true)
  if [ -n "$VENV_PATH" ]; then
    echo "[ENTRYPOINT] Virtualenv detectado em: $VENV_PATH"
    export PATH="$VENV_PATH/bin:$PATH"
  else
    echo "[ENTRYPOINT] Nenhum virtualenv do Prowler detectado."
  fi
}

# ==============================
# Função: Diagnóstico de binários
# ==============================
diagnose_paths() {
  echo "[ENTRYPOINT] Diagnóstico de ferramentas disponíveis:"
  for cmd in prowler aws az gcloud pwsh python3; do
    printf "  %-10s -> " "$cmd"
    if command -v "$cmd" >/dev/null 2>&1; then
      echo "$(command -v "$cmd")"
    else
      echo "❌ não encontrado"
    fi
  done
  echo
}

# ==============================
# Execução principal
# ==============================
main() {
  install_base_deps
  install_aws_cli
  install_azure_cli
  install_powershell
  install_gcloud
  configure_virtualenv_path
  diagnose_paths

  echo "[ENTRYPOINT] Executando run-prowler.sh..."
  exec /usr/local/bin/run-prowler.sh
}

main "$@"

#!/usr/bin/env bash
set -euo pipefail

echo "[ENTRYPOINT] 🔹 Inicializando container em $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# ==============================
# Detectar provider e variáveis obrigatórias
# ==============================
required_vars=("CLIENT_NAME" "CLOUD_PROVIDER" "ACCOUNT_ID" "S3_BUCKET")
for var in "${required_vars[@]}"; do
  if [ -z "${!var:-}" ]; then
    read -rp "[ENTRYPOINT] Informe o valor de ${var}: " value
    export "$var"="$value"
  fi
done

CLOUD_PROVIDER=$(echo "$CLOUD_PROVIDER" | tr '[:upper:]' '[:lower:]')

# ==============================
# Instalações seletivas
# ==============================
install_base_deps() {
  apt-get update -y && apt-get install -y --no-install-recommends jq curl unzip bash wget ca-certificates gnupg lsb-release apt-transport-https dos2unix
  apt-get install -y --no-install-recommends uuid-runtime && 
  rm -rf /var/lib/apt/lists/*
}

install_aws_cli() {
  echo "[ENTRYPOINT] Instalando AWS CLI..."
  curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip -q awscliv2.zip && ./aws/install && rm -rf awscliv2.zip ./aws
}

install_azure_cli() {
  echo "[ENTRYPOINT] Instalando Azure CLI..."
  curl -sL https://aka.ms/InstallAzureCLIDeb | bash
}

install_gcloud() {
  echo "[ENTRYPOINT] Instalando Google Cloud SDK..."
  echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" > /etc/apt/sources.list.d/google-cloud-sdk.list
  curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
  apt-get update -y && apt-get install -y --no-install-recommends google-cloud-cli && rm -rf /var/lib/apt/lists/*
}

configure_virtualenv_path() {
  VENV_PATH=$(find /home/prowler/.cache/pypoetry/virtualenvs -type d -name "prowler-*-py3.*" | head -n 1 || true)
  [ -n "$VENV_PATH" ] && export PATH="$VENV_PATH/bin:$PATH"
}

main() {
  install_base_deps

  case "$CLOUD_PROVIDER" in
    aws) install_aws_cli ;;
    azure) install_azure_cli ;;
    gcp) install_gcloud ;;
    *) echo "[ENTRYPOINT] ❌ Provedor inválido: $CLOUD_PROVIDER"; exit 1 ;;
  esac

  configure_virtualenv_path
  echo "[ENTRYPOINT] ✅ Ambiente preparado. Executando runner..."
  exec /usr/local/bin/run-multicloudassessment.sh
}

main "$@"

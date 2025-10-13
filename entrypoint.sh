#!/usr/bin/env bash
set -euo pipefail
echo "[ENTRYPOINT] Iniciando container em $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

install_base_deps() {
  echo "[ENTRYPOINT] Instalando dependências básicas..."
  apt-get update -y && \
  apt-get install -y --no-install-recommends jq curl unzip bash wget ca-certificates gnupg lsb-release apt-transport-https dos2unix && \
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
  echo "[ENTRYPOINT] Instalando Google Cloud CLI..."
  echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
  curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
  apt-get update -y && apt-get install -y --no-install-recommends google-cloud-cli && rm -rf /var/lib/apt/lists/*
}

configure_virtualenv_path() {
  VENV_PATH=$(find /home/prowler/.cache/pypoetry/virtualenvs -type d -name "prowler-*-py3.*" | head -n 1 || true)
  [ -n "$VENV_PATH" ] && export PATH="$VENV_PATH/bin:$PATH"
}

main() {
  install_base_deps

  case "${CLOUD_PROVIDER,,}" in
    aws) install_aws_cli ;;
    azure) install_azure_cli ;;
    gcp) install_gcloud ;;
    *) echo "[ENTRYPOINT] Cloud provider não especificado ou inválido."; exit 1 ;;
  esac

  configure_virtualenv_path
  echo "[ENTRYPOINT] Executando runner..."
  exec /usr/local/bin/run-multicloudassessment.sh
}

main "$@"


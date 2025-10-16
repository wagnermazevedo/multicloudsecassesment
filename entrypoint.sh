#!/usr/bin/env bash
set -euo pipefail

echo "[ENTRYPOINT] 🔹 Inicializando container em $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# ==============================
# Detectar provider e variáveis obrigatórias
# ==============================
required_vars=("CLIENT_NAME" "CLOUD_PROVIDER" "ACCOUNT_ID")
for var in "${required_vars[@]}"; do
  if [ -z "${!var:-}" ]; then
    echo "[ENTRYPOINT] ❌ Variável obrigatória '${var}' não definida. Abortando."
    exit 1
  fi
done

CLOUD_PROVIDER=$(echo "$CLOUD_PROVIDER" | tr '[:upper:]' '[:lower:]')

echo "[ENTRYPOINT] 🌐 Variáveis de ambiente recebidas:"
echo "  CLIENT_NAME=$CLIENT_NAME"
echo "  CLOUD_PROVIDER=$CLOUD_PROVIDER"
echo "  ACCOUNT_ID=$ACCOUNT_ID"
echo "  S3_BUCKET=${S3_BUCKET:-multicloud-assessments}"

# ==============================
# Funções utilitárias
# ==============================

install_base_deps() {
  echo "[ENTRYPOINT] ⚙️ Instalando dependências básicas..."
  apt-get update -y && \
  apt-get install -y --no-install-recommends jq curl unzip bash wget ca-certificates gnupg lsb-release apt-transport-https dos2unix uuid-runtime && \
  rm -rf /var/lib/apt/lists/*
}

install_aws_cli() {
  if ! command -v aws &>/dev/null; then
    echo "[ENTRYPOINT] 📦 Instalando AWS CLI (requerido para backend SSM)..."
    curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip && ./aws/install && rm -rf awscliv2.zip ./aws
    if command -v aws &>/dev/null; then
      echo "[ENTRYPOINT] ✅ AWS CLI instalada com sucesso: $(aws --version 2>&1)"
    else
      echo "[ENTRYPOINT] ❌ Falha ao instalar AWS CLI. Abortando."
      exit 1
    fi
  else
    echo "[ENTRYPOINT] ✅ AWS CLI já instalada: $(aws --version 2>&1)"
  fi
}

install_azure_cli() {
  if ! command -v az &>/dev/null; then
    echo "[ENTRYPOINT] 📦 Instalando Azure CLI..."
    curl -sL https://aka.ms/InstallAzureCLIDeb | bash
  else
    echo "[ENTRYPOINT] ✅ Azure CLI já instalada: $(az version 2>/dev/null | head -n 1 || echo 'detected')"
  fi
}

install_gcloud() {
  if ! command -v gcloud &>/dev/null; then
    echo "[ENTRYPOINT] 📦 Instalando Google Cloud SDK..."
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
      > /etc/apt/sources.list.d/google-cloud-sdk.list
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
    apt-get update -y && apt-get install -y --no-install-recommends google-cloud-cli && rm -rf /var/lib/apt/lists/*
    echo "[ENTRYPOINT] ✅ Google Cloud SDK instalado: $(gcloud version | head -n 1)"
  else
    echo "[ENTRYPOINT] ✅ Google Cloud SDK já instalado: $(gcloud version | head -n 1)"
  fi
}

configure_virtualenv_path() {
  local VENV_PATH
  VENV_PATH=$(find /home/prowler/.cache/pypoetry/virtualenvs -type d -name "prowler-*-py3.*" | head -n 1 || true)
  if [ -n "$VENV_PATH" ]; then
    export PATH="$VENV_PATH/bin:$PATH"
    echo "[ENTRYPOINT] 🧠 Ambiente virtual detectado: $VENV_PATH"
  else
    echo "[ENTRYPOINT] ⚠️ Nenhum virtualenv detectado, usando PATH padrão."
  fi
}

# ==============================
# Função principal
# ==============================
main() {
  install_base_deps
  install_aws_cli   # AWS CLI é obrigatória para todas as clouds (SSM backend)

  # Dependências específicas por cloud (além da AWS CLI)
  case "$CLOUD_PROVIDER" in
    aws)
      echo "[ENTRYPOINT] 🌩️ Ambiente AWS selecionado — apenas AWS CLI necessária."
      ;;
    azure)
      install_azure_cli
      ;;
    gcp)
      install_gcloud
      ;;
    *)
      echo "[ENTRYPOINT] ❌ Provedor inválido: $CLOUD_PROVIDER"
      exit 1
      ;;
  esac

  configure_virtualenv_path

  echo "[ENTRYPOINT] ✅ Ambiente preparado. Executando wrapper e runner..."
  if [ -x /usr/local/bin/run-multicloudassessment.sh ]; then
    chmod +x /usr/local/bin/run-multicloudassessment.sh
    exec /usr/local/bin/run-multicloud-wrapper.sh "$CLIENT_NAME" "$CLOUD_PROVIDER" "$ACCOUNT_ID" || {
      echo "[ENTRYPOINT] ❌ Falha ao executar runner."
      exit 1
    }
  else
    echo "[ENTRYPOINT] ❌ Script runner não encontrado em /usr/local/bin/run-multicloudassessment.sh"
    ls -la /usr/local/bin
    exit 1
  fi

  echo "[ENTRYPOINT] 🏁 Execução concluída com sucesso em $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}

main "$@"

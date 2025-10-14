#!/bin/bash
set -euo pipefail
echo "[RUNNER] 🧭 Iniciando execução do Multicloud Assessment Runner"

# ==============================
# 1️⃣ Variáveis básicas
# ==============================
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="/tmp/output-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# ==============================
# 2️⃣ Funções auxiliares
# ==============================

# Obtém valor de um parâmetro SSM com decodificação segura
get_param() {
  local name="$1"
  aws ssm get-parameter --name "$name" --with-decryption --output json 2>/dev/null \
    | jq -r '.Parameter.Value // empty'
}

# Busca credenciais no Parameter Store
fetch_credentials() {
  local path="/clients/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/credentials/access"
  echo "[RUNNER] 🔹 Buscando credenciais em $path"
  get_param "$path"
}

# Decodifica Base64 de forma segura
decode_base64_safe() {
  local data="$1"
  echo "$data" | tr -d '\r' | base64 --decode 2>/dev/null || {
    echo "[ERRO] ❌ Falha ao decodificar Base64. Conteúdo inválido no Parameter Store."
    exit 1
  }
}

# Autenticação multi-cloud
authenticate() {
  local creds
  creds=$(fetch_credentials)

  if [ -z "$creds" ]; then
    echo "[RUNNER] ⚠️ Nenhum parâmetro encontrado no SSM. Solicitando credenciais manualmente..."
  fi

  case "$CLOUD_PROVIDER" in
    aws)
      if [ -z "$creds" ]; then
        read -rp "AWS_ACCESS_KEY_ID: " AWS_ACCESS_KEY_ID
        read -rp "AWS_SECRET_ACCESS_KEY: " AWS_SECRET_ACCESS_KEY
        read -rp "AWS_SESSION_TOKEN (opcional): " AWS_SESSION_TOKEN || true
      else
        decode_base64_safe "$creds" > /tmp/aws_creds.json
        export AWS_ACCESS_KEY_ID=$(jq -r '.AWS_ACCESS_KEY_ID' /tmp/aws_creds.json)
        export AWS_SECRET_ACCESS_KEY=$(jq -r '.AWS_SECRET_ACCESS_KEY' /tmp/aws_creds.json)
        export AWS_SESSION_TOKEN=$(jq -r '.AWS_SESSION_TOKEN // empty' /tmp/aws_creds.json)
        export AWS_DEFAULT_REGION=$(jq -r '.AWS_DEFAULT_REGION // "us-east-1"' /tmp/aws_creds.json)
      fi

      echo "[RUNNER] ✅ AWS credenciais carregadas para conta ${ACCOUNT_ID}"
      aws sts get-caller-identity >/dev/null 2>&1 || {
        echo "[ERRO] Falha ao validar credenciais AWS."
        exit 1
      }
      ;;
    azure)
      if [ -z "$creds" ]; then
        read -rp "AZURE_TENANT_ID: " AZURE_TENANT_ID
        read -rp "AZURE_CLIENT_ID: " AZURE_CLIENT_ID
        read -rp "AZURE_CLIENT_SECRET: " AZURE_CLIENT_SECRET
        read -rp "AZURE_SUBSCRIPTION_ID: " AZURE_SUBSCRIPTION_ID
      else
        decode_base64_safe "$creds" > /etc/prowler/credentials/azure.env
        source /etc/prowler/credentials/azure.env
      fi

      echo "[RUNNER] 🔐 Autenticando no Azure..."
      az login --service-principal \
        -u "$AZURE_CLIENT_ID" \
        -p "$AZURE_CLIENT_SECRET" \
        --tenant "$AZURE_TENANT_ID" --output none || {
          echo "[ERRO] Falha ao autenticar no Azure CLI."
          exit 1
        }
      ;;
    gcp)
      mkdir -p /root/.config/gcloud
      if [ -z "$creds" ]; then
        read -rp "Caminho do arquivo JSON da Service Account: " SA_PATH
        cp "$SA_PATH" /root/.config/gcloud/application_default_credentials.json
      else
        decode_base64_safe "$creds" > /root/.config/gcloud/application_default_credentials.json
      fi

      echo "[RUNNER] 🔐 Ativando conta de serviço GCP..."
      gcloud auth activate-service-account \
        --key-file=/root/.config/gcloud/application_default_credentials.json >/dev/null 2>&1 || {
          echo "[ERRO] Falha ao ativar service account GCP."
          exit 1
        }
      ;;
    *)
      echo "[ERRO] ❌ Provedor de nuvem desconhecido: $CLOUD_PROVIDER"
      exit 1
      ;;
  esac
}

# Executa o Prowler
run_scan() {
  local output_file="${OUTPUT_DIR}/${CLOUD_PROVIDER}_${ACCOUNT_ID}_${TIMESTAMP}.json"
  echo "[RUNNER] ▶️ Executando Prowler (${CLOUD_PROVIDER})..."

  case "$CLOUD_PROVIDER" in
    aws)
      prowler aws --account-id "$ACCOUNT_ID" -M json-asff -o "$output_file" || true
      ;;
    azure)
      prowler azure -M json -o "$output_file" || true
      ;;
    gcp)
      prowler gcp --project-ids "$ACCOUNT_ID" -M json -o "$output_file" || true
      ;;
  esac

  if [ -f "$output_file" ]; then
    echo "[RUNNER] 📄 Relatório gerado: $output_file"
  else
    echo "[ERRO] ⚠️ Nenhum arquivo de saída gerado para ${CLOUD_PROVIDER}_${ACCOUNT_ID}"
  fi
}

# Upload dos resultados ao S3
upload_to_s3() {
  if [ "${CLOUD_PROVIDER}" != "aws" ]; then
    echo "[RUNNER] 🌐 Upload S3 é aplicável apenas para AWS. Pulando etapa."
    return
  fi

  local s3_prefix="${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}"
  echo "[RUNNER] 📤 Enviando resultados para s3://${S3_BUCKET}/${s3_prefix}/"
  aws s3 cp "$OUTPUT_DIR" "s3://${S3_BUCKET}/${s3_prefix}/" --recursive --region "${AWS_DEFAULT_REGION:-us-east-1}" || {
    echo "[ERRO] Falha no upload para S3."
    exit 1
  }
  echo "[RUNNER] ✅ Upload concluído!"
}

# ==============================
# 3️⃣ Execução principal
# ==============================
authenticate
run_scan
upload_to_s3

echo "[RUNNER] ✅ Scan finalizado com sucesso."
echo "[RUNNER] Resultados disponíveis em: s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}/"


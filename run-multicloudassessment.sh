#!/bin/bash
set -euo pipefail
echo "[RUNNER] 🧭 Iniciando execução do Multicloud Assessment Runner"

# ==============================
# Variáveis básicas
# ==============================
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="/tmp/output-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# ==============================
# Funções auxiliares
# ==============================
get_param() {
  aws ssm get-parameter --name "$1" --with-decryption --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

fetch_credentials() {
  local path="/clients/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/credentials/access"
  echo "[RUNNER] 🔹 Buscando credenciais em $path"
  get_param "$path"
}

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
        echo "$creds" | base64 -d > /tmp/aws_creds.json
        export AWS_ACCESS_KEY_ID=$(jq -r '.AWS_ACCESS_KEY_ID' /tmp/aws_creds.json)
        export AWS_SECRET_ACCESS_KEY=$(jq -r '.AWS_SECRET_ACCESS_KEY' /tmp/aws_creds.json)
        export AWS_SESSION_TOKEN=$(jq -r '.AWS_SESSION_TOKEN' /tmp/aws_creds.json)
      fi
      ;;
    azure)
      if [ -z "$creds" ]; then
        read -rp "AZURE_TENANT_ID: " AZURE_TENANT_ID
        read -rp "AZURE_CLIENT_ID: " AZURE_CLIENT_ID
        read -rp "AZURE_CLIENT_SECRET: " AZURE_CLIENT_SECRET
      else
        echo "$creds" | base64 -d > /etc/prowler/credentials/azure.env
        source /etc/prowler/credentials/azure.env
      fi
      az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null
      ;;
    gcp)
      if [ -z "$creds" ]; then
        read -rp "Caminho do arquivo JSON da Service Account: " SA_PATH
        cp "$SA_PATH" /root/.config/gcloud/application_default_credentials.json
      else
        echo "$creds" | base64 -d > /root/.config/gcloud/application_default_credentials.json
      fi
      ;;
  esac
}

run_scan() {
  local output_file="${OUTPUT_DIR}/${CLOUD_PROVIDER}_${ACCOUNT_ID}_${TIMESTAMP}.json"
  echo "[RUNNER] ▶️ Executando Prowler (${CLOUD_PROVIDER})..."

  case "$CLOUD_PROVIDER" in
    aws)
      prowler aws --account-id "$ACCOUNT_ID" -M json-asff -o "$output_file"
      ;;
    azure)
      prowler azure -M json -o "$output_file"
      ;;
    gcp)
      prowler gcp --project-ids "$ACCOUNT_ID" -M json -o "$output_file"
      ;;
  esac

  echo "[RUNNER] Arquivo gerado: $output_file"
}

upload_to_s3() {
  local s3_prefix="${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}"
  echo "[RUNNER] 📤 Enviando resultados para s3://${S3_BUCKET}/${s3_prefix}/"
  aws s3 cp "$OUTPUT_DIR" "s3://${S3_BUCKET}/${s3_prefix}/" --recursive --region "$AWS_REGION"
  echo "[RUNNER] ✅ Upload concluído!"
}

# ==============================
# Execução principal
# ==============================
authenticate
run_scan
upload_to_s3

echo "[RUNNER] ✅ Scan finalizado com sucesso."
echo "[RUNNER] Resultados disponíveis em: s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}/"

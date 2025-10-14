#!/bin/bash
set -euo pipefail
echo "[RUNNER] 🧭 Iniciando execução do Multicloud Assessment Runner"

# ==============================
# VARIÁVEIS BÁSICAS
# ==============================
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="/tmp/output-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# ==============================
# FUNÇÕES AUXILIARES
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

  # Se o parâmetro não for encontrado, solicita manualmente
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
        # Verifica se o conteúdo é Base64 válido
        if echo "$creds" | base64 --decode &>/dev/null; then
          echo "$creds" | base64 --decode > /tmp/aws_creds.json
        else
          echo "$creds" > /tmp/aws_creds.json
        fi

        export AWS_ACCESS_KEY_ID=$(jq -r '.AWS_ACCESS_KEY_ID' /tmp/aws_creds.json)
        export AWS_SECRET_ACCESS_KEY=$(jq -r '.AWS_SECRET_ACCESS_KEY' /tmp/aws_creds.json)
        export AWS_SESSION_TOKEN=$(jq -r '.AWS_SESSION_TOKEN // empty' /tmp/aws_creds.json)
      fi
      echo "[RUNNER] ✅ Autenticação AWS configurada."
      ;;
    azure)
      if [ -z "$creds" ]; then
        read -rp "AZURE_TENANT_ID: " AZURE_TENANT_ID
        read -rp "AZURE_CLIENT_ID: " AZURE_CLIENT_ID
        read -rp "AZURE_CLIENT_SECRET: " AZURE_CLIENT_SECRET
      else
        if echo "$creds" | base64 --decode &>/dev/null; then
          echo "$creds" | base64 --decode > /etc/prowler/credentials/azure.env
        else
          echo "$creds" > /etc/prowler/credentials/azure.env
        fi
        source /etc/prowler/credentials/azure.env
      fi
      az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null
      echo "[RUNNER] ✅ Autenticação Azure configurada."
      ;;
    gcp)
      mkdir -p /root/.config/gcloud
      if [ -z "$creds" ]; then
        read -rp "Caminho do arquivo JSON da Service Account: " SA_PATH
        cp "$SA_PATH" /root/.config/gcloud/application_default_credentials.json
      else
        if echo "$creds" | base64 --decode &>/dev/null; then
          echo "$creds" | base64 --decode > /root/.config/gcloud/application_default_credentials.json
        else
          echo "$creds" > /root/.config/gcloud/application_default_credentials.json
        fi
      fi
      gcloud auth activate-service-account --key-file=/root/.config/gcloud/application_default_credentials.json >/dev/null 2>&1 || true
      echo "[RUNNER] ✅ Autenticação GCP configurada."
      ;;
    *)
      echo "[ERRO] ❌ Provedor de nuvem desconhecido: $CLOUD_PROVIDER"
      exit 1
      ;;
  esac
}

# ==============================
# EXECUÇÃO DO SCAN
# ==============================
run_scan() {
  local output_file="${OUTPUT_DIR}/${CLOUD_PROVIDER}_${ACCOUNT_ID}_${TIMESTAMP}.json"
  echo "[RUNNER] ▶️ Executando Prowler para ${CLOUD_PROVIDER} (${ACCOUNT_ID})..."

  case "$CLOUD_PROVIDER" in
    aws)
      echo "[RUNNER] 🟢 Executando varredura AWS..."
      prowler aws \
        --provider aws \
        -M json-asff \
        --output-filename "$(basename "$output_file")" \
        --output-directory "$OUTPUT_DIR" \
        || echo "[WARN] Falha parcial no scan AWS ($ACCOUNT_ID)"
      ;;
    azure)
      echo "[RUNNER] 🟣 Executando varredura Azure..."
      prowler azure \
        --subscription-ids "$ACCOUNT_ID" \
        -M json \
        --output-filename "$(basename "$output_file")" \
        --output-directory "$OUTPUT_DIR" \
        || echo "[WARN] Falha parcial no scan Azure ($ACCOUNT_ID)"
      ;;
    gcp)
      echo "[RUNNER] 🔵 Executando varredura GCP..."
      prowler gcp \
        --project-ids "$ACCOUNT_ID" \
        -M json \
        --output-filename "$(basename "$output_file")" \
        --output-directory "$OUTPUT_DIR" \
        || echo "[WARN] Falha parcial no scan GCP ($ACCOUNT_ID)"
      ;;
    *)
      echo "[ERRO] ❌ Provedor não suportado: $CLOUD_PROVIDER"
      exit 1
      ;;
  esac

  if [ -f "$output_file" ]; then
    echo "[RUNNER] 📄 Relatório gerado: $output_file"
  else
    echo "[ERRO] ⚠️ Nenhum relatório foi gerado para ${CLOUD_PROVIDER}_${ACCOUNT_ID}"
  fi
}

# ==============================
# UPLOAD PARA S3
# ==============================
upload_to_s3() {
  local s3_prefix="${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}"
  echo "[RUNNER] 📤 Enviando resultados para s3://${S3_BUCKET}/${s3_prefix}/"
  aws s3 cp "$OUTPUT_DIR" "s3://${S3_BUCKET}/${s3_prefix}/" --recursive --region "$AWS_REGION"
  echo "[RUNNER] ✅ Upload concluído!"
}

# ==============================
# EXECUÇÃO PRINCIPAL
# ==============================
authenticate
run_scan
upload_to_s3

echo "[RUNNER] ✅ Scan finalizado com sucesso."
echo "[RUNNER] Resultados disponíveis em: s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}/"


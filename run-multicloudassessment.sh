#!/bin/bash
set -euo pipefail

###### Version 3.6 - Production-Ready with Detailed Logging
SESSION_ID=$(uuidgen)
START_TIME=$(date +%s)
LOG_PREFIX="[RUNNER:$SESSION_ID]"

log() {
  local level="$1"; shift
  local msg="$*"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "${LOG_PREFIX} ${timestamp} [${level}] ${msg}"
}

log INFO "🧭 Iniciando execução do Multicloud Assessment Runner v3.6"

# ==============================
# VARIÁVEIS BÁSICAS
# ==============================
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="/tmp/output-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
log INFO "📁 Diretório de saída: ${OUTPUT_DIR}"

# ==============================
# FUNÇÕES AUXILIARES
# ==============================
get_param() {
  local param_name="$1"
  aws ssm get-parameter --name "$param_name" --with-decryption --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

fetch_credentials() {
  local path="/clients/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/credentials/access"
  log INFO "🔍 Buscando credenciais em ${path}"
  get_param "$path"
}

# ==============================
# AUTENTICAÇÃO MULTICLOUD
# ==============================
authenticate() {
  local creds start_auth end_auth duration
  start_auth=$(date +%s)
  creds=$(fetch_credentials)

  if [ -z "$creds" ]; then
    log WARN "⚠️ Nenhum parâmetro encontrado no SSM. Solicitando credenciais manualmente..."
  fi

  case "$CLOUD_PROVIDER" in
    aws)
      if [ -z "$creds" ]; then
        read -rp "AWS_ACCESS_KEY_ID: " AWS_ACCESS_KEY_ID
        read -rp "AWS_SECRET_ACCESS_KEY: " AWS_SECRET_ACCESS_KEY
        read -rp "AWS_SESSION_TOKEN (opcional): " AWS_SESSION_TOKEN || true
      else
        # Verifica se é base64 válido
        if echo "$creds" | base64 --decode &>/dev/null; then
          echo "$creds" | base64 --decode > /tmp/aws_creds.json
        else
          echo "$creds" > /tmp/aws_creds.json
        fi
        # Valida JSON
        if ! jq empty /tmp/aws_creds.json 2>/dev/null; then
          log ERROR "❌ Credenciais AWS inválidas (JSON corrompido no SSM)."
          exit 1
        fi
        export AWS_ACCESS_KEY_ID=$(jq -r '.AWS_ACCESS_KEY_ID' /tmp/aws_creds.json)
        export AWS_SECRET_ACCESS_KEY=$(jq -r '.AWS_SECRET_ACCESS_KEY' /tmp/aws_creds.json)
        export AWS_SESSION_TOKEN=$(jq -r '.AWS_SESSION_TOKEN // empty' /tmp/aws_creds.json)
      fi
      aws sts get-caller-identity >/dev/null 2>&1 \
        && log INFO "✅ Autenticação AWS bem-sucedida" \
        || log ERROR "❌ Falha na autenticação AWS"
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
      az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1 \
        && log INFO "✅ Autenticação Azure bem-sucedida" \
        || log ERROR "❌ Falha na autenticação Azure"
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
      gcloud auth activate-service-account --key-file=/root/.config/gcloud/application_default_credentials.json >/dev/null 2>&1 \
        && log INFO "✅ Autenticação GCP bem-sucedida" \
        || log ERROR "❌ Falha na autenticação GCP"
      ;;

    *)
      log ERROR "❌ Provedor de nuvem desconhecido: ${CLOUD_PROVIDER}"
      exit 1
      ;;
  esac

  end_auth=$(date +%s)
  duration=$((end_auth - start_auth))
  log INFO "⏱️ Duração da autenticação (${CLOUD_PROVIDER}): ${duration}s"
}

# ==============================
# EXECUÇÃO DO SCAN
# ==============================
run_scan() {
  local output_file="${OUTPUT_DIR}/${CLOUD_PROVIDER}_${ACCOUNT_ID}_${TIMESTAMP}.json"
  log INFO "▶️ Executando Prowler (${CLOUD_PROVIDER}) para ${ACCOUNT_ID}"
  local start_scan=$(date +%s)

  case "$CLOUD_PROVIDER" in
    aws)
      log INFO "🟢 Iniciando varredura AWS com provider unificado..."
      prowler aws \
        --provider aws \
        -M json-asff \
        --output-filename "$(basename "$output_file")" \
        --output-directory "$OUTPUT_DIR" \
        --compliance aws_foundational_security_best_practices_aws \
        && log INFO "✅ Scan AWS concluído" \
        || log WARN "⚠️ Falha parcial no scan AWS ($ACCOUNT_ID)"
      ;;
    azure)
      log INFO "🟣 Iniciando varredura Azure..."
      prowler azure \
        --subscription-ids "$ACCOUNT_ID" \
        -M json \
        --output-filename "$(basename "$output_file")" \
        --output-directory "$OUTPUT_DIR" \
        --compliance cis_2.0_azure \
        && log INFO "✅ Scan Azure concluído" \
        || log WARN "⚠️ Falha parcial no scan Azure ($ACCOUNT_ID)"
      ;;
    gcp)
      log INFO "🔵 Iniciando varredura GCP..."
      prowler gcp \
        --project-ids "$ACCOUNT_ID" \
        -M json \
        --output-filename "$(basename "$output_file")" \
        --output-directory "$OUTPUT_DIR" \
        --compliance cis_2.0_gcp \
        && log INFO "✅ Scan GCP concluído" \
        || log WARN "⚠️ Falha parcial no scan GCP ($ACCOUNT_ID)"
      ;;
    *)
      log ERROR "❌ Provedor não suportado: $CLOUD_PROVIDER"
      exit 1
      ;;
  esac

  if [ -f "$output_file" ]; then
    log INFO "📄 Relatório gerado: $output_file"
  else
    log ERROR "⚠️ Nenhum relatório foi gerado para ${CLOUD_PROVIDER}_${ACCOUNT_ID}"
  fi

  local end_scan=$(date +%s)
  log INFO "⏱️ Duração do scan: $((end_scan - start_scan))s"
}

# ==============================
# UPLOAD PARA S3
# ==============================
upload_to_s3() {
  local s3_prefix="${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}"
  local start_upload=$(date +%s)
  log INFO "📤 Iniciando upload para s3://${S3_BUCKET}/${s3_prefix}/"

  aws s3 cp "$OUTPUT_DIR" "s3://${S3_BUCKET}/${s3_prefix}/" --recursive --region "$AWS_REGION" \
    && log INFO "✅ Upload concluído para ${CLOUD_PROVIDER}/${ACCOUNT_ID}" \
    || log ERROR "❌ Falha no upload para S3 (${CLOUD_PROVIDER}/${ACCOUNT_ID})"

  local end_upload=$(date +%s)
  log INFO "⏱️ Duração do upload: $((end_upload - start_upload))s"
}

# ==============================
# EXECUÇÃO PRINCIPAL
# ==============================
authenticate
run_scan
upload_to_s3

END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))
log INFO "🏁 Execução finalizada com sucesso em ${TOTAL_DURATION}s"
log INFO "📊 Resultados disponíveis em: s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}/"


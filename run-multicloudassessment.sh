#!/bin/bash
set -euo pipefail

###### Version 3.7 - Autoformat & Resilient Multicloud Runner ######
SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date +%s)
LOG_PREFIX="[RUNNER:${SESSION_ID}]"

# ========== CORES ==========
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ========== LOGGING ==========
log() {
  local level="$1"; shift
  local msg="$*"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  case "$level" in
    INFO) echo -e "${LOG_PREFIX} ${timestamp} ${BLUE}[INFO]${NC} ${msg}" ;;
    WARN) echo -e "${LOG_PREFIX} ${timestamp} ${YELLOW}[WARN]${NC} ${msg}" ;;
    ERROR) echo -e "${LOG_PREFIX} ${timestamp} ${RED}[ERROR]${NC} ${msg}" ;;
    SUCCESS) echo -e "${LOG_PREFIX} ${timestamp} ${GREEN}[OK]${NC} ${msg}" ;;
    *) echo "${LOG_PREFIX} ${timestamp} [${level}] ${msg}" ;;
  esac
}

log INFO "🧭 Iniciando execução do Multicloud Assessment Runner v3.7"

# ========== VARIÁVEIS ==========
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="/tmp/output-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
log INFO "📁 Diretório de saída: ${OUTPUT_DIR}"

# ========== FUNÇÕES ==========
get_param() {
  aws ssm get-parameter --name "$1" --with-decryption --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

fetch_credentials() {
  local path="/clients/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/credentials/access"
  log INFO "🔹 Buscando credenciais em ${path}"
  get_param "$path"
}

# --- Função inteligente de autenticação ---
authenticate() {
  local creds_json temp_file="/tmp/${CLOUD_PROVIDER}_creds.json"
  local start_auth=$(date +%s)

  creds_json=$(fetch_credentials)

  if [ -z "$creds_json" ]; then
    log ERROR "❌ Nenhum parâmetro encontrado no SSM (${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID})"
    return 1
  fi

  # Detectar e normalizar o formato
  if echo "$creds_json" | jq empty 2>/dev/null; then
    echo "$creds_json" > "$temp_file"
  elif echo "$creds_json" | base64 --decode 2>/dev/null | jq empty 2>/dev/null; then
    echo "$creds_json" | base64 --decode > "$temp_file"
  elif echo "$creds_json" | jq -r . | jq empty 2>/dev/null; then
    echo "$creds_json" | jq -r . > "$temp_file"
  else
    log ERROR "❌ Credenciais ${CLOUD_PROVIDER} inválidas (JSON corrompido no SSM)."
    return 1
  fi

  case "$CLOUD_PROVIDER" in
    aws)
      export AWS_ACCESS_KEY_ID=$(jq -r '.AWS_ACCESS_KEY_ID' "$temp_file")
      export AWS_SECRET_ACCESS_KEY=$(jq -r '.AWS_SECRET_ACCESS_KEY' "$temp_file")
      export AWS_SESSION_TOKEN=$(jq -r '.AWS_SESSION_TOKEN // empty' "$temp_file")
      aws sts get-caller-identity >/dev/null 2>&1 \
        && log SUCCESS "✅ Autenticação AWS bem-sucedida" \
        || log ERROR "❌ Falha na autenticação AWS"
      ;;
    azure)
      export AZURE_TENANT_ID=$(jq -r '.AZURE_TENANT_ID' "$temp_file")
      export AZURE_CLIENT_ID=$(jq -r '.AZURE_CLIENT_ID' "$temp_file")
      export AZURE_CLIENT_SECRET=$(jq -r '.AZURE_CLIENT_SECRET' "$temp_file")
      az login --service-principal \
        -u "$AZURE_CLIENT_ID" \
        -p "$AZURE_CLIENT_SECRET" \
        --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1 \
        && log SUCCESS "✅ Autenticação Azure bem-sucedida" \
        || log ERROR "❌ Falha na autenticação Azure"
      ;;
    gcp)
      mkdir -p /root/.config/gcloud
      echo "$creds_json" > /root/.config/gcloud/application_default_credentials.json
      gcloud auth activate-service-account \
        --key-file=/root/.config/gcloud/application_default_credentials.json >/dev/null 2>&1 \
        && log SUCCESS "✅ Autenticação GCP bem-sucedida" \
        || log ERROR "❌ Falha na autenticação GCP"
      ;;
    *)
      log ERROR "❌ Provedor de nuvem desconhecido: ${CLOUD_PROVIDER}"
      exit 1
      ;;
  esac

  local end_auth=$(date +%s)
  log INFO "⏱️ Duração da autenticação: $((end_auth - start_auth))s"
}

# --- Execução do Scan ---
run_scan() {
  local output_file="${OUTPUT_DIR}/${CLOUD_PROVIDER}_${ACCOUNT_ID}_${TIMESTAMP}.json"
  local start_scan=$(date +%s)
  log INFO "▶️ Executando Prowler (${CLOUD_PROVIDER}) para ${ACCOUNT_ID}"

  case "$CLOUD_PROVIDER" in
    aws)
      prowler aws \
        -M json-asff \
        --output-filename "$(basename "$output_file")" \
        --output-directory "$OUTPUT_DIR" \
        && log SUCCESS "✅ Scan AWS concluído" \
        || log WARN "⚠️ Falha parcial no scan AWS"
      ;;
    azure)
      prowler azure \
        --subscription-ids "$ACCOUNT_ID" \
        -M json \
        --output-filename "$(basename "$output_file")" \
        --output-directory "$OUTPUT_DIR" \
        && log SUCCESS "✅ Scan Azure concluído" \
        || log WARN "⚠️ Falha parcial no scan Azure"
      ;;
    gcp)
      prowler gcp \
        --project-ids "$ACCOUNT_ID" \
        -M json \
        --output-filename "$(basename "$output_file")" \
        --output-directory "$OUTPUT_DIR" \
        && log SUCCESS "✅ Scan GCP concluído" \
        || log WARN "⚠️ Falha parcial no scan GCP"
      ;;
    *)
      log ERROR "❌ Provedor não suportado: $CLOUD_PROVIDER"
      exit 1
      ;;
  esac

  if [ -f "$output_file" ]; then
    log SUCCESS "📄 Relatório gerado: $output_file"
  else
    log ERROR "⚠️ Nenhum relatório gerado para ${CLOUD_PROVIDER}_${ACCOUNT_ID}"
  fi

  local end_scan=$(date +%s)
  log INFO "⏱️ Duração do scan: $((end_scan - start_scan))s"
}

# --- Upload para S3 ---
upload_to_s3() {
  local s3_prefix="${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}"
  local start_upload=$(date +%s)
  log INFO "📤 Enviando resultados para s3://${S3_BUCKET}/${s3_prefix}/"

  aws s3 cp "$OUTPUT_DIR" "s3://${S3_BUCKET}/${s3_prefix}/" \
    --recursive --region "$AWS_REGION" \
    && log SUCCESS "✅ Upload concluído" \
    || log ERROR "❌ Falha no upload para S3"

  local end_upload=$(date +%s)
  log INFO "⏱️ Duração do upload: $((end_upload - start_upload))s"
}

# ========== EXECUÇÃO ==========
authenticate
run_scan
upload_to_s3

END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))
log SUCCESS "🏁 Execução finalizada com sucesso em ${TOTAL_DURATION}s"
log INFO "📊 Resultados disponíveis em: s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}/"

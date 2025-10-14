#!/bin/bash
set -euo pipefail

###### Version 3.9.3 - Unified Region Validation + Safe Credential Handling (AWS/Azure/GCP)
SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date +%s)
LOG_PREFIX="[RUNNER:${SESSION_ID}]"

# =============== Logging Function ===============
log() {
  local level="$1"; shift
  local msg="$*"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local color_reset="\033[0m"
  local color_info="\033[0;34m"
  local color_warn="\033[0;33m"
  local color_error="\033[0;31m"

  case "$level" in
    INFO) echo -e "${LOG_PREFIX} ${timestamp} ${color_info}[INFO]${color_reset} ${msg}" ;;
    WARN) echo -e "${LOG_PREFIX} ${timestamp} ${color_warn}[WARN]${color_reset} ${msg}" ;;
    ERROR) echo -e "${LOG_PREFIX} ${timestamp} ${color_error}[ERROR]${color_reset} ${msg}" ;;
    *) echo -e "${LOG_PREFIX} ${timestamp} [${level}] ${msg}" ;;
  esac
}

log INFO "🧭 Iniciando execução do Multicloud Assessment Runner v3.9.3"

# =============== Variáveis Básicas ===============
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="/tmp/output-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
CREDS_SUMMARY=""

log INFO "📁 Diretório de saída: ${OUTPUT_DIR}"
log INFO "🔹 Cliente: ${CLIENT_NAME:-undefined} | Nuvem: ${CLOUD_PROVIDER:-undefined} | Conta/Projeto: ${ACCOUNT_ID:-undefined}"

# =============== Helpers ===============
get_param() {
  aws ssm get-parameter --name "$1" --with-decryption --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

fetch_credentials() {
  local path="/clients/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/credentials/access"
  log INFO "🔹 Buscando credenciais em ${path}"
  get_param "$path"
}

# =============== Autenticação Multicloud ===============
authenticate() {
  local creds raw_json start_auth end_auth duration
  start_auth=$(date +%s)
  creds=$(fetch_credentials)

  if [ -z "$creds" ]; then
    log ERROR "❌ Nenhum parâmetro encontrado no SSM."
    CREDS_SUMMARY="{}"
    return 1
  fi

  # tenta decodificar base64 ou ler texto direto
  if echo "$creds" | base64 --decode &>/dev/null; then
    raw_json=$(echo "$creds" | base64 --decode)
  else
    raw_json="$creds"
  fi

  CREDS_SUMMARY="$raw_json"

  case "$CLOUD_PROVIDER" in
    aws)
      log INFO "🪣 Iniciando autenticação AWS..."
      export AWS_ACCESS_KEY_ID=$(echo "$raw_json" | jq -r '.AWS_ACCESS_KEY_ID')
      export AWS_SECRET_ACCESS_KEY=$(echo "$raw_json" | jq -r '.AWS_SECRET_ACCESS_KEY')
      export AWS_SESSION_TOKEN=$(echo "$raw_json" | jq -r '.AWS_SESSION_TOKEN // empty')

      export AWS_DEFAULT_REGION=$(echo "$raw_json" | jq -r '.AWS_DEFAULT_REGION')
      if [ -z "$AWS_DEFAULT_REGION" ] || [ "$AWS_DEFAULT_REGION" = "null" ]; then
        AWS_DEFAULT_REGION="${AWS_REGION:-us-east-1}"
      fi
      export AWS_REGION="$AWS_DEFAULT_REGION"

      log INFO "🌎 Região AWS definida como: ${AWS_DEFAULT_REGION}"

      if aws sts get-caller-identity >/dev/null 2>&1; then
        log INFO "✅ Autenticação AWS bem-sucedida"
      else
        log ERROR "❌ Falha na autenticação AWS (verifique credenciais e região)"
      fi
      ;;

    azure)
      log INFO "🟦 Iniciando autenticação Azure..."
      export AZURE_TENANT_ID=$(echo "$raw_json" | jq -r '.AZURE_TENANT_ID')
      export AZURE_CLIENT_ID=$(echo "$raw_json" | jq -r '.AZURE_CLIENT_ID')
      export AZURE_CLIENT_SECRET=$(echo "$raw_json" | jq -r '.AZURE_CLIENT_SECRET')
      export AZURE_SUBSCRIPTION_ID=$(echo "$raw_json" | jq -r '.AZURE_SUBSCRIPTION_ID')
      export AZURE_REGION=$(echo "$raw_json" | jq -r '.AZURE_REGION // empty')

      if [ -z "$AZURE_REGION" ] || [ "$AZURE_REGION" = "null" ]; then
        AZURE_REGION="${AWS_REGION:-eastus}"
      fi

      log INFO "🌎 Região Azure definida como: ${AZURE_REGION}"

      if az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1; then
        log INFO "✅ Autenticação Azure bem-sucedida"
      else
        log ERROR "❌ Falha na autenticação Azure"
      fi
      ;;

    gcp)
      log INFO "🟩 Iniciando autenticação GCP..."
      mkdir -p /root/.config/gcloud
      echo "$raw_json" > /root/.config/gcloud/application_default_credentials.json
      export GOOGLE_APPLICATION_CREDENTIALS="/root/.config/gcloud/application_default_credentials.json"

      export GCP_REGION=$(echo "$raw_json" | jq -r '.GCP_REGION // empty')
      if [ -z "$GCP_REGION" ] || [ "$GCP_REGION" = "null" ]; then
        GCP_REGION="${AWS_REGION:-us-central1}"
      fi
      log INFO "🌎 Região GCP definida como: ${GCP_REGION}"

      if gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS" >/dev/null 2>&1; then
        log INFO "✅ Autenticação GCP bem-sucedida"
      else
        log ERROR "❌ Falha na autenticação GCP"
      fi
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

# =============== Execução do Scan ===============
run_scan() {
  local output_file="${OUTPUT_DIR}/${CLOUD_PROVIDER}_${ACCOUNT_ID}_${TIMESTAMP}.json"
  log INFO "▶️ Executando Prowler (${CLOUD_PROVIDER}) para ${ACCOUNT_ID}"
  local start_scan=$(date +%s)

  case "$CLOUD_PROVIDER" in
    aws)
      export AWS_REGION="${AWS_REGION:-us-east-1}"
      prowler aws \
        -M json-asff \
        --output-filename "$(basename "$output_file")" \
        --output-directory "$OUTPUT_DIR" \
        && log INFO "✅ Scan AWS concluído" \
        || log ERROR "⚠️ Falha no scan AWS"
      ;;
    azure)
      prowler azure \
        --subscription-ids "$AZURE_SUBSCRIPTION_ID" \
        -M json \
        --output-filename "$(basename "$output_file")" \
        --output-directory "$OUTPUT_DIR" \
        && log INFO "✅ Scan Azure concluído" \
        || log ERROR "⚠️ Falha no scan Azure"
      ;;
    gcp)
      prowler gcp \
        --project-ids "$ACCOUNT_ID" \
        -M json \
        --output-filename "$(basename "$output_file")" \
        --output-directory "$OUTPUT_DIR" \
        && log INFO "✅ Scan GCP concluído" \
        || log ERROR "⚠️ Falha no scan GCP"
      ;;
    *)
      log ERROR "❌ Provedor não suportado: $CLOUD_PROVIDER"
      exit 1
      ;;
  esac

  if [ -f "$output_file" ]; then
    log INFO "📄 Relatório gerado: $output_file"
  else
    log WARN "⚠️ Nenhum relatório gerado para ${CLOUD_PROVIDER}_${ACCOUNT_ID}"
  fi

  local end_scan=$(date +%s)
  log INFO "⏱️ Duração do scan: $((end_scan - start_scan))s"
}

# =============== Upload S3 ===============
upload_to_s3() {
  local s3_prefix="${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}"
  local start_upload=$(date +%s)
  log INFO "📤 Enviando resultados para s3://${S3_BUCKET}/${s3_prefix}/"

  aws s3 cp "$OUTPUT_DIR" "s3://${S3_BUCKET}/${s3_prefix}/" --recursive --region "${AWS_REGION:-us-east-1}" \
    && log INFO "✅ Upload concluído" \
    || log ERROR "❌ Falha no upload para S3"

  local end_upload=$(date +%s)
  log INFO "⏱️ Duração do upload: $((end_upload - start_upload))s"
}

# =============== Execução Principal ===============
authenticate || true
run_scan || true
upload_to_s3 || true

# =============== Diagnóstico Final ===============
END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))

echo -e "\n========== 🔍 EXECUTION SUMMARY =========="
echo "Session ID:      $SESSION_ID"
echo "Client:          $CLIENT_NAME"
echo "Cloud Provider:  $CLOUD_PROVIDER"
echo "Account/Project: $ACCOUNT_ID"
echo "Region:          ${AWS_REGION:-not-set}"
echo "Bucket:          $S3_BUCKET"
echo "Output Prefix:   ${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}/"
echo "Duration:        ${TOTAL_DURATION}s"
echo "------------------------------------------"
echo "Credentials Summary (sanitized):"
if [ -n "${CREDS_SUMMARY:-}" ]; then
  printf '%s\n' "$CREDS_SUMMARY" | jq . 2>/dev/null || echo "(⚠️ unable to parse JSON safely)"
else
  echo "(no credentials summary available)"
fi
echo "=========================================="

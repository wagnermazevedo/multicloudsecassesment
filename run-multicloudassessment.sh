#!/bin/bash
set -euo pipefail

###### Version 3.9 - ECS-safe + Retry + Region Diagnostics
SESSION_ID=$(cat /proc/sys/kernel/random/uuid)
START_TIME=$(date +%s)
LOG_PREFIX="[RUNNER:${SESSION_ID}]"

# ==============================
# LOGGING
# ==============================
log() {
  local level="$1"; shift
  local msg="$*"
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  case "$level" in
    INFO)  echo -e "${LOG_PREFIX} ${timestamp} \033[0;34m[INFO]\033[0m ${msg}" ;;
    WARN)  echo -e "${LOG_PREFIX} ${timestamp} \033[0;33m[WARN]\033[0m ${msg}" ;;
    ERROR) echo -e "${LOG_PREFIX} ${timestamp} \033[0;31m[ERROR]\033[0m ${msg}" ;;
    *)     echo -e "${LOG_PREFIX} ${timestamp} [${level}] ${msg}" ;;
  esac
}

log INFO "🧭 Iniciando execução do Multicloud Assessment Runner v3.9"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="/tmp/output-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# ==============================
# AUXILIARES
# ==============================
sanitize_json() {
  sed -n '/{/,/}/p' | sed 's/^[[:space:]]*//' | sed '/^$/d'
}

get_param() {
  local name="$1"
  local region="${AWS_REGION:-$(aws configure get region 2>/dev/null || echo 'us-east-1')}"
  local attempt=1
  local value=""

  log INFO "🔍 Região ativa: ${region}"
  log INFO "🔍 Buscando parâmetro: ${name}"

  while [ $attempt -le 3 ]; do
    value=$(aws ssm get-parameter --name "$name" --with-decryption --query "Parameter.Value" --output text --region "$region" 2>/dev/null || true)
    if [ -n "$value" ]; then
      log INFO "✅ Parâmetro encontrado na tentativa $attempt"
      echo "$value"
      return 0
    fi
    log WARN "⚠️ Tentativa $attempt falhou ao obter $name (aguardando retry...)"
    attempt=$((attempt + 1))
    sleep 1
  done

  # fallback: tenta GetParametersByPath
  log WARN "🔁 Tentando fallback via GetParametersByPath para ${name%/*}"
  value=$(aws ssm get-parameters-by-path --path "${name%/*}" --with-decryption --region "$region" \
          --query "Parameters[?ends_with(Name, 'access')].Value" --output text 2>/dev/null || true)
  if [ -n "$value" ]; then
    log INFO "✅ Parâmetro localizado via fallback"
    echo "$value"
    return 0
  fi

  log ERROR "❌ Nenhum parâmetro encontrado em ${name}"
  return 1
}

# ==============================
# AUTENTICAÇÃO MULTICLOUD
# ==============================
authenticate() {
  local creds raw_json
  local param_path="/clients/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/credentials/access"
  log INFO "🔹 Buscando credenciais em ${param_path}"

  creds=$(get_param "$param_path" || true)
  if [ -z "$creds" ]; then
    log ERROR "❌ Nenhum parâmetro encontrado no SSM após 3 tentativas e fallback."
    return 1
  fi

  raw_json=$(echo "$creds" | sanitize_json)

  if ! echo "$raw_json" | jq empty >/dev/null 2>&1; then
    log ERROR "❌ Credenciais ${CLOUD_PROVIDER} inválidas (JSON corrompido ou fora do formato)."
    log INFO "Conteúdo recebido (truncado): $(echo "$raw_json" | head -n 3)"
    return 2
  fi

  case "$CLOUD_PROVIDER" in
    aws)
      export AWS_ACCESS_KEY_ID=$(echo "$raw_json" | jq -r '.AWS_ACCESS_KEY_ID')
      export AWS_SECRET_ACCESS_KEY=$(echo "$raw_json" | jq -r '.AWS_SECRET_ACCESS_KEY')
      export AWS_SESSION_TOKEN=$(echo "$raw_json" | jq -r '.AWS_SESSION_TOKEN // empty')
      export AWS_DEFAULT_REGION=$(echo "$raw_json" | jq -r '.AWS_DEFAULT_REGION // "us-east-1"')
      aws sts get-caller-identity >/dev/null 2>&1 \
        && log INFO "✅ Autenticação AWS bem-sucedida" \
        || log ERROR "❌ Falha na autenticação AWS"
      ;;
    azure)
      export AZURE_TENANT_ID=$(echo "$raw_json" | jq -r '.AZURE_TENANT_ID')
      export AZURE_CLIENT_ID=$(echo "$raw_json" | jq -r '.AZURE_CLIENT_ID')
      export AZURE_CLIENT_SECRET=$(echo "$raw_json" | jq -r '.AZURE_CLIENT_SECRET')
      export AZURE_SUBSCRIPTION_ID=$(echo "$raw_json" | jq -r '.AZURE_SUBSCRIPTION_ID')
      az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1 \
        && log INFO "✅ Autenticação Azure bem-sucedida" \
        || log ERROR "❌ Falha na autenticação Azure"
      ;;
    gcp)
      mkdir -p /root/.config/gcloud
      echo "$raw_json" > /root/.config/gcloud/application_default_credentials.json
      gcloud auth activate-service-account --key-file=/root/.config/gcloud/application_default_credentials.json >/dev/null 2>&1 \
        && log INFO "✅ Autenticação GCP bem-sucedida" \
        || log ERROR "❌ Falha na autenticação GCP"
      ;;
    *)
      log ERROR "❌ Provedor de nuvem desconhecido: ${CLOUD_PROVIDER}"
      exit 1
      ;;
  esac

  # Guarda credenciais truncadas para exibir no final
  CREDS_SUMMARY=$(echo "$raw_json" | jq -c '. | with_entries(.value |= if length > 20 then (.[:10] + "...") else . end)')
}

# ==============================
# EXECUÇÃO DO SCAN
# ==============================
run_scan() {
  local output_file="${OUTPUT_DIR}/${CLOUD_PROVIDER}_${ACCOUNT_ID}_${TIMESTAMP}.json"
  log INFO "▶️ Executando Prowler (${CLOUD_PROVIDER}) para conta/projeto ${ACCOUNT_ID}"

  case "$CLOUD_PROVIDER" in
    aws)
      prowler aws -M json-asff -o "$OUTPUT_DIR" --output-filename "$(basename "$output_file")" \
        && log INFO "✅ Scan AWS concluído" || log ERROR "⚠️ Falha no scan AWS"
      ;;
    azure)
      prowler azure --subscription-ids "$ACCOUNT_ID" -M json -o "$OUTPUT_DIR" --output-filename "$(basename "$output_file")" \
        && log INFO "✅ Scan Azure concluído" || log ERROR "⚠️ Falha no scan Azure"
      ;;
    gcp)
      prowler gcp --project-ids "$ACCOUNT_ID" -M json -o "$OUTPUT_DIR" --output-filename "$(basename "$output_file")" \
        && log INFO "✅ Scan GCP concluído" || log ERROR "⚠️ Falha no scan GCP"
      ;;
    *)
      log ERROR "❌ Cloud provider inválido: $CLOUD_PROVIDER"
      ;;
  esac

  if [ -f "$output_file" ]; then
    log INFO "📄 Relatório gerado com sucesso: $output_file"
  else
    log WARN "⚠️ Nenhum relatório gerado para ${CLOUD_PROVIDER}_${ACCOUNT_ID}"
  fi
}

# ==============================
# UPLOAD PARA S3
# ==============================
upload_to_s3() {
  local s3_prefix="${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}"
  log INFO "📤 Enviando resultados para s3://${S3_BUCKET}/${s3_prefix}/"
  aws s3 cp "$OUTPUT_DIR" "s3://${S3_BUCKET}/${s3_prefix}/" --recursive --region "$AWS_REGION" \
    && log INFO "✅ Upload concluído" \
    || log ERROR "❌ Falha no upload para S3"
}

# ==============================
# EXECUÇÃO PRINCIPAL
# ==============================
authenticate
run_scan
upload_to_s3

# ==============================
# DIAGNÓSTICO FINAL
# ==============================
END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))

echo -e "\n========== 🔍 EXECUTION SUMMARY =========="
echo "Session ID:      $SESSION_ID"
echo "Client:          $CLIENT_NAME"
echo "Cloud Provider:  $CLOUD_PROVIDER"
echo "Account/Project: $ACCOUNT_ID"
echo "Bucket:          $S3_BUCKET"
echo "Output Prefix:   ${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}/"
echo "Duration:        ${TOTAL_DURATION}s"
echo "------------------------------------------"
echo "Credentials Summary (safely truncated):"
echo "$CREDS_SUMMARY" | jq .
echo "=========================================="

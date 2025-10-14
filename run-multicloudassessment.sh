#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v3.9.4
# Executa varreduras AWS, Azure e GCP de forma unificada.
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner v3.9.4"

# === Variáveis obrigatórias ===
CLIENT_NAME="${CLIENT_NAME:-unknown}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-unknown}"
ACCOUNT_ID="${ACCOUNT_ID:-undefined}"
AWS_REGION="${AWS_REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-multicloud-assessments}"

echo "[RUNNER:$SESSION_ID] [INFO] 🔹 Cliente: $CLIENT_NAME | Nuvem: $CLOUD_PROVIDER | Conta/Projeto: $ACCOUNT_ID | Região: $AWS_REGION"

OUTPUT_DIR="/tmp/output-${SESSION_ID}"
mkdir -p "$OUTPUT_DIR"

# ===== Helper: mensagem padronizada =====
log() { echo "[RUNNER:$SESSION_ID] $(date -u +"%Y-%m-%dT%H:%M:%SZ") $1"; }

# ===== Autenticação e execução =====
authenticate() {
  case "$CLOUD_PROVIDER" in
    aws)
      log "[INFO] 🪣 Iniciando autenticação AWS..."
      creds_json=$(aws ssm get-parameter \
        --name "/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/access" \
        --with-decryption \
        --query "Parameter.Value" \
        --output text 2>/dev/null || true)

      if [[ -z "$creds_json" ]]; then
        log "[ERROR] ❌ Credenciais AWS ausentes no SSM."
        return 1
      fi

      # Corrige JSON corrompido (remove prefixos inválidos)
      if [[ "$creds_json" == PARAMETER* ]]; then
        creds_json="$(echo "$creds_json" | sed 's/^PARAMETER.*{/{/' )"
      fi

      if ! echo "$creds_json" | jq empty >/dev/null 2>&1; then
        log "[ERROR] ❌ Credenciais AWS inválidas (JSON corrompido no SSM)."
        echo "$creds_json" | head -n 3
        return 1
      fi

      export AWS_ACCESS_KEY_ID
      export AWS_SECRET_ACCESS_KEY
      export AWS_SESSION_TOKEN
      export AWS_DEFAULT_REGION="$AWS_REGION"

      AWS_ACCESS_KEY_ID=$(echo "$creds_json" | jq -r '.AWS_ACCESS_KEY_ID')
      AWS_SECRET_ACCESS_KEY=$(echo "$creds_json" | jq -r '.AWS_SECRET_ACCESS_KEY')
      AWS_SESSION_TOKEN=$(echo "$creds_json" | jq -r '.AWS_SESSION_TOKEN')

      log "[INFO] 🌎 Região AWS definida como: $AWS_REGION"
      log "[INFO] ✅ Autenticação AWS bem-sucedida"
      ;;
    
    azure)
      log "[INFO] ☁️ Iniciando autenticação Azure..."
      creds_json=$(aws ssm get-parameter \
        --name "/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials/access" \
        --with-decryption \
        --query "Parameter.Value" \
        --output text 2>/dev/null || true)

      if [[ -z "$creds_json" ]]; then
        log "[ERROR] ❌ Credenciais Azure ausentes no SSM."
        return 1
      fi

      if ! echo "$creds_json" | jq empty >/dev/null 2>&1; then
        log "[ERROR] ❌ JSON Azure inválido. Verifique formatação."
        return 1
      fi

      export AZURE_TENANT_ID=$(echo "$creds_json" | jq -r '.AZURE_TENANT_ID')
      export AZURE_CLIENT_ID=$(echo "$creds_json" | jq -r '.AZURE_CLIENT_ID')
      export AZURE_CLIENT_SECRET=$(echo "$creds_json" | jq -r '.AZURE_CLIENT_SECRET')
      export AZURE_SUBSCRIPTION_ID=$(echo "$creds_json" | jq -r '.AZURE_SUBSCRIPTION_ID')

      az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null
      az account set --subscription "$AZURE_SUBSCRIPTION_ID"

      log "[INFO] ✅ Autenticação Azure concluída"
      ;;
    
    gcp)
      log "[INFO] 🌍 Iniciando autenticação GCP..."
      creds_json=$(aws ssm get-parameter \
        --name "/clients/$CLIENT_NAME/gcp/$ACCOUNT_ID/credentials/access" \
        --with-decryption \
        --query "Parameter.Value" \
        --output text 2>/dev/null || true)

      if [[ -z "$creds_json" ]]; then
        log "[ERROR] ❌ Credenciais GCP ausentes no SSM."
        return 1
      fi

      echo "$creds_json" > /tmp/gcp_creds.json
      gcloud auth activate-service-account --key-file=/tmp/gcp_creds.json >/dev/null
      gcloud config set project "$ACCOUNT_ID"
      log "[INFO] ✅ Autenticação GCP concluída"
      ;;
    
    *)
      log "[ERROR] ❌ Provedor de nuvem não reconhecido: $CLOUD_PROVIDER"
      return 1
      ;;
  esac
}

# ===== Execução principal =====
if ! authenticate; then
  log "[ERROR] ⚠️ Falha na autenticação. Encerrando execução."
  exit 1
fi

SCAN_START=$(date +%s)
log "[INFO] ▶️ Executando Prowler ($CLOUD_PROVIDER) para $ACCOUNT_ID"

case "$CLOUD_PROVIDER" in
  aws)
    prowler aws -M json-asff --output-filename "prowler-aws.json" \
      --output-directory "$OUTPUT_DIR" || log "[ERROR] ⚠️ Falha no scan AWS"
    ;;
  azure)
    prowler azure -M json-asff --output-filename "prowler-azure.json" \
      --output-directory "$OUTPUT_DIR" || log "[ERROR] ⚠️ Falha no scan Azure"
    ;;
  gcp)
    prowler gcp -M json-asff --output-filename "prowler-gcp.json" \
      --output-directory "$OUTPUT_DIR" || log "[ERROR] ⚠️ Falha no scan GCP"
    ;;
esac

SCAN_END=$(date +%s)
DURATION=$((SCAN_END - SCAN_START))

log "[INFO] ⏱️ Duração do scan: ${DURATION}s"
log "[INFO] 📤 Enviando resultados para s3://$S3_BUCKET/$CLIENT_NAME/$CLOUD_PROVIDER/$ACCOUNT_ID/$(date -u +%Y%m%d-%H%M%S)/"
aws s3 cp "$OUTPUT_DIR" "s3://$S3_BUCKET/$CLIENT_NAME/$CLOUD_PROVIDER/$ACCOUNT_ID/$(date -u +%Y%m%d-%H%M%S)/" --recursive

log "[INFO] ✅ Upload concluído"
log "========== 🔍 EXECUTION SUMMARY =========="
log "Client: $CLIENT_NAME"
log "Cloud: $CLOUD_PROVIDER"
log "Account: $ACCOUNT_ID"
log "Region: $AWS_REGION"
log "Duration: ${DURATION}s"
log "=========================================="

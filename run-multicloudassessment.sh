#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v4.0.2
# Autor: Wagner Azevedo
# Descrição:
#   Suporte unificado para AWS, Azure e GCP
#   - Autodetecta formato JSON consolidado no SSM
#   - Log detalhado (debug) compatível com CloudWatch
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner v4.0.2"

# === Variáveis obrigatórias ===
CLIENT_NAME="${CLIENT_NAME:-unknown}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-unknown}"
ACCOUNT_ID="${ACCOUNT_ID:-undefined}"
AWS_REGION="${AWS_REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-multicloud-assessments}"

echo "[RUNNER:$SESSION_ID] [INFO] 🔹 Cliente: $CLIENT_NAME | Nuvem: $CLOUD_PROVIDER | Conta/Projeto: $ACCOUNT_ID | Região: $AWS_REGION"

OUTPUT_DIR="/tmp/output-${SESSION_ID}"
mkdir -p "$OUTPUT_DIR"

# === Helper de log ===
log() { echo "[RUNNER:$SESSION_ID] $(date -u +"%Y-%m-%dT%H:%M:%SZ") $1"; }

# ============================================================
# 🔐 Função de Autenticação (AWS, Azure, GCP)
# ============================================================
authenticate() {
  case "$CLOUD_PROVIDER" in
    aws)
      log "[INFO] 🪣 Iniciando autenticação AWS (detecção automática de JSON único)..."
      ACCESS_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/access"
      SECRET_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/secret"

      ACCESS_RAW=$(aws ssm get-parameter --with-decryption --name "$ACCESS_PATH" --query "Parameter.Value" --output text 2>&1 || true)
      SECRET_RAW=$(aws ssm get-parameter --with-decryption --name "$SECRET_PATH" --query "Parameter.Value" --output text 2>&1 || true)

      log "[DEBUG] 🧾 ACCESS_RAW (first 200 chars): ${ACCESS_RAW:0:200}"
      log "[DEBUG] 🧾 SECRET_RAW (first 80 chars): ${SECRET_RAW:0:80}"

      if echo "$ACCESS_RAW" | jq empty >/dev/null 2>&1; then
        log "[INFO] 📦 Detetado formato JSON consolidado em $ACCESS_PATH"
        AWS_ACCESS_KEY_ID=$(echo "$ACCESS_RAW" | jq -r '.AWS_ACCESS_KEY_ID')
        AWS_SECRET_ACCESS_KEY=$(echo "$ACCESS_RAW" | jq -r '.AWS_SECRET_ACCESS_KEY')
        AWS_SESSION_TOKEN=$(echo "$ACCESS_RAW" | jq -r '.AWS_SESSION_TOKEN')
      else
        AWS_ACCESS_KEY_ID="$ACCESS_RAW"
        AWS_SECRET_ACCESS_KEY="$SECRET_RAW"
        AWS_SESSION_TOKEN=""
      fi

      if [[ -z "$AWS_ACCESS_KEY_ID" || -z "$AWS_SECRET_ACCESS_KEY" ]]; then
        log "[ERROR] ❌ Credenciais AWS incompletas ou inválidas."
        return 1
      fi

      export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION="$AWS_REGION"
      log "[INFO] ✅ Credenciais AWS carregadas com sucesso"
      ;;

    azure)
      log "[INFO] ☁️ Iniciando autenticação Azure (detecção automática de JSON único)..."
      CREDS_PATH="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials/access"
      CREDS_RAW=$(aws ssm get-parameter --with-decryption --name "$CREDS_PATH" --query "Parameter.Value" --output text 2>&1 || true)

      log "[DEBUG] 🧾 CREDS_RAW (first 200 chars): ${CREDS_RAW:0:200}"

      if echo "$CREDS_RAW" | jq empty >/dev/null 2>&1; then
        log "[INFO] 📦 Detetado formato JSON consolidado em $CREDS_PATH"
        AZURE_TENANT_ID=$(echo "$CREDS_RAW" | jq -r '.AZURE_TENANT_ID')
        AZURE_CLIENT_ID=$(echo "$CREDS_RAW" | jq -r '.AZURE_CLIENT_ID')
        AZURE_CLIENT_SECRET=$(echo "$CREDS_RAW" | jq -r '.AZURE_CLIENT_SECRET')
        AZURE_SUBSCRIPTION_ID=$(echo "$CREDS_RAW" | jq -r '.AZURE_SUBSCRIPTION_ID')
      else
        log "[ERROR] ❌ Credenciais Azure devem estar em JSON consolidado."
        return 1
      fi

      if [[ -z "$AZURE_CLIENT_ID" || -z "$AZURE_CLIENT_SECRET" || -z "$AZURE_TENANT_ID" || -z "$AZURE_SUBSCRIPTION_ID" ]]; then
        log "[ERROR] ❌ Credenciais Azure incompletas."
        return 1
      fi

      export AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET AZURE_SUBSCRIPTION_ID

      log "[INFO] 🔑 Autenticando no Azure..."
      az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1 || {
        log "[ERROR] ❌ Falha ao autenticar no Azure."
        return 1
      }
      az account set --subscription "$AZURE_SUBSCRIPTION_ID" >/dev/null 2>&1 || {
        log "[ERROR] ❌ Falha ao definir a subscription Azure."
        return 1
      }
      log "[INFO] ✅ Autenticação Azure concluída"
      ;;

    gcp)
      log "[INFO] 🌍 Iniciando autenticação GCP (detecção automática de JSON único)..."
      CREDS_PATH="/clients/$CLIENT_NAME/gcp/$ACCOUNT_ID/credentials/access"
      CREDS_RAW=$(aws ssm get-parameter --with-decryption --name "$CREDS_PATH" --query "Parameter.Value" --output text 2>&1 || true)

      log "[DEBUG] 🧾 CREDS_RAW (first 200 chars): ${CREDS_RAW:0:200}"

      if echo "$CREDS_RAW" | jq empty >/dev/null 2>&1; then
        log "[INFO] 📦 Credenciais GCP JSON detectadas em $CREDS_PATH"
        echo "$CREDS_RAW" > /tmp/gcp_creds.json
      else
        log "[ERROR] ❌ Credenciais GCP inválidas. Esperado JSON Service Account."
        return 1
      fi

      export GOOGLE_APPLICATION_CREDENTIALS="/tmp/gcp_creds.json"
      gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS" >/dev/null 2>&1 || {
        log "[ERROR] ❌ Falha ao autenticar no GCP."
        return 1
      }
      gcloud config set project "$ACCOUNT_ID" >/dev/null 2>&1
      log "[INFO] ✅ Autenticação GCP concluída"
      ;;

    *)
      log "[ERROR] ❌ Provedor de nuvem não reconhecido: $CLOUD_PROVIDER"
      return 1
      ;;
  esac
}

# ============================================================
# 🚀 Execução principal
# ============================================================
if ! authenticate; then
  log "[ERROR] ⚠️ Falha na autenticação. Encerrando execução."
  exit 1
fi

SCAN_START=$(date +%s)
log "[INFO] ▶️ Executando Prowler para $CLOUD_PROVIDER ($ACCOUNT_ID)"

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

DEST="s3://$S3_BUCKET/$CLIENT_NAME/$CLOUD_PROVIDER/$ACCOUNT_ID/$(date -u +%Y%m%d-%H%M%S)/"

log "[INFO] ⏱️ Duração do scan: ${DURATION}s"
log "[INFO] 📤 Enviando resultados para $DEST"
aws s3 cp "$OUTPUT_DIR" "$DEST" --recursive || log "[WARN] Falha parcial no upload"

log "[INFO] ✅ Upload concluído"
log "========== 🔍 EXECUTION SUMMARY =========="
log "Session ID: $SESSION_ID"
log "Client:     $CLIENT_NAME"
log "Cloud:      $CLOUD_PROVIDER"
log "Account:    $ACCOUNT_ID"
log "Region:     $AWS_REGION"
log "Duration:   ${DURATION}s"
log "=========================================="

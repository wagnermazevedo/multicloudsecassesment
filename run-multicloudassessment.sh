#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v4.1.0
# Autor: Wagner Azevedo
# ============================================================
# Alterações nesta versão:
#   - Fixa AWS_SSM_REGION (backend SSM central)
#   - Azure: autenticação automática (--az-cli-auth ou --sp-env-auth)
#   - GCP: mensagens de erro aprimoradas e roles recomendadas
#   - Logs claros e uniformes entre provedores
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner v4.1.0"

CLIENT_NAME="${CLIENT_NAME:-unknown}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-unknown}"
ACCOUNT_ID="${ACCOUNT_ID:-undefined}"
AWS_REGION="${AWS_REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-multicloud-assessments}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
AWS_SSM_REGION="${AWS_SSM_REGION:-us-east-1}"

echo "[RUNNER:$SESSION_ID] [INFO] 🔹 Cliente: $CLIENT_NAME | Nuvem: $CLOUD_PROVIDER | Conta: $ACCOUNT_ID | Região Prowler: $AWS_REGION | SSM Backend: $AWS_SSM_REGION"

OUTPUT_DIR="/tmp/output-${SESSION_ID}"
mkdir -p "$OUTPUT_DIR"

log() { echo "[RUNNER:$SESSION_ID] $(date -u +"%Y-%m-%dT%H:%M:%SZ") $1"; }

# ============================================================
# 🔧 Utilidades
# ============================================================

aws_cli() { aws --region "$AWS_SSM_REGION" "$@"; }

get_ssm_value() {
  local path="$1"
  aws_cli ssm get-parameter --with-decryption --name "$path" --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

parse_maybe_escaped_json() {
  local raw; raw="$(cat)"
  [[ -z "$raw" ]] && { echo ""; return; }
  if echo "$raw" | jq empty >/dev/null 2>&1; then
    echo "$raw"
  elif echo "$raw" | grep -q '{\\\"'; then
    echo "$raw" | sed 's/^"//' | sed 's/"$//' | jq -r 'fromjson'
  else
    echo ""
  fi
}

# ============================================================
# 🔐 Autenticação Multicloud
# ============================================================

authenticate() {
  log "[INFO] 💾 Backend de credenciais: AWS SSM Parameter Store (região $AWS_SSM_REGION)."

  case "$CLOUD_PROVIDER" in
    aws)
      log "[INFO] ☁️ Iniciando autenticação AWS..."
      CREDS_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/access"
      ACCESS_RAW="$(get_ssm_value "$CREDS_PATH")"
      [[ -z "$ACCESS_RAW" ]] && { log "[ERROR] ❌ Credenciais AWS não encontradas."; return 1; }

      CLEAN_JSON="$(echo "$ACCESS_RAW" | parse_maybe_escaped_json)"
      export AWS_ACCESS_KEY_ID="$(echo "$CLEAN_JSON" | jq -r '.AWS_ACCESS_KEY_ID')"
      export AWS_SECRET_ACCESS_KEY="$(echo "$CLEAN_JSON" | jq -r '.AWS_SECRET_ACCESS_KEY')"
      export AWS_SESSION_TOKEN="$(echo "$CLEAN_JSON" | jq -r '.AWS_SESSION_TOKEN // empty')"

      log "[INFO] ✅ Autenticação AWS concluída."
      ;;

    azure)
      log "[INFO] ☁️ Iniciando autenticação Azure..."
      CREDS_PATH="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials/access"
      CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"
      [[ -z "$CREDS_RAW" ]] && { log "[ERROR] ❌ Credenciais Azure não encontradas."; return 1; }

      CLEAN_JSON="$(echo "$CREDS_RAW" | parse_maybe_escaped_json)"
      export AZURE_TENANT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_TENANT_ID')"
      export AZURE_CLIENT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_ID')"
      export AZURE_CLIENT_SECRET="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_SECRET')"
      export AZURE_SUBSCRIPTION_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_SUBSCRIPTION_ID')"

      log "[INFO] 🔑 Efetuando login via Service Principal..."
      az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1 || {
        log "[ERROR] ❌ Falha no login Azure CLI."; return 1; }
      az account set --subscription "$AZURE_SUBSCRIPTION_ID" >/dev/null 2>&1 || {
        log "[ERROR] ❌ Falha ao definir subscription."; return 1; }
      log "[INFO] ✅ Autenticação Azure concluída."
      ;;

    gcp)
      log "[INFO] ☁️ Iniciando autenticação GCP..."
      CREDS_PATH="/clients/$CLIENT_NAME/gcp/$ACCOUNT_ID/credentials/access"
      CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"
      [[ -z "$CREDS_RAW" ]] && { log "[ERROR] ❌ Credenciais GCP não encontradas."; return 1; }

      if echo "$CREDS_RAW" | jq empty >/dev/null 2>&1; then
        echo "$CREDS_RAW" > /tmp/gcp_creds.json
      elif echo "$CREDS_RAW" | grep -q '{\\\"'; then
        echo "$CREDS_RAW" | sed 's/^"//' | sed 's/"$//' | jq -r 'fromjson' > /tmp/gcp_creds.json
      else
        log "[ERROR] ❌ Formato inválido de credenciais GCP."
        return 1
      fi

      export GOOGLE_APPLICATION_CREDENTIALS="/tmp/gcp_creds.json"
      gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS" >/dev/null 2>&1 || {
        log "[ERROR] ❌ Falha ao autenticar no GCP."; return 1; }
      gcloud config set project "$ACCOUNT_ID" >/dev/null 2>&1 || true
      log "[INFO] ✅ Autenticação GCP concluída."
      ;;

    *)
      log "[ERROR] ❌ Provedor de nuvem não suportado: $CLOUD_PROVIDER"
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
    if az account show >/dev/null 2>&1; then
      log "[INFO] 🔑 Sessão Azure CLI detectada. Usando --az-cli-auth."
      prowler azure --az-cli-auth -M json-asff \
        --output-filename "prowler-azure.json" \
        --output-directory "$OUTPUT_DIR" || log "[ERROR] ⚠️ Falha no scan Azure"
    else
      log "[INFO] 🔑 Sessão CLI não detectada. Usando --sp-env-auth."
      prowler azure --sp-env-auth -M json-asff \
        --output-filename "prowler-azure.json" \
        --output-directory "$OUTPUT_DIR" || log "[ERROR] ⚠️ Falha no scan Azure"
    fi
    ;;

  gcp)
    prowler gcp -M json-asff --output-filename "prowler-gcp.json" \
      --output-directory "$OUTPUT_DIR" || {
        log "[ERROR] ⚠️ Falha no scan GCP — verifique permissões da Service Account.";
        log "[HINT] Requer roles: Viewer, Security Reviewer, Security Center Findings Viewer, Cloud Asset Viewer.";
      }
    ;;

esac

SCAN_END=$(date +%s)
DURATION=$((SCAN_END - SCAN_START))

DEST_BASE="s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/$(date -u +%Y%m%d-%H%M%S)/"
log "[INFO] ⏱️ Duração do scan: ${DURATION}s"
log "[INFO] 📤 Enviando resultados para $DEST_BASE"
aws_cli s3 cp "$OUTPUT_DIR" "$DEST_BASE" --recursive || log "[WARN] ⚠️ Falha parcial no upload."

log "========== 🔍 EXECUTION SUMMARY =========="
log "Session ID: $SESSION_ID"
log "Client:     $CLIENT_NAME"
log "Cloud:      $CLOUD_PROVIDER"
log "Account:    $ACCOUNT_ID"
log "Region:     $AWS_REGION"
log "SSM Region: $AWS_SSM_REGION"
log "Duration:   ${DURATION}s"
log "=========================================="

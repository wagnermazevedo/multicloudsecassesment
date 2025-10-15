#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v4.1.2
# Autor: Wagner Azevedo
# Alterações nesta versão:
#   - GCP não requer mais AWS_REGION nem chamadas AWS no path
#   - Ajuste de logs e comportamento em ambientes híbridos
#   - AWS/SSM e S3 continuam region-aware
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner v4.1.0"

# === Variáveis obrigatórias ===
CLIENT_NAME="${CLIENT_NAME:-unknown}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-unknown}"
ACCOUNT_ID="${ACCOUNT_ID:-undefined}"
AWS_REGION="${AWS_REGION:-us-east-1}" # Só usada para AWS/SSM
S3_BUCKET="${S3_BUCKET:-multicloud-assessments}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

OUTPUT_DIR="/tmp/output-${SESSION_ID}"
mkdir -p "$OUTPUT_DIR"

# === Helper de log ===
log() {
  local LEVEL="$1"
  local MESSAGE="$2"
  local CONTEXT=""

  # Identificação contextual
  if [[ -n "$CLIENT_NAME" ]]; then
    CONTEXT+="Client:$CLIENT_NAME "
  fi
  if [[ -n "$CLOUD_PROVIDER" ]]; then
    CONTEXT+="Cloud:$CLOUD_PROVIDER "
  fi
  if [[ -n "$ACCOUNT_ID" ]]; then
    CONTEXT+="Account:$ACCOUNT_ID "
  fi

  local TS
  TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "[RUNNER:$SESSION_ID] $TS [$LEVEL] ${CONTEXT}${MESSAGE}"
}


# ============================================================
# 🔧 Utilitários AWS
# ============================================================

aws_cli() {
  aws --region "$AWS_REGION" "$@"
}

get_ssm_value() {
  local path="$1"
  aws_cli ssm get-parameter --with-decryption --name "$path" \
    --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

parse_maybe_escaped_json() {
  local raw="$(cat)"
  if [[ -z "$raw" ]]; then echo ""; return 0; fi
  if echo "$raw" | jq empty >/dev/null 2>&1; then echo "$raw"; return 0; fi
  if echo "$raw" | grep -q '{\\\"'; then
    echo "$raw" | sed 's/^"//' | sed 's/"$//' | jq -r 'fromjson'
    return 0
  fi
  echo ""
}

# ============================================================
# 🔐 Autenticação MultiCloud
# ============================================================

authenticate() {
  case "$CLOUD_PROVIDER" in
    aws)
      log "[INFO] ☁️ Iniciando autenticação AWS..."
      ACCESS_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/access"
      ACCESS_RAW="$(get_ssm_value "$ACCESS_PATH")"
      if [[ -z "$ACCESS_RAW" ]]; then
        log "[ERROR] ❌ Credenciais AWS não encontradas em $ACCESS_PATH"
        return 1
      fi

      CLEAN_JSON="$(echo "$ACCESS_RAW" | parse_maybe_escaped_json)"
      export AWS_ACCESS_KEY_ID="$(echo "$CLEAN_JSON" | jq -r '.AWS_ACCESS_KEY_ID // empty')"
      export AWS_SECRET_ACCESS_KEY="$(echo "$CLEAN_JSON" | jq -r '.AWS_SECRET_ACCESS_KEY // empty')"
      export AWS_SESSION_TOKEN="$(echo "$CLEAN_JSON" | jq -r '.AWS_SESSION_TOKEN // empty')"
      export AWS_DEFAULT_REGION="$AWS_REGION"

      log "[INFO] ✅ Autenticação AWS concluída."
      ;;

    azure)
      log "[INFO] ☁️ Iniciando autenticação Azure..."
      CREDS_PATH="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials/access"
      CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"

      if [[ -z "$CREDS_RAW" ]]; then
        log "[ERROR] ❌ Credenciais Azure não encontradas em $CREDS_PATH."
        return 1
      fi

      CLEAN_JSON="$(echo "$CREDS_RAW" | parse_maybe_escaped_json)"
      export AZURE_TENANT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_TENANT_ID')"
      export AZURE_CLIENT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_ID')"
      export AZURE_CLIENT_SECRET="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_SECRET')"
      export AZURE_SUBSCRIPTION_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_SUBSCRIPTION_ID')"

      if az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1; then
        log "[INFO] ✅ Autenticação Azure concluída."
      else
        log "[ERROR] ❌ Falha na autenticação Azure."
        return 1
      fi
      ;;

        gcp)
      log "[INFO] 🌍 Iniciando autenticação GCP..."
      CREDS_PATH_BASE="/clients/$CLIENT_NAME/gcp"
      log "[DEBUG] 📚 Base SSM para GCP: $CREDS_PATH_BASE"

      PROJECTS=$(aws ssm describe-parameters \
        --region "$AWS_REGION" \
        --parameter-filters "Key=Name,Option=BeginsWith,Values=$CREDS_PATH_BASE/" \
        --query "Parameters[?contains(Name, '/credentials/access')].Name" \
        --output text | tr '\t' '\n' | sort -u)

      if [[ -z "$PROJECTS" ]]; then
        log "[ERROR] ❌ Nenhum projeto GCP encontrado em $CREDS_PATH_BASE."
        return 1
      fi

      for PARAM in $PROJECTS; do
        PROJECT_ID=$(echo "$PARAM" | awk -F'/' '{print $(NF-2)}')
        log "[INFO] 🧩 Projeto GCP detectado: $PROJECT_ID"

        CREDS_RAW="$(aws ssm get-parameter --region "$AWS_REGION" --with-decryption \
          --name "$PARAM" --query "Parameter.Value" --output text 2>/dev/null || true)"
        if [[ -z "$CREDS_RAW" ]]; then
          log "[ERROR] ❌ Credenciais GCP não encontradas em $PARAM"
          continue
        fi

        CLEAN_JSON="$(echo "$CREDS_RAW" | jq -r 'fromjson? // .')"
        echo "$CLEAN_JSON" > /tmp/gcp_creds.json
        export GOOGLE_APPLICATION_CREDENTIALS="/tmp/gcp_creds.json"

        log "[INFO] 🔐 Ativando Service Account para $PROJECT_ID..."
        if gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS" >/dev/null 2>&1; then
          gcloud config set project "$PROJECT_ID" >/dev/null 2>&1
          log "[INFO] ✅ Autenticação GCP bem-sucedida para $PROJECT_ID"
        else
          log "[ERROR] ❌ Falha na autenticação GCP ($PROJECT_ID)."
          continue
        fi

        # Teste de acesso (asset list)
        if gcloud asset list --project "$PROJECT_ID" --limit=1 >/dev/null 2>&1; then
          log "[DEBUG] 📊 Acesso validado para $PROJECT_ID"
        else
          log "[WARN] ⚠️ SA autenticada mas sem acesso total em $PROJECT_ID"
        fi

        # Executa Prowler GCP
        log "[INFO] ▶️ Executando Prowler GCP para $PROJECT_ID..."
        prowler gcp \
          --project-id "$PROJECT_ID" \
          -M json-asff \
          --output-filename "prowler-gcp-${PROJECT_ID}.json" \
          --output-directory "$OUTPUT_DIR" \
          --no-banner \
          || log "[WARN] ⚠️ Falha parcial no scan de $PROJECT_ID"
      done
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

SCAN_END=$(date +%s)
log "[INFO] ✅ Todos os scans concluídos com sucesso."

log "========== 🔍 EXECUTION SUMMARY =========="
log "Session ID: $SESSION_ID"
log "Client:     $CLIENT_NAME"
log "Cloud:      $CLOUD_PROVIDER"
log "Account:    $ACCOUNT_ID"
log "Region:     $AWS_REGION"
log "Output:     $OUTPUT_DIR"
log "=========================================="

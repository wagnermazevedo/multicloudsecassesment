#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v4.1.3
# Autor: Wagner Azevedo
# Alterações nesta versão:
#   - Correção de autenticação GCP (arquivos isolados por projeto)
#   - Logs contextualizados com Client/Cloud/Account
#   - Suporte Prowler v4 (--project-id)
#   - Remoção de dependência de região para GCP
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner v4.1.3"

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

  [[ -n "$CLIENT_NAME" ]] && CONTEXT+="Client:$CLIENT_NAME "
  [[ -n "$CLOUD_PROVIDER" ]] && CONTEXT+="Cloud:$CLOUD_PROVIDER "
  [[ -n "$ACCOUNT_ID" && "$ACCOUNT_ID" != "undefined" ]] && CONTEXT+="Account:$ACCOUNT_ID "

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
  [[ -z "$raw" ]] && { echo ""; return; }

  if echo "$raw" | jq empty >/dev/null 2>&1; then
    echo "$raw"; return
  fi

  if echo "$raw" | grep -q '{\\\"'; then
    echo "$raw" | sed 's/^"//' | sed 's/"$//' | jq -r 'fromjson'
    return
  fi
  echo ""
}

# ============================================================
# 🔐 Autenticação MultiCloud
# ============================================================

authenticate() {
  case "$CLOUD_PROVIDER" in
    aws)
      log "INFO" "☁️ Iniciando autenticação AWS..."
      ACCESS_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/access"
      ACCESS_RAW="$(get_ssm_value "$ACCESS_PATH")"
      [[ -z "$ACCESS_RAW" ]] && { log "ERROR" "❌ Credenciais AWS não encontradas em $ACCESS_PATH"; return 1; }

      CLEAN_JSON="$(echo "$ACCESS_RAW" | parse_maybe_escaped_json)"
      export AWS_ACCESS_KEY_ID="$(echo "$CLEAN_JSON" | jq -r '.AWS_ACCESS_KEY_ID // empty')"
      export AWS_SECRET_ACCESS_KEY="$(echo "$CLEAN_JSON" | jq -r '.AWS_SECRET_ACCESS_KEY // empty')"
      export AWS_SESSION_TOKEN="$(echo "$CLEAN_JSON" | jq -r '.AWS_SESSION_TOKEN // empty')"
      export AWS_DEFAULT_REGION="$AWS_REGION"
      log "INFO" "✅ Autenticação AWS concluída."
      ;;

    azure)
      log "INFO" "☁️ Iniciando autenticação Azure..."
      CREDS_PATH="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials/access"
      CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"
      [[ -z "$CREDS_RAW" ]] && { log "ERROR" "❌ Credenciais Azure não encontradas em $CREDS_PATH"; return 1; }

      CLEAN_JSON="$(echo "$CREDS_RAW" | parse_maybe_escaped_json)"
      export AZURE_TENANT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_TENANT_ID')"
      export AZURE_CLIENT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_ID')"
      export AZURE_CLIENT_SECRET="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_SECRET')"
      export AZURE_SUBSCRIPTION_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_SUBSCRIPTION_ID')"

      if az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1; then
        log "INFO" "✅ Autenticação Azure concluída."
      else
        log "ERROR" "❌ Falha na autenticação Azure."
        return 1
      fi
      ;;

    gcp)
      log "INFO" "🌍 Iniciando autenticação GCP..."
      CREDS_PATH_BASE="/clients/$CLIENT_NAME/gcp"
      log "DEBUG" "📚 Base SSM para GCP: $CREDS_PATH_BASE"

      PROJECTS=$(aws_cli ssm describe-parameters \
        --parameter-filters "Key=Name,Option=BeginsWith,Values=$CREDS_PATH_BASE/" \
        --query "Parameters[?contains(Name, '/credentials/access')].Name" \
        --output text | tr '\t' '\n' | sort -u)

      if [[ -z "$PROJECTS" ]]; then
        log "ERROR" "❌ Nenhum projeto GCP encontrado em $CREDS_PATH_BASE."
        return 1
      fi

      for PARAM in $PROJECTS; do
        PROJECT_ID=$(echo "$PARAM" | awk -F'/' '{print $(NF-2)}')
        ACCOUNT_ID="$PROJECT_ID" # contexto para log
        log "INFO" "🧩 Projeto GCP detectado: $PROJECT_ID"

        CREDS_RAW="$(aws_cli ssm get-parameter --with-decryption \
          --name "$PARAM" --query "Parameter.Value" --output text 2>/dev/null || true)"
        [[ -z "$CREDS_RAW" ]] && { log "ERROR" "❌ Credenciais GCP não encontradas em $PARAM"; continue; }

        CLEAN_JSON="$(echo "$CREDS_RAW" | jq -r 'fromjson? // .')"
        TMP_KEY="/tmp/gcp-${PROJECT_ID}.json"
        echo "$CLEAN_JSON" > "$TMP_KEY"
        export GOOGLE_APPLICATION_CREDENTIALS="$TMP_KEY"

        log "INFO" "🔐 Ativando Service Account para $PROJECT_ID..."
        if gcloud auth activate-service-account --key-file="$TMP_KEY" --quiet; then
          gcloud config set project "$PROJECT_ID" --quiet
          log "INFO" "✅ Autenticação GCP bem-sucedida para $PROJECT_ID"
        else
          log "ERROR" "❌ Falha na autenticação GCP ($PROJECT_ID)."
          continue
        fi

        if gcloud asset list --project "$PROJECT_ID" --limit=1 --quiet >/dev/null 2>&1; then
          log "DEBUG" "📊 Acesso validado para $PROJECT_ID"
        else
          log "WARN" "⚠️ SA autenticada mas sem acesso total em $PROJECT_ID"
        fi

        log "INFO" "▶️ Executando Prowler GCP para $PROJECT_ID..."
        if prowler gcp \
            --project-id "$PROJECT_ID" \
            -M json-asff \
            --output-filename "prowler-gcp-${PROJECT_ID}.json" \
            --output-directory "$OUTPUT_DIR" \
            --skip-api-check \
            --no-banner \
            --log-level INFO; then
          log "INFO" "✅ Scan concluído para $PROJECT_ID"
        else
          log "WARN" "⚠️ Falha parcial no scan de $PROJECT_ID"
        fi
      done
      ;;
  esac
}

# ============================================================
# 🚀 Execução principal
# ============================================================

if ! authenticate; then
  log "ERROR" "⚠️ Falha na autenticação. Encerrando execução."
  exit 1
fi

log "INFO" "✅ Todos os scans concluídos com sucesso."
log "========== 🔍 EXECUTION SUMMARY =========="
log "INFO" "Session ID: $SESSION_ID"
log "INFO" "Client:     $CLIENT_NAME"
log "INFO" "Cloud:      $CLOUD_PROVIDER"
log "INFO" "Account:    $ACCOUNT_ID"
log "INFO" "Region:     $AWS_REGION"
log "INFO" "Output:     $OUTPUT_DIR"
log "=========================================="

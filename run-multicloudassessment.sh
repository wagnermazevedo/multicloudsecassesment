#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v4.1.1
# Autor: Wagner Azevedo
# Alterações nesta versão:
#   - Suporte a múltiplos projetos GCP via loop dinâmico
#   - Logs de validação (gcloud info e asset list)
#   - Debug seguro opcional
#   - Mantém awscli obrigatório para leitura via SSM
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner v4.0.9"

# === Variáveis obrigatórias ===
CLIENT_NAME="${CLIENT_NAME:-unknown}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-unknown}"
ACCOUNT_ID="${ACCOUNT_ID:-undefined}"
AWS_REGION="${AWS_REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-multicloud-assessments}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

OUTPUT_DIR="/tmp/output-${SESSION_ID}"
mkdir -p "$OUTPUT_DIR"

# === Helper de log ===
log() { echo "[RUNNER:$SESSION_ID] $(date -u +"%Y-%m-%dT%H:%M:%SZ") $1"; }

# ============================================================
# 🔧 Funções utilitárias
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
      AWS_ACCESS_KEY_ID="$(echo "$CLEAN_JSON" | jq -r '.AWS_ACCESS_KEY_ID // empty')"
      AWS_SECRET_ACCESS_KEY="$(echo "$CLEAN_JSON" | jq -r '.AWS_SECRET_ACCESS_KEY // empty')"
      AWS_SESSION_TOKEN="$(echo "$CLEAN_JSON" | jq -r '.AWS_SESSION_TOKEN // empty')"

      export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION="$AWS_REGION"
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
      log "[DEBUG] 📚 SSM base: $CREDS_PATH_BASE"

      PROJECTS=$(aws_cli ssm get-parameters-by-path --path "$CREDS_PATH_BASE" --recursive \
        --query "Parameters[].Name" --output text | grep "/credentials/access" || true)

      if [[ -z "$PROJECTS" ]]; then
        log "[ERROR] ❌ Nenhum projeto GCP encontrado em $CREDS_PATH_BASE."
        return 1
      fi

      for PARAM in $PROJECTS; do
        PROJECT_ID=$(echo "$PARAM" | awk -F'/' '{print $(NF-2)}')
        log "[INFO] 🧩 Projeto GCP detectado: $PROJECT_ID"
        CREDS_RAW="$(get_ssm_value "$PARAM")"

        if [[ -z "$CREDS_RAW" ]]; then
          log "[ERROR] ❌ Credenciais GCP não encontradas em $PARAM"
          continue
        fi

        CLEAN_JSON="$(echo "$CREDS_RAW" | parse_maybe_escaped_json)"
        echo "$CLEAN_JSON" > /tmp/gcp_creds.json
        export GOOGLE_APPLICATION_CREDENTIALS="/tmp/gcp_creds.json"

        log "[INFO] 🔐 Ativando Service Account para $PROJECT_ID..."
        if gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS" >/dev/null 2>&1; then
          gcloud config set project "$PROJECT_ID" >/dev/null 2>&1
          log "[INFO] ✅ Autenticação GCP bem-sucedida em $PROJECT_ID"
        else
          log "[ERROR] ❌ Falha na autenticação GCP ($PROJECT_ID)."
          continue
        fi

        # Verificação simples de acesso
        if gcloud asset list --project "$PROJECT_ID" --limit=1 >/dev/null 2>&1; then
          log "[DEBUG] 📊 Verificação de acesso OK para $PROJECT_ID"
        else
          log "[WARN] ⚠️ SA autenticada, mas sem permissão de leitura em $PROJECT_ID"
        fi

        # Execução do scan GCP
        log "[INFO] ▶️ Executando Prowler GCP para $PROJECT_ID..."
        prowler gcp -M json-asff \
          --output-filename "prowler-gcp-${PROJECT_ID}.json" \
          --output-directory "$OUTPUT_DIR" \
          --project "$PROJECT_ID" || log "[WARN] ⚠️ Falha parcial no scan de $PROJECT_ID"
      done
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
EOF

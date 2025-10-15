#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v4.1.6
# Autor: Wagner Azevedo
# Alterações nesta versão:
#   - Inclusão de parâmetros automáticos de compliance e formatos de saída
#     baseados no provedor (AWS / Azure / GCP)
#   - Mantida lógica robusta de autenticação e upload S3
#   - Garante consistência entre relatórios e estrutura de diretórios
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_TS=$(date +%s)

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner v4.1.6"

# === Variáveis obrigatórias ===
CLIENT_NAME="${CLIENT_NAME:-${1:-unknown}}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-${2:-unknown}}"
ACCOUNT_ID="${ACCOUNT_ID:-${3:-undefined}}"
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

      CLEAN_JSON="$(echo "$ACCESS_RAW" | jq -r 'fromjson? // .')"
      export AWS_ACCESS_KEY_ID="$(echo "$CLEAN_JSON" | jq -r '.AWS_ACCESS_KEY_ID // empty')"
      export AWS_SECRET_ACCESS_KEY="$(echo "$CLEAN_JSON" | jq -r '.AWS_SECRET_ACCESS_KEY // empty')"
      export AWS_SESSION_TOKEN="$(echo "$CLEAN_JSON" | jq -r '.AWS_SESSION_TOKEN // empty')"
      export AWS_DEFAULT_REGION="$AWS_REGION"
      log "INFO" "✅ Autenticação AWS concluída."

      log "INFO" "▶️ Executando Prowler AWS para $ACCOUNT_ID..."
      if prowler aws \
          --compliance aws_well_architected_framework_reliability_pillar_aws aws_well_architected_framework_security_pillar_aws iso27001_2022_aws mitre_attack_aws nist_800_53_revision_5_aws prowler_threatscore_aws soc2_aws \
          --output-formats csv html json-asff \
          --output-filename "prowler-aws-${ACCOUNT_ID}" \
          --output-directory "$OUTPUT_DIR" \
          --no-banner \
          --log-level "$LOG_LEVEL"; then
        log "INFO" "✅ Scan AWS concluído para $ACCOUNT_ID"
      else
        log "WARN" "⚠️ Falha parcial no scan AWS ($ACCOUNT_ID)"
      fi
      ;;

    azure)
      log "INFO" "☁️ Iniciando autenticação Azure..."
      CREDS_PATH="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials/access"
      CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"
      [[ -z "$CREDS_RAW" ]] && { log "ERROR" "❌ Credenciais Azure não encontradas em $CREDS_PATH"; return 1; }

      CLEAN_JSON="$(echo "$CREDS_RAW" | jq -r 'fromjson? // .')"
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

      log "INFO" "▶️ Executando Prowler Azure para $ACCOUNT_ID..."
      if prowler azure \
          --subscription-id "$AZURE_SUBSCRIPTION_ID" \
          --compliance cis_4.0_azure iso27001_2022_azure mitre_attack_azure prowler_threatscore_azure soc2_azure \
          --output-formats csv html json-asff \
          --output-filename "prowler-azure-${ACCOUNT_ID}" \
          --output-directory "$OUTPUT_DIR" \
          --no-banner \
          --log-level "$LOG_LEVEL"; then
        log "INFO" "✅ Scan Azure concluído para $ACCOUNT_ID"
      else
        log "WARN" "⚠️ Falha parcial no scan Azure ($ACCOUNT_ID)"
      fi
      ;;

    gcp)
      log "INFO" "🌍 Iniciando autenticação GCP..."
      CREDS_PATH_BASE="/clients/$CLIENT_NAME/gcp"
      log "DEBUG" "📚 Base SSM para GCP: $CREDS_PATH_BASE"

      FILTERED_PARAM=$(aws_cli ssm describe-parameters \
        --parameter-filters "Key=Name,Option=BeginsWith,Values=$CREDS_PATH_BASE/$ACCOUNT_ID/" \
        --query "Parameters[?contains(Name, '/credentials/access')].Name" \
        --output text | tr '\t' '\n' | head -n 1)

      if [[ -z "$FILTERED_PARAM" ]]; then
        log "ERROR" "❌ Nenhum parâmetro encontrado para o projeto $ACCOUNT_ID."
        return 1
      fi

      PROJECT_ID="$ACCOUNT_ID"
      PARAM="$FILTERED_PARAM"
      log "INFO" "🧩 Projeto GCP detectado: $PROJECT_ID"

      CREDS_RAW="$(aws_cli ssm get-parameter --with-decryption --name "$PARAM" \
        --query "Parameter.Value" --output text 2>/dev/null || true)"
      [[ -z "$CREDS_RAW" ]] && { log "ERROR" "❌ Credenciais GCP não encontradas em $PARAM"; return 1; }

      RAW_VALUE="$CREDS_RAW"
      CLEAN_JSON=""

      if echo "$RAW_VALUE" | grep -q '^{\\\"'; then
        CLEAN_JSON="$(echo "$RAW_VALUE" | sed 's/^"//' | sed 's/"$//' | jq -r 'fromjson')"
      elif echo "$RAW_VALUE" | grep -q '{\"'; then
        CLEAN_JSON="$(echo "$RAW_VALUE" | jq -r 'fromjson? // .')"
      else
        if echo "$RAW_VALUE" | jq empty >/dev/null 2>&1; then
          CLEAN_JSON="$RAW_VALUE"
        else
          if echo "$RAW_VALUE" | base64 --decode >/dev/null 2>&1; then
            CLEAN_JSON="$(echo "$RAW_VALUE" | base64 --decode)"
          else
            CLEAN_JSON="$RAW_VALUE"
          fi
        fi
      fi

      if ! echo "$CLEAN_JSON" | jq empty >/dev/null 2>&1; then
        log "ERROR" "❌ Credenciais GCP inválidas ou corrompidas para $PROJECT_ID."
        return 1
      fi

      TMP_KEY="/tmp/gcp-${PROJECT_ID}.json"
      echo "$CLEAN_JSON" > "$TMP_KEY"
      export GOOGLE_APPLICATION_CREDENTIALS="$TMP_KEY"
      log "DEBUG" "💾 Credenciais GCP salvas em $TMP_KEY ($(wc -c < "$TMP_KEY") bytes)"

      log "INFO" "🔐 Ativando Service Account para $PROJECT_ID..."
      if gcloud auth activate-service-account --key-file="$TMP_KEY" --quiet; then
        gcloud config set project "$PROJECT_ID" --quiet
        log "INFO" "✅ Autenticação GCP bem-sucedida para $PROJECT_ID"
      else
        log "ERROR" "❌ Falha na autenticação GCP ($PROJECT_ID)."
        return 1
      fi

      log "INFO" "▶️ Executando Prowler GCP para $PROJECT_ID..."
      if prowler gcp \
          --project-id "$PROJECT_ID" \
          --compliance cis_4.0_gcp iso27001_2022_gcp mitre_attack_gcp prowler_threatscore_gcp soc2_gcp \
          --output-formats csv html json-asff \
          --output-filename "prowler-gcp-${PROJECT_ID}" \
          --output-directory "$OUTPUT_DIR" \
          --skip-api-check \
          --no-banner \
          --log-level "$LOG_LEVEL"; then
        log "INFO" "✅ Scan GCP concluído para $PROJECT_ID"
      else
        log "WARN" "⚠️ Falha parcial no scan de $PROJECT_ID"
      fi
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

# Upload automático para S3
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
S3_PATH="s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}/"

if aws s3 cp "$OUTPUT_DIR" "$S3_PATH" --recursive --only-show-errors; then
  log "INFO" "☁️ Relatórios enviados com sucesso para $S3_PATH"
else
  log "WARN" "⚠️ Falha no upload para S3 (verifique permissões)."
fi

END_TS=$(date +%s)
DURATION=$((END_TS - START_TS))
log "INFO" "⏱️ Execução finalizada em ${DURATION}s."

log "========== 🔍 EXECUTION SUMMARY =========="
log "INFO" "Session ID: $SESSION_ID"
log "INFO" "Client:     $CLIENT_NAME"
log "INFO" "Cloud:      $CLOUD_PROVIDER"
log "INFO" "Account:    $ACCOUNT_ID"
log "INFO" "Region:     $AWS_REGION"
log "INFO" "Output:     $OUTPUT_DIR"
log "INFO" "S3 Path:    $S3_PATH"
log "=========================================="

#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v4.1.6-rev6
# Autor: Wagner Azevedo
# Criado em: 2025-10-16T00:29:00Z
# Alterações nesta revisão:
#   - Corrige prefixo dos relatórios de saída para "multicloudassessment-*"
#   - Mantém 100% da compatibilidade e estabilidade da v4.1.5
#   - Mantém formatos  csv html json-asff 
#   - Cabeçalho inclui timestamp de criação
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

CREATED_AT="2025-10-16T00:29:00Z"
SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_TS=$(date +%s)

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner v4.1.6-rev1 (criado em $CREATED_AT)"

# === Variáveis obrigatórias ===
# === Variáveis obrigatórias (corrigido) ===
CLIENT_NAME="${1:-${CLIENT_NAME:-undefined}}"
CLOUD_PROVIDER="${2:-${CLOUD_PROVIDER:-undefined}}"
ACCOUNT_ID="${3:-${ACCOUNT_ID:-undefined}}"
AWS_REGION="${AWS_REGION:-us-east-1}"
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

aws_cli() { aws --region "$AWS_REGION" "$@"; }

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
  log "INFO" "☁️ Iniciando autenticação AWS (modo regeneração por execução)..."

  ROLE_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/role"
  ROLE_ARN="$(get_ssm_value "$ROLE_PATH")"
  if [[ -z "$ROLE_ARN" ]]; then
    log "ERROR" "❌ Nenhum Role ARN encontrado em $ROLE_PATH. Abortando execução."
    return 1
  fi

  log "INFO" "🔑 Solicitando novo token temporário via STS assume-role..."
  CREDS_JSON="$(aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "MulticloudAssessment-$(date +%s)" --duration-seconds 3600)"

  export AWS_ACCESS_KEY_ID="$(echo "$CREDS_JSON" | jq -r '.Credentials.AccessKeyId')"
  export AWS_SECRET_ACCESS_KEY="$(echo "$CREDS_JSON" | jq -r '.Credentials.SecretAccessKey')"
  export AWS_SESSION_TOKEN="$(echo "$CREDS_JSON" | jq -r '.Credentials.SessionToken')"
  export AWS_DEFAULT_REGION="$AWS_REGION"

  # ============================================================
  # 🔁 Atualiza o token no SSM (overwrite automático)
  # ============================================================
  UPDATED_CREDS_JSON=$(jq -n \
    --arg id "$AWS_ACCESS_KEY_ID" \
    --arg secret "$AWS_SECRET_ACCESS_KEY" \
    --arg token "$AWS_SESSION_TOKEN" \
    '{AWS_ACCESS_KEY_ID:$id, AWS_SECRET_ACCESS_KEY:$secret, AWS_SESSION_TOKEN:$token}')

  if aws ssm put-parameter \
      --name "/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/access" \
      --value "$UPDATED_CREDS_JSON" \
      --type "SecureString" \
      --overwrite >/dev/null 2>&1; then
    log "INFO" "💾 Token STS atualizado com sucesso em SSM."
  else
    log "WARN" "⚠️ Falha ao atualizar token STS no SSM (verifique permissões)."
  fi

  # ============================================================
  # Executa o scan com credenciais válidas
  # ============================================================
  log "INFO" "▶️ Executando Prowler AWS com token recém-gerado..."
  prowler aws \
    --output-formats csv html json-asff \
    --compliance aws_well_architected_framework_reliability_pillar_aws aws_well_architected_framework_security_pillar_aws iso27001_2022_aws mitre_attack_aws nist_800_53_revision_5_aws prowler_threatscore_aws soc2_aws \
    --output-filename "multicloudassessment-aws-${ACCOUNT_ID}.json" \
    --output-directory "$OUTPUT_DIR" \
    --no-banner \
    --log-level "$LOG_LEVEL" || log "WARN" "⚠️ Falha parcial no scan AWS"
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

      log "INFO" "▶️ Executando Prowler Azure..."
      prowler azure \
        --sp-env-auth \
        --output-formats csv html json-asff \
        --compliance cis_4.0_azure iso27001_2022_azure  mitre_attack_azure prowler_threatscore_azure soc2_azure \
        --output-filename "multicloudassessment-azure-${ACCOUNT_ID}.json" \
        --output-directory "$OUTPUT_DIR" \
        --no-banner \
        --log-level "$LOG_LEVEL" || log "WARN" "⚠️ Falha parcial no scan Azure"
      ;;

    gcp)
      log "INFO" "🌍 Iniciando autenticação GCP..."
      CREDS_PATH_BASE="/clients/$CLIENT_NAME/gcp"

      FILTERED_PARAM=$(aws_cli ssm describe-parameters \
        --parameter-filters "Key=Name,Option=BeginsWith,Values=$CREDS_PATH_BASE/$ACCOUNT_ID/" \
        --query "Parameters[?contains(Name, '/credentials/access')].Name" \
        --output text | tr '\t' '\n' | head -n 1)

      [[ -z "$FILTERED_PARAM" ]] && { log "ERROR" "❌ Nenhum parâmetro encontrado no SSM para $ACCOUNT_ID."; return 1; }

      CREDS_RAW="$(aws_cli ssm get-parameter --with-decryption --name "$FILTERED_PARAM" \
        --query "Parameter.Value" --output text 2>/dev/null || true)"
      [[ -z "$CREDS_RAW" ]] && { log "ERROR" "❌ Credenciais GCP não encontradas em $FILTERED_PARAM"; return 1; }

      CLEAN_JSON="$(echo "$CREDS_RAW" | jq -r 'fromjson? // .')"
      TMP_KEY="/tmp/gcp-${ACCOUNT_ID}.json"
      echo "$CLEAN_JSON" > "$TMP_KEY"
      export GOOGLE_APPLICATION_CREDENTIALS="$TMP_KEY"

      if gcloud auth activate-service-account --key-file="$TMP_KEY" --quiet; then
        gcloud config set project "$ACCOUNT_ID" --quiet
        log "INFO" "✅ Autenticação GCP concluída."
      else
        log "ERROR" "❌ Falha na autenticação GCP."
        return 1
      fi

      log "INFO" "▶️ Executando Prowler GCP..."
      prowler gcp \
        --project-id "$ACCOUNT_ID" \
        --output-formats csv html json-asff \
        --compliance cis_4.0_gcp iso27001_2022_gcp  mitre_attack_gcp prowler_threatscore_gcp soc2_gcp \
        --output-filename "multicloudassessment-gcp-${ACCOUNT_ID}.json" \
        --output-directory "$OUTPUT_DIR" \
        --skip-api-check \
        --no-banner \
        --log-level "$LOG_LEVEL" || log "WARN" "⚠️ Falha parcial no scan GCP"
      rm -f "$TMP_KEY" || true
      ;;
  *)
    log "ERROR" "❌ Provedor inválido: $CLOUD_PROVIDER"
    return 1
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
log "INFO" "Created At: $CREATED_AT"
log "INFO" "Client:     $CLIENT_NAME"
log "INFO" "Cloud:      $CLOUD_PROVIDER"
log "INFO" "Account:    $ACCOUNT_ID"
log "INFO" "Region:     $AWS_REGION"
log "INFO" "Output:     $OUTPUT_DIR"
log "INFO" "S3 Path:    $S3_PATH"
log "=========================================="

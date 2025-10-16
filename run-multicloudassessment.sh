#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner - v4.1.6-rev2 (fixed)
# Autor: Wagner Azevedo
# Criado em: 2025-10-16T00:29:00Z
# Alterações nesta revisão:
#   - CORREÇÃO: Proteção de variáveis na função log() para evitar 'unbound variable' (set -u).
#   - Lógica de argumentos simplificada e mais robusta.
# ============================================================

set -euo pipefail
# Mantemos set -u desativado APENAS para o tratamento dos argumentos iniciais.
set +u
export LANG=C.UTF-8

CREATED_AT="2025-10-16T00:29:00Z"
SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_TS=$(date +%s)

VERSION_REV="v4.1.6-rev2-$START_TIME"

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner $VERSION_REV (criado em $CREATED_AT)"

# === Tratamento e atribuição de Variáveis obrigatórias (mais robusto) ===
# Se o argumento não existir, ele assume o valor padrão.
# Isso é seguro porque set -u está desligado (+u).
CLIENT_NAME="${1:-unknown}"
CLOUD_PROVIDER="${2:-unknown}"
ACCOUNT_ID="${3:-undefined}"

# Reativa o modo estrito para o restante do script
# O erro '$2: unbound variable' não ocorrerá mais aqui, pois $2 (CLOUD_PROVIDER) foi definido.
set -u

AWS_REGION="${AWS_REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-multicloud-assessments}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

OUTPUT_DIR="/tmp/output-${SESSION_ID}"
mkdir -p "$OUTPUT_DIR"

# === Helper de log (CORREÇÃO DE UNBOUND VARIABLE) ===
log() {
  # Proteção com ${1:-} e ${2:-} garante que set -u não falhe se um argumento
  # for omitido na chamada da função.
  local LEVEL="${1:-}" 
  local MESSAGE="${2:-}"
  local CONTEXT=""

  [[ -n "$CLIENT_NAME" ]] && CONTEXT+="Client:$CLIENT_NAME "
  [[ -n "$CLOUD_PROVIDER" ]] && CONTEXT+="Cloud:$CLOUD_PROVIDER "
  [[ -n "$ACCOUNT_ID" && "$ACCOUNT_ID" != "undefined" ]] && CONTEXT+="Account:$ACCOUNT_ID "

  local TS
  TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  # Linha de log agora segura contra erros de unbound variable
  echo "[RUNNER:$SESSION_ID] $TS [$LEVEL] ${CONTEXT}${MESSAGE}"
}

# ============================================================
# 🔧 Utilitários AWS
# ============================================================

aws_cli() { aws --region "$AWS_REGION" "$@"; }

get_ssm_value() {
  local path="$1"
  # Proteção: ${path:-} garante que o script não falhe se get_ssm_value for chamado sem argumento
  aws_cli ssm get-parameter --with-decryption --name "${path:-}" \
    --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

# ============================================================
# 🔐 Autenticação MultiCloud (NÃO ALTERADA)
# ============================================================

authenticate() {
  case "$CLOUD_PROVIDER" in
    aws)
      log "INFO" "☁️ Iniciando autenticação AWS (modo regeneração automática de token)..."

      ROLE_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/role"
      ROLE_ARN="$(get_ssm_value "$ROLE_PATH")"

      if [[ -z "$ROLE_ARN" ]]; then
        log "ERROR" "❌ Nenhum Role ARN encontrado em $ROLE_PATH. Abortando execução."
        return 1
      fi

      log "INFO" "🔑 Gerando novas credenciais temporárias via STS assume-role..."
      CREDS_JSON="$(aws sts assume-role \
        --role-arn "$ROLE_ARN" \
        --role-session-name "MulticloudAssessment-${SESSION_ID}" \
        --duration-seconds 3600)"

      export AWS_ACCESS_KEY_ID="$(echo "$CREDS_JSON" | jq -r '.Credentials.AccessKeyId')"
      export AWS_SECRET_ACCESS_KEY="$(echo "$CREDS_JSON" | jq -r '.Credentials.SecretAccessKey')"
      export AWS_SESSION_TOKEN="$(echo "$CREDS_JSON" | jq -r '.Credentials.SessionToken')"
      export AWS_DEFAULT_REGION="$AWS_REGION"

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
        log "INFO" "💾 Novo token STS gravado com sucesso em SSM (overwrite realizado)."
      else
        log "WARN" "⚠️ Falha ao atualizar token STS no SSM (verifique permissões)."
      fi

      log "INFO" "✅ Autenticação AWS concluída. Executando Prowler..."
      prowler aws \
        ---output-formats csv html json-asff \
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
  esac
}

# ============================================================
# 🚀 Execução principal (NÃO ALTERADA)
# ============================================================

if ! authenticate; then
  log "ERROR" "⚠️ Falha na autenticação. Encerrando execução."
  exit 1
fi

# Upload automático para S3
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
S3_PATH="s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}/"

# === Garante uso da AWS CLI global (não Poetry) ===
export PATH=/usr/local/bin:/usr/bin:/bin

# === Restaura credenciais originais do ECS (origem) ===
log "INFO" "♻️ Revertendo credenciais para a conta de origem (ECS Task Role) para upload no S3..."
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

# Diagnóstico opcional — exibe qual conta está ativa agora
aws sts get-caller-identity --output text | awk '{print "🆔 Conta ativa para upload:", $3}' || true

# Executa o upload com controle de propriedade do bucket
echo "Upload dos artefatos no caminho $S3_PATH" # Corrigido de $PATH para $S3_PATH
cd /
if aws s3 cp "$OUTPUT_DIR/" "$S3_PATH" \
    --recursive \
    --only-show-errors \
    --acl bucket-owner-full-control ; then
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

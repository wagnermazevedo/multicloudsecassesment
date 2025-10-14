#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v4.0.0
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner v4.0.0"

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
# 🔐 Função de Autenticação
# ============================================================
authenticate() {
  case "$CLOUD_PROVIDER" in
    aws)
      log "[INFO] 🪣 Iniciando autenticação AWS (modo dinâmico sem sessão persistida)..."

      ACCESS_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/access"
      SECRET_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/secret"

      ACCESS_KEY=$(aws ssm get-parameter --with-decryption --name "$ACCESS_PATH" --query "Parameter.Value" --output text 2>/dev/null || echo "")
      SECRET_KEY=$(aws ssm get-parameter --with-decryption --name "$SECRET_PATH" --query "Parameter.Value" --output text 2>/dev/null || echo "")

      if [[ -z "$ACCESS_KEY" || -z "$SECRET_KEY" ]]; then
        log "[ERROR] ❌ Credenciais não encontradas em $ACCESS_PATH ou $SECRET_PATH"
        return 1
      fi

      log "[INFO] 🔑 Credenciais base recuperadas. Solicitando token STS temporário..."
      TOKEN_JSON=$(aws sts get-session-token \
        --duration-seconds 3600 \
        --region "$AWS_REGION" \
        --output json \
        --cli-binary-format raw-in-base64-out \
        --query 'Credentials' \
        --access-key "$ACCESS_KEY" \
        --secret-key "$SECRET_KEY" 2>/dev/null || true)

      if [[ -z "$TOKEN_JSON" ]] || echo "$TOKEN_JSON" | grep -qi "error"; then
        log "[ERROR] ❌ Falha ao gerar token STS. Resposta:"
        echo "$TOKEN_JSON"
        return 1
      fi

      AWS_ACCESS_KEY_ID=$(echo "$TOKEN_JSON" | jq -r '.AccessKeyId')
      AWS_SECRET_ACCESS_KEY=$(echo "$TOKEN_JSON" | jq -r '.SecretAccessKey')
      AWS_SESSION_TOKEN=$(echo "$TOKEN_JSON" | jq -r '.SessionToken')

      if [[ -z "$AWS_ACCESS_KEY_ID" || -z "$AWS_SECRET_ACCESS_KEY" || -z "$AWS_SESSION_TOKEN" ]]; then
        log "[ERROR] ❌ Token STS inválido. Campos obrigatórios ausentes."
        return 1
      fi

      export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION="$AWS_REGION"

      log "[INFO] 🌎 Região AWS definida como: $AWS_REGION"
      log "[INFO] ✅ Sessão autenticada (token STS temporário ativo por 1h)"
      ;;

    azure)
      log "[INFO] ☁️ Iniciando autenticação Azure..."
      CREDS_PATH="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials/access"
      creds_json=$(aws ssm get-parameter --name "$CREDS_PATH" --with-decryption --query "Parameter.Value" --output text 2>/dev/null || true)

      if [[ -z "$creds_json" ]]; then
        log "[ERROR] ❌ Credenciais Azure ausentes em $CREDS_PATH"
        return 1
      fi

      echo "$creds_json" | jq empty >/dev/null 2>&1 || {
        log "[ERROR] ❌ JSON Azure inválido."; return 1;
      }

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
      CREDS_PATH="/clients/$CLIENT_NAME/gcp/$ACCOUNT_ID/credentials/access"
      creds_json=$(aws ssm get-parameter --name "$CREDS_PATH" --with-decryption --query "Parameter.Value" --output text 2>/dev/null || true)

      if [[ -z "$creds_json" ]]; then
        log "[ERROR] ❌ Credenciais GCP ausentes em $CREDS_PATH"
        return 1
      fi

      echo "$creds_json" > /tmp/gcp_creds.json
      gcloud auth activate-service-account --key-file=/tmp/gcp_creds.json >/dev/null
      gcloud config set project "$ACCOUNT_ID" >/dev/null
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

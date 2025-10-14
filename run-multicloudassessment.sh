#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v4.0.3
# Autor: Wagner Azevedo
# Descrição:
#   - Autenticação automática AWS, Azure e GCP
#   - Gera token STS em runtime (sem armazenar no SSM)
#   - Se falhar, regenera automaticamente
#   - Logs detalhados para CloudWatch
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner v4.0.3"

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
      log "[INFO] 🪣 Iniciando autenticação AWS (STS autogerado, sem sessão persistida)..."

      ACCESS_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/access"
      SECRET_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/secret"

      # --- Lê credenciais base ---
      ACCESS_RAW=$(aws ssm get-parameter --with-decryption --name "$ACCESS_PATH" --query "Parameter.Value" --output text 2>&1 || true)
      SECRET_RAW=$(aws ssm get-parameter --with-decryption --name "$SECRET_PATH" --query "Parameter.Value" --output text 2>&1 || true)

      if [[ -z "$ACCESS_RAW" || -z "$SECRET_RAW" || "$ACCESS_RAW" == *"ParameterNotFound"* ]]; then
        log "[ERROR] ❌ Falha ao obter credenciais base em $ACCESS_PATH/$SECRET_PATH"
        return 1
      fi

      log "[DEBUG] ✅ ACCESS_KEY prefix: ${ACCESS_RAW:0:6}********"
      log "[DEBUG] ✅ SECRET_KEY prefix: ${SECRET_RAW:0:6}********"

      # --- Gera token STS em runtime ---
      log "[INFO] 🔑 Solicitando token STS temporário (1h)..."
      TOKEN_JSON=$(AWS_ACCESS_KEY_ID="$ACCESS_RAW" AWS_SECRET_ACCESS_KEY="$SECRET_RAW" \
        aws sts get-session-token --duration-seconds 3600 --region "$AWS_REGION" --output json 2>&1 || true)

      if echo "$TOKEN_JSON" | grep -qi "error"; then
        log "[WARN] ⚠️ Primeira tentativa de token STS falhou. Tentando novamente..."
        sleep 3
        TOKEN_JSON=$(AWS_ACCESS_KEY_ID="$ACCESS_RAW" AWS_SECRET_ACCESS_KEY="$SECRET_RAW" \
          aws sts get-session-token --duration-seconds 3600 --region "$AWS_REGION" --output json 2>&1 || true)
      fi

      if echo "$TOKEN_JSON" | grep -qi "error"; then
        log "[ERROR] ❌ Falha ao gerar token STS após segunda tentativa."
        echo "$TOKEN_JSON" | head -n 15
        return 1
      fi

      AWS_ACCESS_KEY_ID=$(echo "$TOKEN_JSON" | jq -r '.Credentials.AccessKeyId')
      AWS_SECRET_ACCESS_KEY=$(echo "$TOKEN_JSON" | jq -r '.Credentials.SecretAccessKey')
      AWS_SESSION_TOKEN=$(echo "$TOKEN_JSON" | jq -r '.Credentials.SessionToken')

      if [[ -z "$AWS_ACCESS_KEY_ID" || -z "$AWS_SECRET_ACCESS_KEY" || -z "$AWS_SESSION_TOKEN" ]]; then
        log "[ERROR] ❌ Token STS inválido (campos ausentes)."
        return 1
      fi

      export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION="$AWS_REGION"

      # --- Valida sessão com STS ---
      log "[INFO] 🔍 Validando sessão STS..."
      VALIDATION=$(aws sts get-caller-identity --output json 2>&1 || true)

      if echo "$VALIDATION" | grep -qi "error"; then
        log "[WARN] ⚠️ Sessão STS inválida, regenerando token..."
        TOKEN_JSON=$(AWS_ACCESS_KEY_ID="$ACCESS_RAW" AWS_SECRET_ACCESS_KEY="$SECRET_RAW" \
          aws sts get-session-token --duration-seconds 3600 --region "$AWS_REGION" --output json 2>&1 || true)
        AWS_ACCESS_KEY_ID=$(echo "$TOKEN_JSON" | jq -r '.Credentials.AccessKeyId')
        AWS_SECRET_ACCESS_KEY=$(echo "$TOKEN_JSON" | jq -r '.Credentials.SecretAccessKey')
        AWS_SESSION_TOKEN=$(echo "$TOKEN_JSON" | jq -r '.Credentials.SessionToken')
        export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
        log "[INFO] ✅ Sessão STS regenerada com sucesso."
      else
        log "[INFO] ✅ Sessão STS validada com sucesso."
      fi
      ;;

    azure)
      log "[INFO] ☁️ Iniciando autenticação Azure..."
      CREDS_PATH="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials/access"
      CREDS_RAW=$(aws ssm get-parameter --with-decryption --name "$CREDS_PATH" --query "Parameter.Value" --output text 2>&1 || true)

      if echo "$CREDS_RAW" | jq empty >/dev/null 2>&1; then
        AZURE_TENANT_ID=$(echo "$CREDS_RAW" | jq -r '.AZURE_TENANT_ID')
        AZURE_CLIENT_ID=$(echo "$CREDS_RAW" | jq -r '.AZURE_CLIENT_ID')
        AZURE_CLIENT_SECRET=$(echo "$CREDS_RAW" | jq -r '.AZURE_CLIENT_SECRET')
        AZURE_SUBSCRIPTION_ID=$(echo "$CREDS_RAW" | jq -r '.AZURE_SUBSCRIPTION_ID')
      else
        log "[ERROR] ❌ Credenciais Azure inválidas. Esperado JSON."
        return 1
      fi

      if [[ -z "$AZURE_CLIENT_ID" || -z "$AZURE_CLIENT_SECRET" || -z "$AZURE_TENANT_ID" || -z "$AZURE_SUBSCRIPTION_ID" ]]; then
        log "[ERROR] ❌ Campos obrigatórios Azure ausentes."
        return 1
      fi

      export AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET AZURE_SUBSCRIPTION_ID
      log "[INFO] 🔑 Autenticando no Azure..."
      az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1 || {
        log "[ERROR] ❌ Falha ao autenticar no Azure."; return 1; }
      az account set --subscription "$AZURE_SUBSCRIPTION_ID" >/dev/null 2>&1 || {
        log "[ERROR] ❌ Falha ao definir subscription."; return 1; }
      log "[INFO] ✅ Autenticação Azure concluída."
      ;;

    gcp)
      log "[INFO] 🌍 Iniciando autenticação GCP..."
      CREDS_PATH="/clients/$CLIENT_NAME/gcp/$ACCOUNT_ID/credentials/access"
      CREDS_RAW=$(aws ssm get-parameter --with-decryption --name "$CREDS_PATH" --query "Parameter.Value" --output text 2>&1 || true)

      if echo "$CREDS_RAW" | jq empty >/dev/null 2>&1; then
        echo "$CREDS_RAW" > /tmp/gcp_creds.json
      else
        log "[ERROR] ❌ Credenciais GCP inválidas. Esperado JSON Service Account."
        return 1
      fi

      export GOOGLE_APPLICATION_CREDENTIALS="/tmp/gcp_creds.json"
      gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS" >/dev/null 2>&1 || {
        log "[ERROR] ❌ Falha ao autenticar no GCP."; return 1; }
      gcloud config set project "$ACCOUNT_ID" >/dev/null 2>&1
      log "[INFO] ✅ Autenticação GCP concluída."
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

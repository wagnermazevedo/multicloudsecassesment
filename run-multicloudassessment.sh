#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v4.0.6 (DEBUG Edition)
# Autor: Wagner Azevedo
# Alterações nesta versão:
#   - Preferência por credenciais do ECS Task Role (sem usar usuário local)
#   - Fallback para SSM + STS (gera token temporário em runtime)
#   - Tratamento robusto de JSON escapado vindo do SSM
#   - Preflight de S3 (testa permissão de PutObject antes do upload massivo)
#   - Logs mais claros e seguros (sem vazamento de segredos)
#   - Ajustes Azure/GCP mantendo padrão de limpeza de JSON escapado
#   - (DEBUG) Exibição de variáveis de autenticação temporária
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner v4.0.6"

# === Variáveis obrigatórias (por ENV) ===
CLIENT_NAME="${CLIENT_NAME:-unknown}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-unknown}"
ACCOUNT_ID="${ACCOUNT_ID:-undefined}"
AWS_REGION="${AWS_REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-multicloud-assessments}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

echo "[RUNNER:$SESSION_ID] [INFO] 🔹 Cliente: $CLIENT_NAME | Nuvem: $CLOUD_PROVIDER | Conta/Projeto: $ACCOUNT_ID | Região: $AWS_REGION"

OUTPUT_DIR="/tmp/output-${SESSION_ID}"
mkdir -p "$OUTPUT_DIR"

# === Helper de log ===
log() { echo "[RUNNER:$SESSION_ID] $(date -u +"%Y-%m-%dT%H:%M:%SZ") $1"; }

# ============================================================
# 🔎 Utilidades
# ============================================================

aws_cli() {
  aws --region "$AWS_REGION" "$@"
}

whoami_aws() {
  local ident
  ident=$(aws_cli sts get-caller-identity --output json || true)
  if [[ -n "$ident" ]]; then
    log "[DEBUG] 🪪 get-caller-identity: $ident"
  else
    log "[DEBUG] 🪪 get-caller-identity falhou."
  fi
}

is_ecs_task_role_available() {
  if [[ -n "${AWS_CONTAINER_CREDENTIALS_FULL_URI:-}" ]] || [[ -n "${AWS_ECS_EXECUTION_ENV:-}" ]]; then
    if aws_cli sts get-caller-identity >/dev/null 2>&1; then
      return 0
    fi
  fi
  return 1
}

get_ssm_value() {
  local path="$1"
  aws_cli ssm get-parameter --with-decryption --name "$path" --query "Parameter.Value" --output text || echo ""
}

parse_maybe_escaped_json() {
  local raw
  raw="$(cat)"
  if [[ -z "$raw" ]]; then
    echo ""
    return 0
  fi
  if echo "$raw" | jq empty >/dev/null 2>&1; then
    echo "$raw"
    return 0
  fi
  if echo "$raw" | grep -q '{\\\"'; then
    echo "$raw" | sed 's/^"//' | sed 's/"$//' | jq -r 'fromjson'
    return 0
  fi
  echo ""
}

generate_sts_from_keys() {
  local akid="$1"
  local secret="$2"

  log "[INFO] 🔑 Solicitando token STS temporário (1h)..."
  local out err rc
  out="$(AWS_ACCESS_KEY_ID="$akid" AWS_SECRET_ACCESS_KEY="$secret" aws_cli sts get-session-token --duration-seconds 3600 --output json 2> /tmp/sts.err || true)"
  rc=$?
  if [[ $rc -ne 0 || -z "$out" ]]; then
    log "[WARN] ⚠️ Primeira tentativa de token STS falhou. Tentando novamente..."
    sleep 3
    out="$(AWS_ACCESS_KEY_ID="$akid" AWS_SECRET_ACCESS_KEY="$secret" aws_cli sts get-session-token --duration-seconds 3600 --output json 2> /tmp/sts.err || true)"
  fi
  if ! echo "$out" | jq -e '.Credentials.AccessKeyId,.Credentials.SecretAccessKey,.Credentials.SessionToken' >/dev/null 2>&1; then
    log "[ERROR] ❌ Falha ao gerar token STS."
    head -n 20 /tmp/sts.err || true
    return 1
  fi
  echo "$out"
}

s3_preflight_put() {
  local client="$1" cloud="$2" acct="$3"
  local ts dest key tmpfile
  ts=$(date -u +%Y%m%d-%H%M%S)
  dest="s3://${S3_BUCKET}/${client}/${cloud}/${acct}/${ts}/"
  key="${dest}.preflight_${SESSION_ID}"
  tmpfile="/tmp/.preflight_${SESSION_ID}"
  echo "ok ${SESSION_ID}" > "$tmpfile"

  log "[DEBUG] 🔎 S3 preflight: tentando PutObject em ${key}"
  if aws_cli s3 cp "$tmpfile" "$key" >/dev/null 2>&1; then
    log "[INFO] ✅ S3 preflight bem-sucedido (PutObject permitido)."
    aws_cli s3 rm "$key" >/dev/null 2>&1 || true
    echo "$dest"
    return 0
  else
    log "[ERROR] ❌ S3 preflight falhou: sem permissão para PutObject no caminho de destino."
    whoami_aws
    log "[HINT] Verifique se a task role possui s3:PutObject em arn:aws:s3:::${S3_BUCKET}/* e bucket policy sem Deny."
    return 1
  fi
}

# ============================================================
# 🔐 Autenticação
# ============================================================

authenticate() {
  case "$CLOUD_PROVIDER" in
    aws)
      if is_ecs_task_role_available; then
        log "[INFO] 🔒 Usando credenciais do ECS Task Role (preferência)."
        whoami_aws
        if ! aws_cli ssm get-parameter --name "/dummy/health" >/dev/null 2>&1; then
          log "[WARN] ⚠️ ECS Role ativa, mas sem acesso SSM."
        fi
        return 0
      fi

      log "[INFO] 🪣 Task Role indisponível. Iniciando fallback via SSM + STS..."
      ACCESS_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/access"
      log "[DEBUG] 🔍 Lendo $ACCESS_PATH"
      ACCESS_RAW="$(get_ssm_value "$ACCESS_PATH")"

      if [[ -z "$ACCESS_RAW" ]]; then
        log "[ERROR] ❌ Falha ao obter $ACCESS_PATH (vazio ou sem permissão)."
        return 1
      fi

      CLEAN_JSON="$(echo "$ACCESS_RAW" | parse_maybe_escaped_json)"
      if [[ -z "$CLEAN_JSON" ]]; then
        log "[ERROR] ❌ O parâmetro $ACCESS_PATH deve estar em JSON consolidado."
        log "[DEBUG] Conteúdo bruto (primeiros 120 chars): ${ACCESS_RAW:0:120}..."
        return 1
      fi

      local BASE_AKID BASE_SECRET
      BASE_AKID="$(echo "$CLEAN_JSON" | jq -r '.AWS_ACCESS_KEY_ID // empty')"
      BASE_SECRET="$(echo "$CLEAN_JSON" | jq -r '.AWS_SECRET_ACCESS_KEY // empty')"

      if [[ -z "$BASE_AKID" || -z "$BASE_SECRET" ]]; then
        log "[ERROR] ❌ Credenciais base (ACCESS_KEY/SECRET_KEY) ausentes no JSON."
        return 1
      fi

      log "[DEBUG] ✅ ACCESS_KEY prefix: ${BASE_AKID:0:6}********"
      log "[DEBUG] ✅ SECRET_KEY prefix: ${BASE_SECRET:0:6}********"

      local STS_JSON
      STS_JSON="$(generate_sts_from_keys "$BASE_AKID" "$BASE_SECRET")" || return 1

      AWS_ACCESS_KEY_ID="$(echo "$STS_JSON" | jq -r '.Credentials.AccessKeyId')"
      AWS_SECRET_ACCESS_KEY="$(echo "$STS_JSON" | jq -r '.Credentials.SecretAccessKey')"
      AWS_SESSION_TOKEN="$(echo "$STS_JSON" | jq -r '.Credentials.SessionToken')"

      export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION="$AWS_REGION"

      # === BLOCO DE DEBUG TEMPORÁRIO - REMOVER APÓS TESTES ===
      log "[DEBUG] --- VARIÁVEIS AWS (debug temporário) ---"
      log "[DEBUG] AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:0:8}********"
      log "[DEBUG] AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY:0:8}********"
      log "[DEBUG] AWS_SESSION_TOKEN: ${AWS_SESSION_TOKEN:0:8}********"
      log "[DEBUG] --- FIM DO BLOCO DE DEBUG TEMPORÁRIO ---"
      # ======================================================

      log "[INFO] 🔍 Validando sessão STS..."
      aws_cli sts get-caller-identity --output json || {
        log "[ERROR] ❌ Sessão STS inválida mesmo após geração."
        return 1
      }
      whoami_aws
      ;;

    azure)
      log "[INFO] ☁️ Iniciando autenticação Azure..."
      CREDS_PATH="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials/access"
      log "[DEBUG] Caminho de credencial esperado: $CREDS_PATH"
      CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"
      if [[ -z "$CREDS_RAW" ]]; then
        log "[ERROR] ❌ Credenciais Azure não encontradas em $CREDS_PATH."
        return 1
      fi
      CLEAN_JSON="$(echo "$CREDS_RAW" | parse_maybe_escaped_json)"
      if [[ -z "$CLEAN_JSON" ]]; then
        log "[ERROR] ❌ Formato inválido de credenciais Azure (esperado JSON)."
        return 1
      fi

      export AZURE_TENANT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_TENANT_ID')"
      export AZURE_CLIENT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_ID')"
      export AZURE_CLIENT_SECRET="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_SECRET')"
      export AZURE_SUBSCRIPTION_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_SUBSCRIPTION_ID')"

      # === BLOCO DE DEBUG TEMPORÁRIO - REMOVER APÓS TESTES ===
      log "[DEBUG] --- VARIÁVEIS AZURE (debug temporário) ---"
      log "[DEBUG] AZURE_TENANT_ID: ${AZURE_TENANT_ID:0:8}********"
      log "[DEBUG] AZURE_CLIENT_ID: ${AZURE_CLIENT_ID:0:8}********"
      log "[DEBUG] AZURE_SUBSCRIPTION_ID: ${AZURE_SUBSCRIPTION_ID}"
      log "[DEBUG] --- FIM DO BLOCO DE DEBUG TEMPORÁRIO ---"
      # ======================================================

      if ! az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID"; then
        log "[ERROR] ❌ Falha ao autenticar no Azure."
        return 1
      fi
      if ! az account set --subscription "$AZURE_SUBSCRIPTION_ID"; then
        log "[ERROR] ❌ Falha ao definir subscription no Azure."
        return 1
      fi
      log "[INFO] ✅ Autenticação Azure concluída."
      ;;

    gcp)
      log "[INFO] 🌍 Iniciando autenticação GCP..."
      CREDS_PATH="/clients/$CLIENT_NAME/gcp/$ACCOUNT_ID/credentials/access"
      log "[DEBUG] Caminho de credencial esperado: $CREDS_PATH"
      CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"

      if [[ -z "$CREDS_RAW" ]]; then
        log "[ERROR] ❌ Credenciais GCP não encontradas em $CREDS_PATH."
        return 1
      fi

      if echo "$CREDS_RAW" | jq empty >/dev/null 2>&1; then
        echo "$CREDS_RAW" > /tmp/gcp_creds.json
      elif echo "$CREDS_RAW" | grep -q '{\\\"'; then
        echo "$CREDS_RAW" | sed 's/^"//' | sed 's/"$//' | jq -r 'fromjson' > /tmp/gcp_creds.json
      else
        log "[ERROR] ❌ Formato inválido de credenciais GCP (esperado JSON)."
        return 1
      fi

      export GOOGLE_APPLICATION_CREDENTIALS="/tmp/gcp_creds.json"

      # === BLOCO DE DEBUG TEMPORÁRIO - REMOVER APÓS TESTES ===
      log "[DEBUG] --- VARIÁVEIS GCP (debug temporário) ---"
      log "[DEBUG] GOOGLE_APPLICATION_CREDENTIALS: $GOOGLE_APPLICATION_CREDENTIALS"
      head -n 5 "$GOOGLE_APPLICATION_CREDENTIALS" | sed 's/./*/g'
      log "[DEBUG] --- FIM DO BLOCO DE DEBUG TEMPORÁRIO ---"
      # ======================================================

      if ! gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS"; then
        log "[ERROR] ❌ Falha ao autenticar no GCP."
        return 1
      fi
      gcloud config set project "$ACCOUNT_ID" || true
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
    if ! DEST_BASE="$(s3_preflight_put "$CLIENT_NAME" "aws" "$ACCOUNT_ID")"; then
      log "[ERROR] ❌ Sem permissão de upload no bucket. Abortando antes do scan."
      exit 1
    fi
    prowler aws -M json-asff --output-filename "prowler-aws.json" \
      --output-directory "$OUTPUT_DIR" || log "[ERROR] ⚠️ Falha no scan AWS"
    ;;
  azure)
    if ! DEST_BASE="$(s3_preflight_put "$CLIENT_NAME" "azure" "$ACCOUNT_ID")"; then
      log "[ERROR] ❌ Sem permissão de upload no bucket. Abortando antes do scan."
      exit 1
    fi
    prowler azure -M json-asff --output-filename "prowler-azure.json" \
      --output-directory "$OUTPUT_DIR" || log "[ERROR] ⚠️ Falha no scan Azure"
    ;;
  gcp)
    if ! DEST_BASE="$(s3_preflight_put "$CLIENT_NAME" "gcp" "$ACCOUNT_ID")"; then
      log "[ERROR] ❌ Sem permissão de upload no bucket. Abortando antes do scan."
      exit 1
    fi
    prowler gcp -M json-asff --output-filename "prowler-gcp.json" \
      --output-directory "$OUTPUT_DIR" || log "[ERROR] ⚠️ Falha no scan GCP"
    ;;
esac

SCAN_END=$(date +%s)
DURATION=$((SCAN_END - SCAN_START))

if [[ -z "${DEST_BASE:-}" ]]; then
  DEST_BASE="s3://$S3_BUCKET/$CLIENT_NAME/$CLOUD_PROVIDER/$ACCOUNT_ID/$(date -u +%Y%m%d-%H%M%S)/"
fi

log "[INFO] ⏱️ Duração do scan: ${DURATION}s"
log "[INFO] 📤 Enviando resultados para $DEST_BASE"
if aws_cli s3 cp "$OUTPUT_DIR" "$DEST_BASE" --recursive; then
  log "[INFO] ✅ Upload concluído"
else
  log "[WARN] ⚠️ Falha parcial no upload (verifique permissões/retentativas)."
fi

log "========== 🔍 EXECUTION SUMMARY =========="
log "Session ID: $SESSION_ID"
log "Client:     $CLIENT_NAME"
log "Cloud:      $CLOUD_PROVIDER"
log "Account:    $ACCOUNT_ID"
log "Region:     $AWS_REGION"
log "Duration:   ${DURATION}s"
log "=========================================="

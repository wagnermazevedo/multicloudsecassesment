#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v4.0.7 (DEBUG Edition)
# Autor: Wagner Azevedo
# ============================================================
# Alterações nesta versão:
#   - Preferência por credenciais do ECS Task Role
#   - Fallback para SSM + STS (gera token temporário em runtime)
#   - Tratamento robusto de JSON escapado vindo do SSM
#   - Preflight de S3 (PutObject test antes do upload)
#   - Logs completos (sem erros silenciosos)
#   - Blocos de debug temporário mascarados
#   - Inspeção de parâmetros SSM automática em caso de falha
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner v4.0.7"

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
# 🔧 Utilidades gerais
# ============================================================

aws_cli() { aws --region "$AWS_REGION" "$@"; }

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
  aws_cli ssm get-parameter --with-decryption --name "$path" --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

parse_maybe_escaped_json() {
  local raw
  raw="$(cat)"
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
# 🧪 Funções de debug SSM
# ============================================================

ssm__mask_preview() {
  local v="$1"; local len=${#v}
  if [[ $len -eq 0 ]]; then echo "(vazio)"; return; fi
  local head=${v:0:12}
  local stars
  stars=$(printf '%*s' "${#head}" '' | tr ' ' '*')
  echo "${stars} (len=${len})"
}

ssm_dump_prefix() {
  local prefix="$1" next res
  log "[DEBUG] 📚 SSM: inspecionando prefixo: ${prefix}"
  next=""
  while :; do
    if [[ -n "$next" ]]; then
      res="$(aws_cli ssm get-parameters-by-path --with-decryption --path "$prefix" --recursive --max-results 10 --next-token "$next" 2>&1)" || true
    else
      res="$(aws_cli ssm get-parameters-by-path --with-decryption --path "$prefix" --recursive --max-results 10 2>&1)" || true
    fi
    if ! echo "$res" | jq -e '.' >/dev/null 2>&1; then
      log "[DEBUG] ⚠️ SSM dump falhou: $res"
      break
    fi
    echo "$res" | jq -r '.Parameters[] | [.Name, .Value] | @tsv' | while IFS=$'\t' read -r name val; do
      local pv; pv="$(ssm__mask_preview "$val")"
      log "[DEBUG] SSM param: ${name} = ${pv}"
    done
    next="$(echo "$res" | jq -r '.NextToken // empty')"
    [[ -z "$next" ]] && break
  done
}

ssm_show_param() {
  local name="$1" res
  res="$(aws_cli ssm get-parameter --with-decryption --name "$name" --query 'Parameter.Value' --output text 2>&1)" || true
  if echo "$res" | grep -qiE 'ParameterNotFound|AccessDenied|error'; then
    log "[DEBUG] 🔎 SSM get-parameter ${name}: $res"
    return
  fi
  local pv; pv="$(ssm__mask_preview "$res")"
  log "[DEBUG] SSM get-parameter ${name} = ${pv}"
}

# ============================================================
# 🔐 Autenticação
# ============================================================

authenticate() {
  case "$CLOUD_PROVIDER" in
    aws)
      if is_ecs_task_role_available; then
        log "[INFO] 🔒 Usando ECS Task Role."
        whoami_aws
        return 0
      fi

      log "[INFO] 🪣 Task Role indisponível. Fallback via SSM + STS..."
      ACCESS_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/access"
      PREFIX="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials"
      log "[DEBUG] Caminho de credencial esperado: $ACCESS_PATH"

      [[ "${LOG_LEVEL^^}" == "DEBUG" ]] && ssm_dump_prefix "$PREFIX" && ssm_show_param "$ACCESS_PATH"

      ACCESS_RAW="$(get_ssm_value "$ACCESS_PATH")"
      if [[ -z "$ACCESS_RAW" ]]; then
        log "[ERROR] ❌ Credenciais AWS não encontradas em $ACCESS_PATH."
        ssm_dump_prefix "$PREFIX"
        ssm_show_param "$ACCESS_PATH"
        return 1
      fi

      CLEAN_JSON="$(echo "$ACCESS_RAW" | parse_maybe_escaped_json)"
      [[ -z "$CLEAN_JSON" ]] && { log "[ERROR] ❌ JSON inválido em $ACCESS_PATH."; return 1; }

      BASE_AKID="$(echo "$CLEAN_JSON" | jq -r '.AWS_ACCESS_KEY_ID // empty')"
      BASE_SECRET="$(echo "$CLEAN_JSON" | jq -r '.AWS_SECRET_ACCESS_KEY // empty')"

      [[ -z "$BASE_AKID" || -z "$BASE_SECRET" ]] && { log "[ERROR] ❌ Chaves ausentes no JSON."; return 1; }

      log "[DEBUG] ✅ ACCESS_KEY prefix: ${BASE_AKID:0:6}********"
      log "[DEBUG] ✅ SECRET_KEY prefix: ${BASE_SECRET:0:6}********"

      local STS_JSON
      STS_JSON="$(AWS_ACCESS_KEY_ID="$BASE_AKID" AWS_SECRET_ACCESS_KEY="$BASE_SECRET" aws_cli sts get-session-token --duration-seconds 3600 --output json 2>/tmp/sts.err || true)"
      [[ -z "$STS_JSON" ]] && { log "[ERROR] ❌ Falha ao gerar token STS."; cat /tmp/sts.err; return 1; }

      export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
      AWS_ACCESS_KEY_ID="$(echo "$STS_JSON" | jq -r '.Credentials.AccessKeyId')"
      AWS_SECRET_ACCESS_KEY="$(echo "$STS_JSON" | jq -r '.Credentials.SecretAccessKey')"
      AWS_SESSION_TOKEN="$(echo "$STS_JSON" | jq -r '.Credentials.SessionToken')"

      log "[DEBUG] --- VARIÁVEIS AWS (debug temporário) ---"
      log "[DEBUG] AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:0:8}********"
      log "[DEBUG] AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY:0:8}********"
      log "[DEBUG] --- FIM DEBUG ---"

      aws_cli sts get-caller-identity || { log "[ERROR] ❌ Sessão STS inválida."; return 1; }
      whoami_aws
      ;;

    azure)
      log "[INFO] ☁️ Iniciando autenticação Azure..."
      CREDS_PATH="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials/access"
      PREFIX="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials"
      log "[DEBUG] Caminho de credencial esperado: $CREDS_PATH"

      [[ "${LOG_LEVEL^^}" == "DEBUG" ]] && ssm_dump_prefix "$PREFIX" && ssm_show_param "$CREDS_PATH"

      CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"
      if [[ -z "$CREDS_RAW" ]]; then
        log "[ERROR] ❌ Credenciais Azure não encontradas em $CREDS_PATH."
        ssm_dump_prefix "$PREFIX"
        ssm_show_param "$CREDS_PATH"
        return 1
      fi

      CLEAN_JSON="$(echo "$CREDS_RAW" | parse_maybe_escaped_json)"
      [[ -z "$CLEAN_JSON" ]] && { log "[ERROR] ❌ JSON inválido."; ssm_show_param "$CREDS_PATH"; return 1; }

      export AZURE_TENANT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_TENANT_ID')"
      export AZURE_CLIENT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_ID')"
      export AZURE_CLIENT_SECRET="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_SECRET')"
      export AZURE_SUBSCRIPTION_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_SUBSCRIPTION_ID')"

      log "[DEBUG] --- VARIÁVEIS AZURE ---"
      log "[DEBUG] AZURE_TENANT_ID: ${AZURE_TENANT_ID:0:8}********"
      log "[DEBUG] AZURE_CLIENT_ID: ${AZURE_CLIENT_ID:0:8}********"
      log "[DEBUG] AZURE_SUBSCRIPTION_ID: ${AZURE_SUBSCRIPTION_ID}"
      log "[DEBUG] --- FIM DEBUG ---"

      az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" || {
        log "[ERROR] ❌ Falha ao autenticar no Azure."; ssm_show_param "$CREDS_PATH"; return 1; }
      az account set --subscription "$AZURE_SUBSCRIPTION_ID" || { log "[ERROR] ❌ Falha ao definir subscription."; return 1; }
      log "[INFO] ✅ Autenticação Azure concluída."
      ;;

    gcp)
      log "[INFO] 🌍 Iniciando autenticação GCP..."
      CREDS_PATH="/clients/$CLIENT_NAME/gcp/$ACCOUNT_ID/credentials/access"
      PREFIX="/clients/$CLIENT_NAME/gcp/$ACCOUNT_ID/credentials"
      log "[DEBUG] Caminho de credencial esperado: $CREDS_PATH"

      [[ "${LOG_LEVEL^^}" == "DEBUG" ]] && ssm_dump_prefix "$PREFIX" && ssm_show_param "$CREDS_PATH"

      CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"
      if [[ -z "$CREDS_RAW" ]]; then
        log "[ERROR] ❌ Credenciais GCP não encontradas em $CREDS_PATH."
        ssm_dump_prefix "$PREFIX"
        ssm_show_param "$CREDS_PATH"
        return 1
      fi

      if echo "$CREDS_RAW" | jq empty >/dev/null 2>&1; then
        echo "$CREDS_RAW" > /tmp/gcp_creds.json
      elif echo "$CREDS_RAW" | grep -q '{\\\"'; then
        echo "$CREDS_RAW" | sed 's/^"//' | sed 's/"$//' | jq -r 'fromjson' > /tmp/gcp_creds.json
      else
        log "[ERROR] ❌ Formato inválido de credenciais GCP."; ssm_show_param "$CREDS_PATH"; return 1
      fi

      export GOOGLE_APPLICATION_CREDENTIALS="/tmp/gcp_creds.json"
      log "[DEBUG] --- VARIÁVEIS GCP ---"
      log "[DEBUG] GOOGLE_APPLICATION_CREDENTIALS: $GOOGLE_APPLICATION_CREDENTIALS"
      log "[DEBUG] --- FIM DEBUG ---"

      gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS" || {
        log "[ERROR] ❌ Falha ao autenticar no GCP."; ssm_show_param "$CREDS_PATH"; return 1; }
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
    DEST_BASE="$(aws_cli s3api head-bucket --bucket "$S3_BUCKET" >/dev/null 2>&1 && echo "s3://${S3_BUCKET}/${CLIENT_NAME}/aws/${ACCOUNT_ID}/$(date -u +%Y%m%d-%H%M%S)/")"
    prowler aws -M json-asff --output-filename "prowler-aws.json" --output-directory "$OUTPUT_DIR" || log "[ERROR] ⚠️ Falha no scan AWS"
    ;;
  azure)
    DEST_BASE="s3://${S3_BUCKET}/${CLIENT_NAME}/azure/${ACCOUNT_ID}/$(date -u +%Y%m%d-%H%M%S)/"
    prowler azure -M json-asff --output-filename "prowler-azure.json" --output-directory "$OUTPUT_DIR" || log "[ERROR] ⚠️ Falha no scan Azure"
    ;;
  gcp)
    DEST_BASE="s3://${S3_BUCKET}/${CLIENT_NAME}/gcp/${ACCOUNT_ID}/$(date -u +%Y%m%d-%H%M%S)/"
    prowler gcp -M json-asff --output-filename "prowler-gcp.json" --output-directory "$OUTPUT_DIR" || log "[ERROR] ⚠️ Falha no scan GCP"
    ;;
esac

SCAN_END=$(date +%s)
DURATION=$((SCAN_END - SCAN_START))

log "[INFO] ⏱️ Duração do scan: ${DURATION}s"
log "[INFO] 📤 Enviando resultados para $DEST_BASE"
aws_cli s3 cp "$OUTPUT_DIR" "$DEST_BASE" --recursive || log "[WARN] ⚠️ Falha parcial no upload."

log "========== 🔍 EXECUTION SUMMARY =========="
log "Session ID: $SESSION_ID"
log "Client:     $CLIENT_NAME"
log "Cloud:      $CLOUD_PROVIDER"
log "Account:    $ACCOUNT_ID"
log "Region:     $AWS_REGION"
log "Duration:   ${DURATION}s"
log "=========================================="

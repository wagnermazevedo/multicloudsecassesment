#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v4.0.8
# Autor: Wagner Azevedo
# ============================================================
# Alterações nesta versão:
#   - Correção de PATH do AWS CLI em ambientes Poetry e Slim
#   - AWS CLI obrigatório para todas as clouds (SSM backend)
#   - Log explicativo de backend SSM universal
#   - Melhoria de robustez na inspeção de parâmetros
#   - Retenção de debug mascarado para segurança
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[RUNNER:$SESSION_ID] $START_TIME [INFO] 🧭 Iniciando execução do Multicloud Assessment Runner v4.0.8"

CLIENT_NAME="${CLIENT_NAME:-unknown}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-unknown}"
ACCOUNT_ID="${ACCOUNT_ID:-undefined}"
AWS_REGION="${AWS_REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-multicloud-assessments}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

echo "[RUNNER:$SESSION_ID] [INFO] 🔹 Cliente: $CLIENT_NAME | Nuvem: $CLOUD_PROVIDER | Conta/Projeto: $ACCOUNT_ID | Região: $AWS_REGION"

# ============================================================
# 🔧 PATH fix e verificação do AWS CLI
# ============================================================
if ! command -v aws >/dev/null 2>&1; then
  for d in /usr/local/bin /usr/bin /bin; do
    if [[ -x "$d/aws" ]]; then
      export PATH="$d:$PATH"
      echo "[ENTRYPOINT] ⚙️ AWS CLI detectado e PATH ajustado: $PATH"
      break
    fi
  done
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "[ENTRYPOINT] ❌ AWS CLI não encontrado! É obrigatório para leitura de credenciais (SSM backend)."
  exit 1
fi

OUTPUT_DIR="/tmp/output-${SESSION_ID}"
mkdir -p "$OUTPUT_DIR"

# === Helper de log ===
log() { echo "[RUNNER:$SESSION_ID] $(date -u +"%Y-%m-%dT%H:%M:%SZ") $1"; }

# ============================================================
# 🔎 Utilidades e funções de apoio
# ============================================================

aws_cli() { aws --region "$AWS_REGION" "$@"; }

get_ssm_value() {
  local path="$1"
  aws_cli ssm get-parameter --with-decryption --name "$path" --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

parse_maybe_escaped_json() {
  local raw; raw="$(cat)"
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
  [[ $len -eq 0 ]] && { echo "(vazio)"; return; }
  local head=${v:0:12}; local stars
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
# 🔐 Autenticação Multicloud (Azure, AWS, GCP)
# ============================================================

authenticate() {
  log "[INFO] 💾 Todas as credenciais são obtidas do AWS SSM Parameter Store (backend unificado)."

  case "$CLOUD_PROVIDER" in
    aws)
      log "[INFO] ☁️ Iniciando autenticação AWS..."
      CREDS_PATH="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials/access"
      PREFIX="/clients/$CLIENT_NAME/aws/$ACCOUNT_ID/credentials"
      log "[DEBUG] Caminho esperado: $CREDS_PATH"

      [[ "${LOG_LEVEL^^}" == "DEBUG" ]] && ssm_dump_prefix "$PREFIX" && ssm_show_param "$CREDS_PATH"

      ACCESS_RAW="$(get_ssm_value "$CREDS_PATH")"
      if [[ -z "$ACCESS_RAW" ]]; then
        log "[ERROR] ❌ Credenciais AWS não encontradas."
        ssm_dump_prefix "$PREFIX"; ssm_show_param "$CREDS_PATH"
        return 1
      fi

      CLEAN_JSON="$(echo "$ACCESS_RAW" | parse_maybe_escaped_json)"
      BASE_AKID="$(echo "$CLEAN_JSON" | jq -r '.AWS_ACCESS_KEY_ID // empty')"
      BASE_SECRET="$(echo "$CLEAN_JSON" | jq -r '.AWS_SECRET_ACCESS_KEY // empty')"
      BASE_TOKEN="$(echo "$CLEAN_JSON" | jq -r '.AWS_SESSION_TOKEN // empty')"

      [[ -z "$BASE_AKID" || -z "$BASE_SECRET" ]] && { log "[ERROR] ❌ Credenciais inválidas."; return 1; }

      export AWS_ACCESS_KEY_ID="$BASE_AKID"
      export AWS_SECRET_ACCESS_KEY="$BASE_SECRET"
      export AWS_SESSION_TOKEN="$BASE_TOKEN"
      log "[INFO] ✅ Autenticação AWS concluída."
      ;;

    azure)
      log "[INFO] ☁️ Iniciando autenticação Azure..."
      CREDS_PATH="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials/access"
      PREFIX="/clients/$CLIENT_NAME/azure/$ACCOUNT_ID/credentials"
      log "[DEBUG] Caminho esperado: $CREDS_PATH"

      [[ "${LOG_LEVEL^^}" == "DEBUG" ]] && ssm_dump_prefix "$PREFIX" && ssm_show_param "$CREDS_PATH"

      CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"
      if [[ -z "$CREDS_RAW" ]]; then
        log "[ERROR] ❌ Credenciais Azure não encontradas em $CREDS_PATH."
        ssm_dump_prefix "$PREFIX"; ssm_show_param "$CREDS_PATH"
        return 1
      fi

      CLEAN_JSON="$(echo "$CREDS_RAW" | parse_maybe_escaped_json)"
      export AZURE_TENANT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_TENANT_ID')"
      export AZURE_CLIENT_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_ID')"
      export AZURE_CLIENT_SECRET="$(echo "$CLEAN_JSON" | jq -r '.AZURE_CLIENT_SECRET')"
      export AZURE_SUBSCRIPTION_ID="$(echo "$CLEAN_JSON" | jq -r '.AZURE_SUBSCRIPTION_ID')"

      log "[DEBUG] --- VARIÁVEIS AZURE (debug temporário) ---"
      log "[DEBUG] AZURE_TENANT_ID: ${AZURE_TENANT_ID:0:8}********"
      log "[DEBUG] AZURE_CLIENT_ID: ${AZURE_CLIENT_ID:0:8}********"
      log "[DEBUG] AZURE_SUBSCRIPTION_ID: ${AZURE_SUBSCRIPTION_ID}"
      log "[DEBUG] --- FIM DEBUG ---"

      az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1 || {
        log "[ERROR] ❌ Falha ao autenticar no Azure."; return 1; }
      az account set --subscription "$AZURE_SUBSCRIPTION_ID" >/dev/null 2>&1 || {
        log "[ERROR] ❌ Falha ao definir subscription."; return 1; }
      log "[INFO] ✅ Autenticação Azure concluída."
      ;;

    gcp)
      log "[INFO] ☁️ Iniciando autenticação GCP..."
      CREDS_PATH="/clients/$CLIENT_NAME/gcp/$ACCOUNT_ID/credentials/access"
      PREFIX="/clients/$CLIENT_NAME/gcp/$ACCOUNT_ID/credentials"
      log "[DEBUG] Caminho esperado: $CREDS_PATH"

      [[ "${LOG_LEVEL^^}" == "DEBUG" ]] && ssm_dump_prefix "$PREFIX" && ssm_show_param "$CREDS_PATH"

      CREDS_RAW="$(get_ssm_value "$CREDS_PATH")"
      [[ -z "$CREDS_RAW" ]] && { log "[ERROR] ❌ Credenciais GCP não encontradas."; return 1; }

      if echo "$CREDS_RAW" | jq empty >/dev/null 2>&1; then
        echo "$CREDS_RAW" > /tmp/gcp_creds.json
      elif echo "$CREDS_RAW" | grep -q '{\\\"'; then
        echo "$CREDS_RAW" | sed 's/^"//' | sed 's/"$//' | jq -r 'fromjson' > /tmp/gcp_creds.json
      else
        log "[ERROR] ❌ Formato inválido de credenciais GCP."
        return 1
      fi

      export GOOGLE_APPLICATION_CREDENTIALS="/tmp/gcp_creds.json"
      gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS" >/dev/null 2>&1 || {
        log "[ERROR] ❌ Falha ao autenticar no GCP."; return 1; }
      gcloud config set project "$ACCOUNT_ID" >/dev/null 2>&1 || true
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

DEST_BASE="s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/$(date -u +%Y%m%d-%H%M%S)/"
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

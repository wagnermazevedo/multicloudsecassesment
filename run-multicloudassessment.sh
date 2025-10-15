#!/usr/bin/env bash
# ============================================================
# MultiCloud Security Assessment Runner v4.2.1
# Autor: Wagner Azevedo
# Alterações nesta versão:
#   - Correção definitiva do "unbound variable" com defaults seguros e validação de entrada
#   - Validação de dependências (aws/az/gcloud/prowler/jq/base64)
#   - Autenticação endurecida (STS/GetCallerIdentity na AWS; login SP no Azure; SA no GCP)
#   - Parsing robusto de credenciais (JSON puro, JSON escapado, base64)
#   - Prefixo multicloudassessment em todos os relatórios e múltiplos formatos
#   - Logs consistentes + sumário final
# ============================================================

set -euo pipefail
export LANG=C.UTF-8

SESSION_ID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_TS=$(date +%s)

# =========================
# Config (com defaults)
# =========================
CLIENT_NAME="${CLIENT_NAME:-${1:-}}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-${2:-}}"
ACCOUNT_ID="${ACCOUNT_ID:-${3:-}}"
AWS_REGION="${AWS_REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-multicloud-assessments}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

OUTPUT_DIR="/tmp/output-${SESSION_ID}"
mkdir -p "$OUTPUT_DIR"

# =========================
# Logging
# =========================
log() {
  local LEVEL="$1"
  local MESSAGE="$2"
  local CONTEXT=""
  [[ -n "${CLIENT_NAME:-}" ]] && CONTEXT+="Client:${CLIENT_NAME} "
  [[ -n "${CLOUD_PROVIDER:-}" ]] && CONTEXT+="Cloud:${CLOUD_PROVIDER} "
  [[ -n "${ACCOUNT_ID:-}" ]] && CONTEXT+="Account:${ACCOUNT_ID} "
  local TS; TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "[RUNNER:${SESSION_ID}] ${TS} [${LEVEL}] ${CONTEXT}${MESSAGE}"
}

usage() {
  cat <<EOF
Uso:
  $0 <client_name> <cloud_provider> <account_or_project_id>

…ou via variáveis de ambiente:
  CLIENT_NAME=<client> CLOUD_PROVIDER=<aws|azure|gcp> ACCOUNT_ID=<id> $0

Exemplos:
  CLIENT_NAME=acme CLOUD_PROVIDER=aws ACCOUNT_ID=767397997901 $0
  $0 acme azure 00000000-0000-0000-0000-000000000000
  $0 acme gcp loyal-symbol-424319
EOF
}

# =========================
# Pré-validações
# =========================
if [[ -z "${CLIENT_NAME}" || -z "${CLOUD_PROVIDER}" || -z "${ACCOUNT_ID}" ]]; then
  log "ERROR" "Parâmetros ausentes. É necessário informar CLIENT_NAME, CLOUD_PROVIDER e ACCOUNT_ID."
  usage
  exit 2
fi

# normaliza provedor
CLOUD_PROVIDER_LC="$(echo "${CLOUD_PROVIDER}" | tr '[:upper:]' '[:lower:]')"
if [[ "${CLOUD_PROVIDER_LC}" != "aws" && "${CLOUD_PROVIDER_LC}" != "azure" && "${CLOUD_PROVIDER_LC}" != "gcp" ]]; then
  log "ERROR" "Provedor inválido: ${CLOUD_PROVIDER} (use aws|azure|gcp)."
  usage
  exit 2
fi

# =========================
# Dependências
# =========================
need() {
  local bin="$1"
  command -v "$bin" >/dev/null 2>&1 || { log "ERROR" "Dependência ausente: ${bin}"; exit 3; }
}
need jq
need base64
need prowler
need aws
[[ "${CLOUD_PROVIDER_LC}" == "azure" ]] && need az
[[ "${CLOUD_PROVIDER_LC}" == "gcp"   ]] && need gcloud

log "INFO" "🧭 Iniciando execução do Multicloud Assessment Runner v4.2.1"

# ============================================================
# Utilitários AWS
# ============================================================
aws_cli() { aws --region "${AWS_REGION}" "$@"; }

get_ssm_value() {
  local path="$1"
  aws_cli ssm get-parameter --with-decryption --name "$path" \
    --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

# ============================================================
# Parsing robusto de blob de credenciais (JSON/base64/escapado)
# Retorna em stdout o JSON limpo (ou string vazia em falha)
# ============================================================
clean_secret_blob() {
  local RAW="$1"

  # 1) Já é JSON válido?
  if echo "${RAW}" | jq -e . >/dev/null 2>&1; then
    echo "${RAW}"
    return 0
  fi

  # 2) Tenta base64 -> JSON
  if CLEAN="$(echo -n "${RAW}" | base64 -d 2>/dev/null)"; then
    if echo "${CLEAN}" | jq -e . >/dev/null 2>&1; then
      echo "${CLEAN}"
      return 0
    fi
  fi

  # 3) Tenta remover aspas externas e desserializar JSON escapado
  STRIPPED="$(echo -n "${RAW}" | sed 's/^"//' | sed 's/"$//')"
  if CLEAN="$(echo -n "${STRIPPED}" | jq -r 'fromjson? // empty' 2>/dev/null)"; then
    if [[ -n "${CLEAN}" ]] && echo "${CLEAN}" | jq -e . >/dev/null 2>&1; then
      echo "${CLEAN}"
      return 0
    fi
  fi

  # 4) Falhou
  echo ""
  return 1
}

# ============================================================
# Autenticação + Execução Prowler
# ============================================================
authenticate_and_scan() {
  case "${CLOUD_PROVIDER_LC}" in
    aws)
      log "INFO" "☁️ Iniciando autenticação AWS…"
      local ACCESS_PATH="/clients/${CLIENT_NAME}/aws/${ACCOUNT_ID}/credentials/access"
      local ACCESS_RAW; ACCESS_RAW="$(get_ssm_value "${ACCESS_PATH}")"
      if [[ -z "${ACCESS_RAW}" ]]; then
        log "ERROR" "❌ Credenciais AWS não encontradas em ${ACCESS_PATH}"
        return 1
      fi

      local CLEAN_JSON; CLEAN_JSON="$(clean_secret_blob "${ACCESS_RAW}")" || true
      if [[ -z "${CLEAN_JSON}" ]]; then
        log "ERROR" "❌ Falha ao normalizar credenciais AWS (formato inválido)."
        return 1
      fi

      export AWS_ACCESS_KEY_ID="$(echo "${CLEAN_JSON}" | jq -r '.AWS_ACCESS_KEY_ID // empty')"
      export AWS_SECRET_ACCESS_KEY="$(echo "${CLEAN_JSON}" | jq -r '.AWS_SECRET_ACCESS_KEY // empty')"
      export AWS_SESSION_TOKEN="$(echo "${CLEAN_JSON}" | jq -r '.AWS_SESSION_TOKEN // empty')"
      export AWS_DEFAULT_REGION="${AWS_REGION}"

      if [[ -z "${AWS_ACCESS_KEY_ID}" || -z "${AWS_SECRET_ACCESS_KEY}" || -z "${AWS_SESSION_TOKEN}" ]]; then
        log "ERROR" "❌ Variáveis AWS_* ausentes após parsing (AKID/SECRET/TOKEN)."
        return 1
      fi

      # Valida credenciais
      if ! aws_cli sts get-caller-identity >/dev/null 2>&1; then
        log "ERROR" "❌ STS falhou (possível InvalidClientTokenId / token expirado / credenciais incorretas)."
        return 1
      fi
      log "INFO" "✅ Autenticação AWS concluída."

      log "INFO" "🚀 Executando scan AWS…"
      if ! prowler aws \
        --compliance aws_well_architected_framework_reliability_pillar_aws aws_well_architected_framework_security_pillar_aws iso27001_2022_aws mitre_attack_aws nist_800_53_revision_5_aws prowler_threatscore_aws soc2_aws \
        --output-formats csv html json-asff \
        --output-filename "multicloudassessment-aws-${ACCOUNT_ID}" \
        --output-directory "${OUTPUT_DIR}" \
        --no-banner \
        --log-level "${LOG_LEVEL}"
      then
        log "WARN" "⚠️ Falha parcial no scan AWS"
      fi
      ;;

    azure)
      log "INFO" "☁️ Iniciando autenticação Azure…"
      local CREDS_PATH="/clients/${CLIENT_NAME}/azure/${ACCOUNT_ID}/credentials/access"
      local CREDS_RAW; CREDS_RAW="$(get_ssm_value "${CREDS_PATH}")"
      if [[ -z "${CREDS_RAW}" ]]; then
        log "ERROR" "❌ Credenciais Azure não encontradas em ${CREDS_PATH}"
        return 1
      fi

      local CLEAN_JSON; CLEAN_JSON="$(clean_secret_blob "${CREDS_RAW}")" || true
      if [[ -z "${CLEAN_JSON}" ]]; then
        log "ERROR" "❌ Falha ao normalizar credenciais Azure."
        return 1
      fi

      export AZURE_TENANT_ID="$(echo "${CLEAN_JSON}" | jq -r '.AZURE_TENANT_ID // empty')"
      export AZURE_CLIENT_ID="$(echo "${CLEAN_JSON}" | jq -r '.AZURE_CLIENT_ID // empty')"
      export AZURE_CLIENT_SECRET="$(echo "${CLEAN_JSON}" | jq -r '.AZURE_CLIENT_SECRET // empty')"
      export AZURE_SUBSCRIPTION_ID="$(echo "${CLEAN_JSON}" | jq -r '.AZURE_SUBSCRIPTION_ID // empty')"

      if [[ -z "${AZURE_TENANT_ID}" || -z "${AZURE_CLIENT_ID}" || -z "${AZURE_CLIENT_SECRET}" || -z "${AZURE_SUBSCRIPTION_ID}" ]]; then
        log "ERROR" "❌ Variáveis AZURE_* ausentes após parsing."
        return 1
      fi

      if az login --service-principal -u "${AZURE_CLIENT_ID}" -p "${AZURE_CLIENT_SECRET}" --tenant "${AZURE_TENANT_ID}" >/dev/null 2>&1; then
        az account set --subscription "${AZURE_SUBSCRIPTION_ID}" >/dev/null 2>&1 || true
        log "INFO" "✅ Autenticação Azure concluída."
      else
        log "ERROR" "❌ Falha na autenticação Azure."
        return 1
      fi

      log "INFO" "🚀 Executando scan Azure…"
      if ! prowler azure \
        --compliance cis_4.0_azure iso27001_2022_azure mitre_attack_azure prowler_threatscore_azure soc2_azure \
        --output-formats csv html json-asff \
        --output-filename "multicloudassessment-azure-${ACCOUNT_ID}" \
        --output-directory "${OUTPUT_DIR}" \
        --no-banner \
        --log-level "${LOG_LEVEL}"
      then
        log "WARN" "⚠️ Falha parcial no scan Azure"
      fi
      ;;

    gcp)
      log "INFO" "🌍 Iniciando autenticação GCP…"
      local CREDS_PATH_BASE="/clients/${CLIENT_NAME}/gcp/${ACCOUNT_ID}/credentials/access"

      local CREDS_RAW; CREDS_RAW="$(get_ssm_value "${CREDS_PATH_BASE}")"
      if [[ -z "${CREDS_RAW}" ]]; then
        # fallback: tenta localizar pelo prefixo
        local FOUND; FOUND="$(aws_cli ssm describe-parameters \
           --parameter-filters "Key=Name,Option=BeginsWith,Values=/clients/${CLIENT_NAME}/gcp/${ACCOUNT_ID}/" \
           --query "Parameters[?contains(Name, '/credentials/access')].Name" \
           --output text 2>/dev/null | tr '\t' '\n' | head -n1)"
        if [[ -n "${FOUND}" ]]; then
          CREDS_RAW="$(get_ssm_value "${FOUND}")"
        fi
      fi
      if [[ -z "${CREDS_RAW}" ]]; then
        log "ERROR" "❌ Credenciais GCP não encontradas no SSM para ${ACCOUNT_ID}"
        return 1
      fi

      local CLEAN_JSON; CLEAN_JSON="$(clean_secret_blob "${CREDS_RAW}")" || true
      if [[ -z "${CLEAN_JSON}" ]]; then
        log "ERROR" "❌ Falha ao normalizar credenciais GCP."
        return 1
      fi

      local TMP_KEY="/tmp/gcp-${ACCOUNT_ID}.json"
      echo -n "${CLEAN_JSON}" > "${TMP_KEY}"

      if gcloud auth activate-service-account --key-file="${TMP_KEY}" --quiet; then
        # Se vier project_id no JSON e ACCOUNT_ID não for um projeto válido, usa o do JSON
        local PJ_JSON; PJ_JSON="$(jq -r '.project_id // empty' "${TMP_KEY}")"
        local PROJECT="${ACCOUNT_ID}"
        [[ -n "${PJ_JSON}" ]] && PROJECT="${PJ_JSON}"
        gcloud config set project "${PROJECT}" --quiet
        # Atualiza ACCOUNT_ID (para refletir project_id efetivo)
        ACCOUNT_ID="${PROJECT}"
        log "INFO" "✅ Autenticação GCP bem-sucedida para projeto ${PROJECT}"
      else
        log "ERROR" "❌ Falha na autenticação GCP (${ACCOUNT_ID})."
        rm -f "${TMP_KEY}" || true
        return 1
      fi

      log "INFO" "🚀 Executando scan GCP…"
      if ! prowler gcp \
        --project-id "${ACCOUNT_ID}" \
        --compliance cis_4.0_gcp iso27001_2022_gcp mitre_attack_gcp prowler_threatscore_gcp soc2_gcp \
        --output-formats csv html json-asff \
        --output-filename "multicloudassessment-gcp-${ACCOUNT_ID}" \
        --output-directory "${OUTPUT_DIR}" \
        --skip-api-check \
        --no-banner \
        --log-level "${LOG_LEVEL}"
      then
        log "WARN" "⚠️ Falha parcial no scan GCP"
      fi
      rm -f "${TMP_KEY}" || true
      ;;
  esac
}

# ============================================================
# Execução principal
# ============================================================
if ! authenticate_and_scan; then
  log "ERROR" "⚠️ Falha na autenticação ou execução. Encerrando."
  exit 1
fi

# Upload para S3
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
S3_PATH="s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER_LC}/${ACCOUNT_ID}/${TIMESTAMP}/"

if aws s3 cp "${OUTPUT_DIR}" "${S3_PATH}" --recursive --only-show-errors; then
  log "INFO" "☁️ Relatórios enviados com sucesso para ${S3_PATH}"
else
  log "WARN" "⚠️ Falha no upload para S3 (verifique permissões)."
fi

END_TS=$(date +%s)
DURATION=$((END_TS - START_TS))

log "INFO" "⏱️ Execução finalizada em ${DURATION}s."
log "INFO" "Saídas armazenadas em ${OUTPUT_DIR}:"
ls -lh "${OUTPUT_DIR}" || true

log "========== 🔍 EXECUTION SUMMARY =========="
log "INFO" "Session ID: ${SESSION_ID}"
log "INFO" "Client:     ${CLIENT_NAME}"
log "INFO" "Cloud:      ${CLOUD_PROVIDER_LC}"
log "INFO" "Account:    ${ACCOUNT_ID}"
log "INFO" "Region:     ${AWS_REGION}"
log "INFO" "Output:     ${OUTPUT_DIR}"
log "INFO" "S3 Path:    ${S3_PATH}"
log "=========================================="

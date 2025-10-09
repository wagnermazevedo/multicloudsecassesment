#!/usr/bin/env bash
set -Eeuo pipefail

# ==========================================================
# Prowler Runner - MultiCloud + MultiAccount (root mode)
# Limpo de instaladores e sem caracteres especiais
# ==========================================================

echo "=== Iniciando execução do Prowler Runner ==="
date

# --- 1. Caminhos absolutos e variáveis padrão ---
PROWLER_BIN="/root/.pyenv/versions/3.11.13/bin/prowler"
AWS_BIN="/usr/local/bin/aws"
AZ_BIN="/usr/bin/az"
GCLOUD_BIN="/usr/bin/gcloud"
PWSH_BIN="/usr/bin/pwsh"

# --- 2. Verificações básicas ---
if [[ ! -x "$PROWLER_BIN" ]]; then
  echo "ERRO: Prowler não encontrado em $PROWLER_BIN"
  exit 127
fi

# --- 3. Variáveis obrigatórias ---
: "${CLOUD_PROVIDER:?ERRO: CLOUD_PROVIDER não definido (aws | azure | gcp)}"
: "${TARGET_ACCOUNTS:?ERRO: TARGET_ACCOUNTS não definido (IDs separados por vírgula ou ALL)}"

REGION="${AWS_REGION:-us-east-1}"
BUCKET="${S3_BUCKET:-my-prowler-results}"
TIMESTAMP="$(date +%Y%m%d%H%M)"
OUTPUT_DIR="/tmp"
OUTPUTS=()

# --- 4. Função para upload S3 ---
upload_to_s3() {
  local file="$1"
  local account="$2"
  local dest="s3://${BUCKET}/${CLOUD_PROVIDER}/${account}/${TIMESTAMP}/$(basename "$file")"
  echo "Enviando $file -> $dest"
  "$AWS_BIN" s3 cp "$file" "$dest" --acl bucket-owner-full-control || {
    echo "Falha no upload de $file"
    return 1
  }
}

# --- 5. Execução genérica ---
run_prowler_generic() {
  local provider="$1"
  local id="$2"
  shift 2
  local extra_args=( "$@" )

  echo "Executando Prowler para ${provider^^} -> $id"
  local out_file="${OUTPUT_DIR}/prowler-output-${id}-${TIMESTAMP}.json"

  "$PROWLER_BIN" "$provider" "${extra_args[@]}" \
    --output-formats json-asff \
    --output-filename "$(basename "$out_file" .json)" \
    --output-directory "$OUTPUT_DIR" \
    --ignore-exit-code-3

  if [[ -f "$out_file" ]]; then
    echo "Arquivo gerado: $out_file"
    OUTPUTS+=( "$out_file" )
    upload_to_s3 "$out_file" "$id"
  else
    echo "Arquivo não encontrado para $id"
  fi
}

# ==========================================================
# AWS
# ==========================================================
if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
  echo "Selecionado AWS"
  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    TARGET_ACCOUNTS="$("$AWS_BIN" ssm get-parameter \
      --name "/prowler/aws/accounts" \
      --query "Parameter.Value" \
      --output text)"
  fi

  for ACCOUNT_ID in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    echo "Conta alvo: $ACCOUNT_ID"

    CREDS="$("$AWS_BIN" sts assume-role \
      --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/ProwlerAuditRole" \
      --role-session-name "prowler-session")"

    export AWS_ACCESS_KEY_ID="$(echo "$CREDS" | jq -r .Credentials.AccessKeyId)"
    export AWS_SECRET_ACCESS_KEY="$(echo "$CREDS" | jq -r .Credentials.SecretAccessKey)"
    export AWS_SESSION_TOKEN="$(echo "$CREDS" | jq -r .Credentials.SessionToken)"

    run_prowler_generic aws "$ACCOUNT_ID" --region "$REGION"

    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  done
fi

# ==========================================================
# Azure
# ==========================================================
if [[ "$CLOUD_PROVIDER" == "azure" ]]; then
  echo "Selecionado Azure"
  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    TARGET_ACCOUNTS="$("$AWS_BIN" ssm get-parameter \
      --name "/prowler/azure/subscriptions" \
      --query "Parameter.Value" \
      --output text)"
  fi

  for SUB in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    echo "Subscription alvo: $SUB"
    run_prowler_generic azure "$SUB" --subscription-id "$SUB"
  done
fi

# ==========================================================
# GCP
# ==========================================================
if [[ "$CLOUD_PROVIDER" == "gcp" ]]; then
  echo "Selecionado GCP"
  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    TARGET_ACCOUNTS="$("$AWS_BIN" ssm get-parameter \
      --name "/prowler/gcp/projects" \
      --query "Parameter.Value" \
      --output text)"
  fi

  echo "Recuperando credenciais de service account..."
  "$AWS_BIN" ssm get-parameter \
    --name "/prowler/gcp/michel/serviceAccountKey" \
    --with-decryption \
    --query "Parameter.Value" \
    --output text | base64 -d > /tmp/prowler-sa.json

  export GOOGLE_APPLICATION_CREDENTIALS="/tmp/prowler-sa.json"

  for PROJECT in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    run_prowler_generic gcp "$PROJECT" --project-id "$PROJECT"
  done
fi

# ==========================================================
# Resumo final
# ==========================================================
echo "=== Execução finalizada. Relatórios gerados: ==="
printf '%s\n' "${OUTPUTS[@]}"

# ==========================================================
# Debug hold opcional
# ==========================================================
if [[ "${PROWLER_DEBUG:-0}" == "1" ]]; then
  echo "PROWLER_DEBUG=1 ativo. O container permanecerá em execução para debug."
  tail -f /dev/null
fi


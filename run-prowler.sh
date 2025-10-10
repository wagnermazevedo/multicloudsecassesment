#!/bin/bash
set -euo pipefail

echo "[RUNNER] Iniciando execução do Prowler Runner"

# Localiza o binário do Prowler
if command -v prowler >/dev/null 2>&1; then
  PROWLER_BIN="$(command -v prowler)"
else
  PROWLER_BIN=$(find /home/prowler/.cache/pypoetry/virtualenvs -type f -name "prowler" | head -n 1 || true)
fi

if [ -z "$PROWLER_BIN" ]; then
  echo "[RUNNER] ERRO: Não foi possível localizar o binário do Prowler!"
  exit 1
else
  echo "[RUNNER] Prowler encontrado em: $PROWLER_BIN"
fi

# Verifica variáveis obrigatórias
: "${CLOUD_PROVIDER:?ERRO: CLOUD_PROVIDER não definido (aws | azure | gcp)}"
: "${TARGET_ACCOUNTS:?ERRO: TARGET_ACCOUNTS não definido (IDs separados por vírgula ou ALL)}"

REGION="${AWS_REGION:-us-east-1}"
BUCKET="${S3_BUCKET:-my-prowler-results}"
TIMESTAMP="$(date +%Y%m%d%H%M)"
OUTPUT_DIR="/tmp"
OUTPUTS=()

CLOUD_PROVIDER="$(echo "$CLOUD_PROVIDER" | tr '[:upper:]' '[:lower:]')"

# Upload S3
upload_to_s3() {
  local file="$1"
  local account="$2"
  local dest="s3://${BUCKET}/${CLOUD_PROVIDER}/${account}/${TIMESTAMP}/$(basename "$file")"
  echo "[RUNNER] Upload para $dest"
  aws s3 cp "$file" "$dest" --acl bucket-owner-full-control || {
    echo "[RUNNER] Falha no upload de $file"
    return 1
  }
}

# Execução genérica
run_prowler_generic() {
  local provider="$1"
  local id="$2"
  shift 2
  local extra_args=( "$@" )

  echo "[RUNNER] Executando Prowler para ${provider^^} → $id"
  local out_file="${OUTPUT_DIR}/prowler-output-${id}-${TIMESTAMP}.json"

  "$PROWLER_BIN" "$provider" "${extra_args[@]}" \
    --output-formats json-asff \
    --output-filename "$(basename "$out_file" .json)" \
    --output-directory "$OUTPUT_DIR" \
    --ignore-exit-code-3

  if [[ -f "$out_file" ]]; then
    echo "[RUNNER] Arquivo gerado: $out_file"
    OUTPUTS+=( "$out_file" )
    upload_to_s3 "$out_file" "$id"
  else
    echo "[RUNNER] Arquivo não encontrado para $id"
  fi
}

# AWS
if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
  echo "[RUNNER] Selecionado AWS"
  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    TARGET_ACCOUNTS="$(aws ssm get-parameter --name "/prowler/aws/accounts" --query "Parameter.Value" --output text)"
  fi
  for ACCOUNT_ID in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    CREDS="$(aws sts assume-role --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/ProwlerAuditRole" --role-session-name "prowler-session")"
    export AWS_ACCESS_KEY_ID="$(echo "$CREDS" | jq -r .Credentials.AccessKeyId)"
    export AWS_SECRET_ACCESS_KEY="$(echo "$CREDS" | jq -r .Credentials.SecretAccessKey)"
    export AWS_SESSION_TOKEN="$(echo "$CREDS" | jq -r .Credentials.SessionToken)"
    run_prowler_generic aws "$ACCOUNT_ID" --region "$REGION"
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  done
fi

# Azure
if [[ "$CLOUD_PROVIDER" == "azure" ]]; then
  echo "[RUNNER] Selecionado Azure"
  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    TARGET_ACCOUNTS="$(aws ssm get-parameter --name "/prowler/azure/subscriptions" --query "Parameter.Value" --output text)"
  fi
  for SUB in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    run_prowler_generic azure "$SUB" --subscription-id "$SUB"
  done
fi

# GCP
if [[ "$CLOUD_PROVIDER" == "gcp" ]]; then
  echo "[RUNNER] Selecionado GCP"
  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    TARGET_ACCOUNTS="$(aws ssm get-parameter --name "/prowler/gcp/projects" --query "Parameter.Value" --output text)"
  fi
  aws ssm get-parameter \
    --name "/prowler/gcp/michel/serviceAccountKey" \
    --with-decryption \
    --query "Parameter.Value" \
    --output text | base64 -d > /tmp/prowler-sa.json
  export GOOGLE_APPLICATION_CREDENTIALS="/tmp/prowler-sa.json"
  for PROJECT in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    run_prowler_generic gcp "$PROJECT" --project-id "$PROJECT"
  done
fi

echo "[RUNNER] Execução finalizada. Relatórios gerados:"
printf '%s\n' "${OUTPUTS[@]}"

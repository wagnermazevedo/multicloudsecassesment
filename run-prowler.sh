#!/bin/bash
set -euo pipefail

# === PATH FIX ===
export PATH="/usr/local/bin:/home/prowler/.local/bin:${PATH}"

echo "🛰️  === Iniciando execução do Prowler Runner ==="

# === VARIÁVEIS OBRIGATÓRIAS (validação manual para mensagens amigáveis) ===
: "${CLOUD_PROVIDER:?❌ CLOUD_PROVIDER não definido (aws | azure | gcp)}"
: "${TARGET_ACCOUNTS:?❌ TARGET_ACCOUNTS não definido (IDs separados por vírgula ou ALL)}"

REGION="${AWS_REGION:-us-east-1}"
BUCKET="my-prowler-results"
TIMESTAMP=$(date +%Y%m%d%H%M)
OUTPUT_DIR="/tmp"
OUTPUTS=()

# Normaliza cloud provider (case insensitive)
CLOUD_PROVIDER=$(echo "$CLOUD_PROVIDER" | tr '[:upper:]' '[:lower:]')

# === Função de upload para S3 ===
upload_to_s3() {
  local file="$1"
  local account="$2"
  local dest="s3://${BUCKET}/${CLOUD_PROVIDER}/${account}/${TIMESTAMP}/$(basename "$file")"
  echo "📤 Enviando $file → $dest"
  aws s3 cp "$file" "$dest" --acl bucket-owner-full-control || {
    echo "❌ Falha no upload de $file"
    return 1
  }
}

# === Verifica se Prowler está disponível ===
if ! command -v prowler >/dev/null 2>&1; then
  echo "⚠️  Prowler não encontrado no PATH (${PATH})"
  exit 1
fi

# === Função para execução genérica ===
run_prowler_generic() {
  local provider="$1"
  local id="$2"
  local extra_args=("${@:3}")

  echo "🚀 Executando Prowler para ${provider^^} → $id"
  local OUT_FILE="${OUTPUT_DIR}/prowler-output-${id}-${TIMESTAMP}.json"

  prowler "$provider" "${extra_args[@]}" \
    --output-formats json-asff \
    --output-filename "$(basename "$OUT_FILE" .json)" \
    --output-directory "$OUTPUT_DIR" \
    --ignore-exit-code-3

  if [[ -f "$OUT_FILE" ]]; then
    echo "✅ Arquivo gerado: $OUT_FILE"
    OUTPUTS+=("$OUT_FILE")
    upload_to_s3 "$OUT_FILE" "$id"
  else
    echo "❌ Arquivo não encontrado para $id"
  fi
}

# === AWS ===
if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
  echo "☁️  Selecionado AWS"

  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    echo "🔎 Buscando contas AWS no SSM..."
    TARGET_ACCOUNTS=$(aws ssm get-parameter \
      --name "/prowler/aws/accounts" \
      --query "Parameter.Value" \
      --output text)
  fi

  for ACCOUNT_ID in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    echo "🎯 Conta alvo: $ACCOUNT_ID"
    CREDS=$(aws sts assume-role \
      --role-arn arn:aws:iam::${ACCOUNT_ID}:role/ProwlerAuditRole \
      --role-session-name prowler-session)

    export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r .Credentials.AccessKeyId)
    export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r .Credentials.SecretAccessKey)
    export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r .Credentials.SessionToken)

    run_prowler_generic aws "$ACCOUNT_ID" --region "$REGION"

    # Limpa credenciais da conta anterior
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  done
fi

# === AZURE ===
if [[ "$CLOUD_PROVIDER" == "azure" ]]; then
  echo "☁️  Selecionado Azure"

  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    echo "🔎 Buscando subscriptions Azure no SSM..."
    TARGET_ACCOUNTS=$(aws ssm get-parameter \
      --name "/prowler/azure/subscriptions" \
      --query "Parameter.Value" \
      --output text)
  fi

  for SUB in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    run_prowler_generic azure "$SUB" --subscription-id "$SUB"
  done
fi

# === GCP ===
if [[ "$CLOUD_PROVIDER" == "gcp" ]]; then
  echo "☁️  Selecionado GCP"

  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    echo "🔎 Buscando projetos GCP no SSM..."
    TARGET_ACCOUNTS=$(aws ssm get-parameter \
      --name "/prowler/gcp/projects" \
      --query "Parameter.Value" \
      --output text)
  fi

  echo "🔑 Recuperando credenciais de service account..."
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

echo "🧾 === Execução finalizada. Relatórios gerados: ==="
printf '%s\n' "${OUTPUTS[@]}"

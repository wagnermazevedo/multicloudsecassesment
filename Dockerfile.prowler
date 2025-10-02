#!/bin/bash
set -euo pipefail

echo "=== Iniciando execução do Prowler Runner ==="

# === VARIÁVEIS OBRIGATÓRIAS ===
CLOUD_PROVIDER=${CLOUD_PROVIDER:?Informe a nuvem alvo: aws | azure | gcp}
TARGET_ACCOUNTS=${TARGET_ACCOUNTS:?Informe contas/IDs separados por vírgula ou ALL}
REGION=${AWS_REGION:-us-east-1}
BUCKET="my-prowler-results"

# === CONTROLE DE TEMPO / ARQUIVOS ===
TIMESTAMP=$(date +%Y%m%d%H%M)
OUTPUT_DIR="/tmp"
OUTPUTS=()

# Normaliza cloud provider (case insensitive)
CLOUD_PROVIDER=$(echo "$CLOUD_PROVIDER" | tr '[:upper:]' '[:lower:]')

# === FUNÇÃO PARA ENVIAR RESULTADOS PARA S3 ===
upload_to_s3 () {
  local file="$1"
  local account="$2"
  local dest="s3://${BUCKET}/${CLOUD_PROVIDER}/${account}/${TIMESTAMP}/$(basename "$file")"

  echo "=== Upload de $file para $dest ==="
  aws s3 cp "$file" "$dest" --acl bucket-owner-full-control || {
    echo "❌ Falha no upload de $file"
    exit 1
  }
}

# === TRATAMENTO PARA AWS ===
if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
  echo "=== Selecionado AWS ==="

  # Se ALL → buscar lista de contas no SSM
  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    echo "Buscando lista de contas AWS no Parameter Store..."
    TARGET_ACCOUNTS=$(aws ssm get-parameter \
      --name "/prowler/aws/accounts" \
      --query "Parameter.Value" \
      --output text)
  fi

  for ACCOUNT_ID in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    echo "--- Rodando Prowler para conta $ACCOUNT_ID ---"

    CREDS=$(aws sts assume-role \
      --role-arn arn:aws:iam::${ACCOUNT_ID}:role/ProwlerAuditRole \
      --role-session-name prowler-session)

    export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r .Credentials.AccessKeyId)
    export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r .Credentials.SecretAccessKey)
    export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r .Credentials.SessionToken)

    OUT_FILE="${OUTPUT_DIR}/prowler-output-${ACCOUNT_ID}-${TIMESTAMP}.asff.json"

    prowler aws \
      --region "${REGION}" \
      --output-formats json-asff \
      --output-filename "$(basename "$OUT_FILE" .json)" \
      --output-directory "${OUTPUT_DIR}" \
      --ignore-exit-code-3

    if [[ -f "$OUT_FILE" ]]; then
      echo "✅ Arquivo gerado: $OUT_FILE"
      OUTPUTS+=("$OUT_FILE")
      upload_to_s3 "$OUT_FILE" "$ACCOUNT_ID"
    else
      echo "❌ Arquivo não encontrado para conta $ACCOUNT_ID"
    fi
  done
fi

# === TRATAMENTO PARA AZURE ===
if [[ "$CLOUD_PROVIDER" == "azure" ]]; then
  echo "=== Selecionado Azure ==="

  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    echo "Buscando lista de subscriptions Azure no Parameter Store..."
    TARGET_ACCOUNTS=$(aws ssm get-parameter \
      --name "/prowler/azure/subscriptions" \
      --query "Parameter.Value" \
      --output text)
  fi

  for SUB in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    echo "--- Rodando Prowler para subscription $SUB ---"

    OUT_FILE="${OUTPUT_DIR}/prowler-output-${SUB}-${TIMESTAMP}.asff.json"

    prowler azure \
      --subscription-id "$SUB" \
      --output-formats json-asff \
      --output-filename "$(basename "$OUT_FILE" .json)" \
      --output-directory "${OUTPUT_DIR}" \
      --ignore-exit-code-3

    if [[ -f "$OUT_FILE" ]]; then
      echo "✅ Arquivo gerado: $OUT_FILE"
      OUTPUTS+=("$OUT_FILE")
      upload_to_s3 "$OUT_FILE" "$SUB"
    else
      echo "❌ Arquivo não encontrado para subscription $SUB"
    fi
  done
fi

# === TRATAMENTO PARA GCP ===
if [[ "$CLOUD_PROVIDER" == "gcp" ]]; then
  echo "=== Selecionado GCP ==="

  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    echo "Buscando lista de projetos GCP no Parameter Store..."
    TARGET_ACCOUNTS=$(aws ssm get-parameter \
      --name "/prowler/gcp/projects" \
      --query "Parameter.Value" \
      --output text)
  fi

  # Recupera chave de service account do SSM
  aws ssm get-parameter \
    --name "/prowler/gcp/michel/serviceAccountKey" \
    --with-decryption \
    --query "Parameter.Value" \
    --output text | base64 -d > /tmp/prowler-sa.json

  export GOOGLE_APPLICATION_CREDENTIALS="/tmp/prowler-sa.json"

  for PROJECT in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    echo "--- Rodando Prowler para projeto $PROJECT ---"

    OUT_FILE="${OUTPUT_DIR}/prowler-output-${PROJECT}-${TIMESTAMP}.asff.json"

    prowler gcp \
      --project-id "$PROJECT" \
      --output-formats json-asff \
      --output-filename "$(basename "$OUT_FILE" .json)" \
      --output-directory "${OUTPUT_DIR}" \
      --ignore-exit-code-3

    if [[ -f "$OUT_FILE" ]]; then
      echo "✅ Arquivo gerado: $OUT_FILE"
      OUTPUTS+=("$OUT_FILE")
      upload_to_s3 "$OUT_FILE" "$PROJECT"
    else
      echo "❌ Arquivo não encontrado para projeto $PROJECT"
    fi
  done
fi

echo "=== Execução finalizada. Relatórios gerados: ==="
printf '%s\n' "${OUTPUTS[@]}"

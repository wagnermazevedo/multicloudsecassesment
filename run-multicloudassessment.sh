#!/bin/bash
set -euo pipefail
#### version 2.1
echo "[RUNNER] Iniciando execução do Multicloud Assessment Runner"

# ==============================
# 1️⃣ VARIÁVEIS DE AMBIENTE
# ==============================
CLIENT_NAME="${CLIENT_NAME:-unknown_client}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-aws}"
ACCOUNT_ID="${ACCOUNT_ID:-none}"
AWS_REGION="${AWS_REGION:-us-east-1}"
S3_BUCKET="${S3_BUCKET:-multicloud-assessments}"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")

OUTPUT_DIR="/tmp/output-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

echo "[RUNNER] Cliente: $CLIENT_NAME"
echo "[RUNNER] Cloud: $CLOUD_PROVIDER"
echo "[RUNNER] Accounts: $ACCOUNT_ID"
echo "[RUNNER] Região AWS: $AWS_REGION"
echo "[RUNNER] Bucket de destino: $S3_BUCKET"
echo "[RUNNER] Diretório de saída: $OUTPUT_DIR"
echo "--------------------------------------------------"

# ==============================
# 2️⃣ LOCALIZAÇÃO DO PROWLER
# ==============================
VENV_PATH=$(find /home/prowler/.cache/pypoetry/virtualenvs -type d -name "prowler-*-py3.*" | head -n 1 || true)
if [ -n "$VENV_PATH" ]; then
  export PATH="$VENV_PATH/bin:$PATH"
fi

PROWLER_PATH=$(command -v prowler || true)
if [ -z "$PROWLER_PATH" ]; then
  echo "[ERRO] O binário do Prowler não foi encontrado no PATH."
  exit 1
else
  echo "[RUNNER] Prowler detectado em: $PROWLER_PATH"
fi
echo "--------------------------------------------------"

# ==============================
# 3️⃣ FUNÇÕES AUXILIARES
# ==============================

get_param() {
  aws ssm get-parameter --name "$1" --with-decryption --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

fetch_credentials() {
  local path="/clients/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/credentials/access"
  echo "[RUNNER] 🔹 Buscando credenciais em $path"
  get_param "$path"
}

authenticate() {
  local creds
  creds=$(fetch_credentials)
  case "$CLOUD_PROVIDER" in
    aws)
      echo "$creds" | base64 -d > /tmp/aws_creds.json
      export AWS_ACCESS_KEY_ID=$(jq -r '.AWS_ACCESS_KEY_ID' /tmp/aws_creds.json)
      export AWS_SECRET_ACCESS_KEY=$(jq -r '.AWS_SECRET_ACCESS_KEY' /tmp/aws_creds.json)
      export AWS_SESSION_TOKEN=$(jq -r '.AWS_SESSION_TOKEN' /tmp/aws_creds.json)
      ;;
    azure)
      echo "$creds" | base64 -d > /etc/prowler/credentials/azure.env
      source /etc/prowler/credentials/azure.env
      az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID" >/dev/null
      ;;
    gcp)
      echo "$creds" | base64 -d > /root/.config/gcloud/application_default_credentials.json
      ;;
  esac
}

run_for_account() {
  local account_id="$1"
  local output_file="${OUTPUT_DIR}/${CLOUD_PROVIDER}_${account_id}_${TIMESTAMP}.json"
  echo "[RUNNER] ▶️ Iniciando varredura para $CLOUD_PROVIDER ($account_id)..."

  case "$CLOUD_PROVIDER" in
    aws)
      prowler aws --account-id "$account_id" -M json-asff -o "$output_file" || echo "[WARN] Falha parcial na conta $account_id"
      ;;
    azure)
      prowler azure -M json -o "$output_file" || echo "[WARN] Falha parcial na subscrição $account_id"
      ;;
    gcp)
      prowler gcp --project-ids "$account_id" -M json -o "$output_file" || echo "[WARN] Falha parcial no projeto $account_id"
      ;;
    *)
      echo "[ERRO] Provedor de nuvem não suportado: $CLOUD_PROVIDER"
      exit 1
      ;;
  esac

  if [ -f "$output_file" ]; then
    echo "[RUNNER] Resultado salvo em: $output_file"
    upload_to_s3 "$account_id"
  else
    echo "[ERRO] Nenhum resultado gerado para $account_id"
  fi
}

upload_to_s3() {
  local account_id="$1"
  local s3_prefix="${CLIENT_NAME}/${CLOUD_PROVIDER}/${account_id}/${TIMESTAMP}"
  echo "[RUNNER] 📤 Enviando resultados para s3://${S3_BUCKET}/${s3_prefix}/"
  aws s3 cp "$OUTPUT_DIR" "s3://${S3_BUCKET}/${s3_prefix}/" --recursive --region "$AWS_REGION"
  echo "[RUNNER] ✅ Upload concluído para $account_id."
  echo "--------------------------------------------------"
}

# ==============================
# 4️⃣ EXECUÇÃO DO SCAN
# ==============================
IFS=',' read -ra ACCOUNTS <<< "$ACCOUNT_ID"
TOTAL=${#ACCOUNTS[@]}
INDEX=1

authenticate

echo "[RUNNER] Detectadas ${TOTAL} contas para análise."
echo "--------------------------------------------------"

for acc in "${ACCOUNTS[@]}"; do
  acc_trimmed=$(echo "$acc" | xargs)
  echo "[RUNNER] ▶️ [$INDEX/$TOTAL] Iniciando $acc_trimmed..."
  run_for_account "$acc_trimmed"
  PERCENT=$((INDEX * 100 / TOTAL))
  echo "[RUNNER] ✅ Progresso: ${PERCENT}% concluído"
  ((INDEX++))
done

# ==============================
# 5️⃣ FINALIZAÇÃO
# ==============================
echo "[RUNNER] ✅ Todos os scans concluídos com sucesso."
echo "[RUNNER] Resultados enviados para o bucket S3: $S3_BUCKET"

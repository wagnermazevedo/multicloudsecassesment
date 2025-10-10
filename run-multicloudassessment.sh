#!/bin/bash
set -euo pipefail
#### version 2.0
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
run_for_account() {
  local account_id="$1"
  local output_file="${OUTPUT_DIR}/${CLOUD_PROVIDER}_${account_id}_${TIMESTAMP}.json"
  echo "[RUNNER] [$(date +%H:%M:%S)] Iniciando varredura para conta $account_id..."

  case "$CLOUD_PROVIDER" in
    aws)
      prowler aws --account-id "$account_id" -M json-asff -o "$output_file" || echo "[WARN] Falha parcial na conta $account_id"
      ;;
    azure)
      prowler azure -M json -o "$output_file" || echo "[WARN] Falha parcial na subscrição $account_id"
      ;;
    gcp)
      prowler gcp -M json -o "$output_file" || echo "[WARN] Falha parcial no projeto $account_id"
      ;;
    *)
      echo "[ERRO] Provedor de nuvem não suportado: $CLOUD_PROVIDER"
      exit 1
      ;;
  esac

  if [ -f "$output_file" ]; then
    echo "[RUNNER] Resultado salvo em: $output_file"
  else
    echo "[ERRO] Nenhum resultado gerado para $account_id"
  fi
}

upload_to_s3() {
  local account_id="$1"
  local s3_prefix="${CLIENT_NAME}/${CLOUD_PROVIDER}/${account_id}/${TIMESTAMP}"
  echo "[RUNNER] Enviando resultados para s3://${S3_BUCKET}/${s3_prefix}/"
  aws s3 cp "$OUTPUT_DIR" "s3://${S3_BUCKET}/${s3_prefix}/" --recursive --region "$AWS_REGION"
  echo "[RUNNER] Upload concluído para $account_id."
  echo "--------------------------------------------------"
}

# ==============================
# 4️⃣ EXECUÇÃO DO SCAN (LOOP MULTI-CONTA)
# ==============================
IFS=',' read -ra ACCOUNTS <<< "$ACCOUNT_ID"
TOTAL=${#ACCOUNTS[@]}
INDEX=1

echo "[RUNNER] Detectadas ${TOTAL} contas para análise."
echo "--------------------------------------------------"

for acc in "${ACCOUNTS[@]}"; do
  acc_trimmed=$(echo "$acc" | xargs)
  echo "[RUNNER] ▶️ [$INDEX/$TOTAL] Iniciando conta $acc_trimmed..."
  run_for_account "$acc_trimmed"
  upload_to_s3 "$acc_trimmed"

  PERCENT=$((INDEX * 100 / TOTAL))
  echo "[RUNNER] ✅ Progresso: ${PERCENT}% concluído"
  ((INDEX++))
done

# ==============================
# 5️⃣ FINALIZAÇÃO
# ==============================
echo "[RUNNER] ✅ Todos os scans concluídos com sucesso."
echo "[RUNNER] Resultados enviados para o bucket S3: $S3_BUCKET"

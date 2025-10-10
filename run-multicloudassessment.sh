#!/bin/bash
set -euo pipefail

echo "[RUNNER] Iniciando execução do MultiCloud Assessment"

# ===========================
# Variáveis de ambiente
# ===========================
CLIENT_NAME="${CLIENT_NAME:-undefined}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-undefined}"
ACCOUNT_ID="${ACCOUNT_ID:-undefined}"
S3_BUCKET="${S3_BUCKET:-multicloud-assessments}"
AWS_REGION="${AWS_REGION:-us-east-1}"
LOG_PATH="/home/prowler/logs"
RESULTS_PATH="/home/prowler/results"

mkdir -p "$LOG_PATH" "$RESULTS_PATH"

echo "[RUNNER] CLIENT_NAME........: $CLIENT_NAME"
echo "[RUNNER] CLOUD_PROVIDER.....: $CLOUD_PROVIDER"
echo "[RUNNER] ACCOUNT_ID.........: $ACCOUNT_ID"
echo "[RUNNER] REGION.............: $AWS_REGION"
echo "[RUNNER] S3_BUCKET..........: $S3_BUCKET"

# ===========================
# Validações básicas
# ===========================
if [[ "$CLIENT_NAME" == "undefined" || "$CLOUD_PROVIDER" == "undefined" || "$ACCOUNT_ID" == "undefined" ]]; then
    echo "[ERRO] Variáveis obrigatórias não definidas (CLIENT_NAME, CLOUD_PROVIDER, ACCOUNT_ID)."
    exit 1
fi

# ===========================
# Função para obter contas do Parameter Store
# ===========================
get_accounts_from_ssm() {
    local client="$1"
    local cloud="$2"
    aws ssm get-parameter \
        --name "/clients/${client}/${cloud}/accounts" \
        --query "Parameter.Value" \
        --output text \
        --region "$AWS_REGION" 2>/dev/null || true
}

# ===========================
# Resolve lista de contas
# ===========================
if [[ "$ACCOUNT_ID" == "all" || "$ACCOUNT_ID" == "ALL" ]]; then
    echo "[RUNNER] Coletando todas as contas do cliente '$CLIENT_NAME' e provedor '$CLOUD_PROVIDER'..."
    ACCOUNT_ID=$(get_accounts_from_ssm "$CLIENT_NAME" "$CLOUD_PROVIDER")
    if [[ -z "$ACCOUNT_ID" ]]; then
        echo "[ERRO] Nenhum registro encontrado no Parameter Store."
        exit 1
    fi
fi

IFS=',' read -ra ACCOUNT_ARRAY <<< "$ACCOUNT_ID"

# ===========================
# Detecta Prowler binário
# ===========================
PROWLER_BIN=$(find /home/prowler/.cache/pypoetry/virtualenvs -type f -name prowler -perm -111 2>/dev/null | head -n1)
if [[ -z "$PROWLER_BIN" ]]; then
    PROWLER_BIN=$(command -v prowler || true)
fi

if [[ -z "$PROWLER_BIN" ]]; then
    echo "[ERRO] Binário do prowler não encontrado!"
    exit 1
fi

echo "[RUNNER] Binário encontrado: $PROWLER_BIN"

# ===========================
# Loop de execução por conta
# ===========================
for acc in "${ACCOUNT_ARRAY[@]}"; do
    acc_trim=$(echo "$acc" | xargs)
    echo "----------------------------------------------"
    echo "[RUNNER] Iniciando scan para conta: $acc_trim"
    echo "----------------------------------------------"

    OUTPUT_DIR="${RESULTS_PATH}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${acc_trim}"
    mkdir -p "$OUTPUT_DIR"

    case "$CLOUD_PROVIDER" in
        aws)
            $PROWLER_BIN aws \
              -A "$acc_trim" \
              -R "$AWS_REGION" \
              -M json,json-asff,csv \
              -o "$OUTPUT_DIR" \
              --quiet
            ;;
        azure)
            $PROWLER_BIN azure \
              --subscription-ids "$acc_trim" \
              -M json,csv \
              -o "$OUTPUT_DIR" \
              --quiet
            ;;
        gcp)
            $PROWLER_BIN gcp \
              --project-ids "$acc_trim" \
              -M json,csv \
              -o "$OUTPUT_DIR" \
              --quiet
            ;;
        *)
            echo "[ERRO] Provedor não suportado: $CLOUD_PROVIDER"
            exit 1
            ;;
    esac

    echo "[RUNNER] Upload para S3: s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${acc_trim}/"
    aws s3 sync "$OUTPUT_DIR" "s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${acc_trim}/" --region "$AWS_REGION" || true

    echo "[RUNNER] Finalizado: $acc_trim"
done

echo "[RUNNER] Todos os scans concluídos com sucesso."

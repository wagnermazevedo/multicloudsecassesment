#!/bin/bash
set -euo pipefail

# ============================================================
# 🔧 FIX DEFINITIVO: Garante que o binário do Prowler seja localizado
# mesmo que o PATH do container não carregue automaticamente o virtualenv
# ============================================================

# Caminho base e PATH padrão
export PATH="/home/prowler/.local/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
cd /home/prowler/prowler || {
    echo "❌ Diretório /home/prowler/prowler não encontrado."
    exit 1
}

# Detecta virtualenv do Poetry e adiciona ao PATH
if [ -d "/home/prowler/.cache/pypoetry/virtualenvs" ]; then
    VENV_PATH=$(find /home/prowler/.cache/pypoetry/virtualenvs -maxdepth 1 -type d -name "prowler*" | head -n 1 || true)
    if [ -n "$VENV_PATH" ]; then
        export PATH="$VENV_PATH/bin:$PATH"
        echo "✅ Virtualenv detectado e adicionado ao PATH: $VENV_PATH"
    else
        echo "⚠️ Nenhum virtualenv encontrado em ~/.cache/pypoetry/virtualenvs"
    fi
else
    echo "⚠️ Diretório ~/.cache/pypoetry/virtualenvs não encontrado"
fi

# Diagnóstico
echo "🔧 PATH atual: $PATH"
if ! command -v prowler &>/dev/null; then
    echo "⚠️ prowler ainda não acessível — tentando localizar manualmente..."
    PWL_BIN=$(find /home/prowler/.cache/pypoetry/virtualenvs -type f -name prowler | head -n 1 || true)
    if [ -n "$PWL_BIN" ]; then
        echo "✅ Encontrado binário: $PWL_BIN"
        alias prowler="$PWL_BIN"
        export PATH="$(dirname "$PWL_BIN"):$PATH"
    else
        echo "❌ Erro crítico: 'prowler' não encontrado em nenhum caminho válido."
        exit 127
    fi
fi

echo "✅ Prowler pronto para uso: $(command -v prowler)"
prowler --version || echo "⚠️ Não foi possível exibir a versão do prowler."

echo "🛰️ === Iniciando execução do Prowler Runner ==="
echo "📂 Diretório atual: $(pwd)"
echo "👤 Usuário atual: $(whoami)"

# ============================================================
# 🌩️ VARIÁVEIS OBRIGATÓRIAS
# ============================================================
: "${CLOUD_PROVIDER:?❌ CLOUD_PROVIDER não definido (aws | azure | gcp)}"
: "${TARGET_ACCOUNTS:?❌ TARGET_ACCOUNTS não definido (IDs separados por vírgula ou ALL)}"

REGION="${AWS_REGION:-us-east-1}"
BUCKET="my-prowler-results"
TIMESTAMP=$(date +%Y%m%d%H%M)
OUTPUT_DIR="/tmp"
OUTPUTS=()

CLOUD_PROVIDER=$(echo "$CLOUD_PROVIDER" | tr '[:upper:]' '[:lower:]')

# ============================================================
# 📤 Função: Upload para S3
# ============================================================
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

# ============================================================
# 🚀 Função: Execução Genérica do Prowler
# ============================================================
run_prowler_generic() {
    local provider="$1"
    local id="$2"
    shift 2
    local extra_args=("$@")

    echo "🚀 Executando Prowler para ${provider^^} → $id"
    local OUT_FILE="${OUTPUT_DIR}/prowler-output-${id}-${TIMESTAMP}.json"

    # Diagnóstico do ambiente
    echo "🧭 Verificação de ambiente..."
    echo "PWD: $(pwd)"
    echo "PATH: $PATH"
    echo "Arquivos em /home/prowler:"
    ls -la /home/prowler | head -n 10
    echo "🔍 Procurando binário do Prowler..."
    find /home/prowler/.cache/pypoetry -type f -name "prowler" | head -n 3

    # Execução principal
    /home/prowler/.cache/pypoetry/virtualenvs/prowler*/bin/prowler "$provider" "${extra_args[@]}" \
        --output-formats json-asff \
        --output-filename "$(basename "$OUT_FILE" .json)" \
        --output-directory "$OUTPUT_DIR" \
        --ignore-exit-code-3

    # Upload e verificação
    if [[ -f "$OUT_FILE" ]]; then
        echo "✅ Arquivo gerado: $OUT_FILE"
        OUTPUTS+=("$OUT_FILE")
        upload_to_s3 "$OUT_FILE" "$id"
    else
        echo "❌ Arquivo não encontrado para $id"
    fi
}

# ============================================================
# ☁️ Execução por Provedor
# ============================================================

# --- AWS ---
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

        unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    done
fi

# --- AZURE ---
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

# --- GCP ---
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

# ============================================================
# 🧾 Resumo final
# ============================================================
echo "🧾 === Execução finalizada. Relatórios gerados: ==="
printf '%s\n' "${OUTPUTS[@]}"

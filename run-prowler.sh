#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# 🛰️ Prowler Runner – multicloud e multiaccount (Pyenv-safe)
# ============================================================

# Caminho padrão onde o Prowler e outros binários Python ficam
PYENV_PATH=$(find /root/.pyenv/versions -maxdepth 1 -type d | sort -r | head -n 1)
PROWLER_BIN="${PYENV_PATH}/bin/prowler"

# Diagnóstico inicial
echo "=== Iniciando execução do Prowler Runner ==="
echo "📂 Diretório atual: $(pwd)"
echo "👤 Usuário atual: $(whoami)"
echo "🔧 Binário do Prowler: $PROWLER_BIN"

# Validação
if [[ ! -x "$PROWLER_BIN" ]]; then
    echo "❌ Prowler não encontrado em ${PROWLER_BIN}"
    echo "🔍 Tentando localizar fallback..."
    PROWLER_BIN=$(find /root/.pyenv -type f -name prowler | head -n 1 || true)
    if [[ -z "$PROWLER_BIN" ]]; then
        echo "❌ Nenhum binário do Prowler encontrado. Abortando."
        exit 127
    fi
    echo "✅ Fallback localizado: $PROWLER_BIN"
fi

# Mostrar versão
"$PROWLER_BIN" --version || echo "⚠️ Não foi possível exibir a versão do Prowler."

# ============================================================
# 🌩️ Variáveis obrigatórias
# ============================================================
: "${CLOUD_PROVIDER:?❌ CLOUD_PROVIDER não definido (aws | azure | gcp)}"
: "${TARGET_ACCOUNTS:?❌ TARGET_ACCOUNTS não definido (IDs separados por vírgula ou ALL)}"

REGION="${AWS_REGION:-us-east-1}"
BUCKET="my-prowler-results"
TIMESTAMP="$(date +%Y%m%d%H%M)"
OUTPUT_DIR="/tmp"
OUTPUTS=()

CLOUD_PROVIDER="$(echo "$CLOUD_PROVIDER" | tr '[:upper:]' '[:lower:]')"

# ============================================================
# 📤 Função de upload S3
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
# 🚀 Função de execução genérica
# ============================================================
run_prowler_generic() {
    local provider="$1"
    local id="$2"
    shift 2
    local extra_args=( "$@" )

    echo "🚀 Executando Prowler para ${provider^^} → $id"
    local out_file="${OUTPUT_DIR}/prowler-output-${id}-${TIMESTAMP}.json"

    "$PROWLER_BIN" "$provider" "${extra_args[@]}" \
        --output-formats json-asff \
        --output-filename "$(basename "$out_file" .json)" \
        --output-directory "$OUTPUT_DIR" \
        --ignore-exit-code-3

    if [[ -f "$out_file" ]]; then
        echo "✅ Arquivo gerado: $out_file"
        OUTPUTS+=( "$out_file" )
        upload_to_s3 "$out_file" "$id"
    else
        echo "❌ Arquivo não encontrado para $id"
    fi
}

# ============================================================
# ☁️ Execução por provedor
# ============================================================

# --- AWS ---
if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
    echo "☁️  Selecionado AWS"
    if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
        echo "🔎 Buscando contas AWS no Parameter Store..."
        TARGET_ACCOUNTS="$(aws ssm get-parameter \
            --name "/prowler/aws/accounts" \
            --query "Parameter.Value" \
            --output text)"
    fi

    for ACCOUNT_ID in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
        echo "🎯 Conta alvo: $ACCOUNT_ID"

        CREDS="$(aws sts assume-role \
            --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/ProwlerAuditRole" \
            --role-session-name "prowler-session")"

        export AWS_ACCESS_KEY_ID="$(echo "$CREDS" | jq -r .Credentials.AccessKeyId)"
        export AWS_SECRET_ACCESS_KEY="$(echo "$CREDS" | jq -r .Credentials.SecretAccessKey)"
        export AWS_SESSION_TOKEN="$(echo "$CREDS" | jq -r .Credentials.SessionToken)"

        run_prowler_generic aws "$ACCOUNT_ID" --region "$REGION"

        unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    done
fi

# --- AZURE ---
if [[ "$CLOUD_PROVIDER" == "azure" ]]; then
    echo "☁️  Selecionado Azure"
    if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
        echo "🔎 Buscando subscriptions Azure no Parameter Store..."
        TARGET_ACCOUNTS="$(aws ssm get-parameter \
            --name "/prowler/azure/subscriptions" \
            --query "Parameter.Value" \
            --output text)"
    fi

    for SUB in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
        run_prowler_generic azure "$SUB" --subscription-id "$SUB"
    done
fi

# --- GCP ---
if [[ "$CLOUD_PROVIDER" == "gcp" ]]; then
    echo "☁️  Selecionado GCP"
    if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
        echo "🔎 Buscando projetos GCP no Parameter Store..."
        TARGET_ACCOUNTS="$(aws ssm get-parameter \
            --name "/prowler/gcp/projects" \
            --query "Parameter.Value" \
            --output text)"
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
# 📜 Resumo
# ============================================================
echo "🧾 === Execução finalizada. Relatórios gerados: ==="
printf '%s\n' "${OUTPUTS[@]}"

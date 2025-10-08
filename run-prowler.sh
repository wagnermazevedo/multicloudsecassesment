#!/bin/bash
set -euo pipefail

# ============================================================
# 🛰️ Prowler Runner — versão aprimorada com fallback em Python
# ============================================================

# Força PATH abrangente para ambientes ECS/Docker
export PATH="/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.local/bin:/prowler"

echo "🛰️ === Inicializando ambiente Prowler ==="
echo "📂 Diretório atual: $(pwd)"
echo "👤 Usuário atual: $(whoami)"
echo "🔧 PATH atual: $PATH"

# ============================================================
# 🔍 LOCALIZAÇÃO INTELIGENTE DO PROWLER
# ============================================================

# Lista de candidatos ao executável
CANDIDATES=(
    "/usr/local/bin/prowler"
    "/usr/bin/prowler"
    "/root/.local/bin/prowler"
    "/prowler/prowler.py"
)

PROWLER_CMD=""

for path in "${CANDIDATES[@]}"; do
    if [[ -x "$path" ]]; then
        PROWLER_CMD="$path"
        break
    fi
done

# Caso não exista executável, tenta via Python
if [[ -z "$PROWLER_CMD" ]]; then
    if python3 -m prowler --version &>/dev/null; then
        PROWLER_CMD="python3 -m prowler"
    else
        echo "❌ Erro crítico: não foi possível localizar o Prowler."
        echo "Verifique se o diretório /prowler existe ou se o pacote foi instalado via pip."
        exit 1
    fi
fi

echo "✅ Usando Prowler via: $PROWLER_CMD"
$PROWLER_CMD --version || echo "⚠️ Não foi possível exibir a versão do Prowler."

# ============================================================
# 🔧 VARIÁVEIS DE AMBIENTE OBRIGATÓRIAS
# ============================================================
: "${CLOUD_PROVIDER:?❌ CLOUD_PROVIDER não definido (aws | azure | gcp)}"
: "${TARGET_ACCOUNTS:?❌ TARGET_ACCOUNTS não definido (IDs separados por vírgula ou ALL)}"

REGION="${AWS_REGION:-us-east-1}"
BUCKET="my-prowler-results"
TIMESTAMP=$(date +%Y%m%d%H%M)
OUTPUT_DIR="/tmp"
OUTPUTS=()

# Normaliza o provedor para minúsculas
CLOUD_PROVIDER=$(echo "$CLOUD_PROVIDER" | tr '[:upper:]' '[:lower:]')

# ============================================================
# 📤 Função de upload para S3
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
# 🚀 Função genérica de execução
# ============================================================
run_prowler_generic() {
    local provider="$1"
    local id="$2"
    shift 2
    local extra_args=("$@")

    echo "🚀 Executando Prowler para ${provider^^} → $id"
    local OUT_FILE="${OUTPUT_DIR}/prowler-output-${id}-${TIMESTAMP}.json"

    # Usa variável dinâmica $PROWLER_CMD (Python ou binário)
    eval "$PROWLER_CMD $provider ${extra_args[*]} \
        --output-formats json-asff \
        --output-filename $(basename "$OUT_FILE" .json) \
        --output-directory $OUTPUT_DIR \
        --ignore-exit-code-3" || echo "⚠️ Execução retornou código não crítico"

    if [[ -f "$OUT_FILE" ]]; then
        echo "✅ Arquivo gerado: $OUT_FILE"
        OUTPUTS+=("$OUT_FILE")
        upload_to_s3 "$OUT_FILE" "$id"
    else
        echo "❌ Arquivo não encontrado para $id"
    fi
}

# ============================================================
# ☁️ AWS
# ============================================================
if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
    echo "☁️  Selecionado AWS"
    echo "Variável PATH: $PATH"
    echo "---------------------------------"

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

# ============================================================
# ☁️ AZURE
# ============================================================
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

# ============================================================
# ☁️ GCP
# ============================================================
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
# 📜 FINALIZAÇÃO
# ============================================================
echo "🧾 === Execução finalizada. Relatórios gerados: ==="
printf '%s\n' "${OUTPUTS[@]}"


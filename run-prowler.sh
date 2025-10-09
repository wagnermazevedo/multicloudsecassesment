#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# 🌩️ MultiCloud Prowler Runner - v4.0
#   Autor: Wagner Azevedo
#   Suporte: AWS | Azure | GCP
#   Multi-cliente e multi-account com Parameter Store
# ============================================================

export PATH="/usr/local/bin:/usr/bin:/bin:/home/prowler/.local/bin:$PATH"
TIMESTAMP="$(date +%Y%m%d%H%M)"
OUTPUT_DIR="/tmp"
BUCKET="my-prowler-results"
OUTPUTS=()

# === Cores ===
RED="\033[0;31m"; GREEN="\033[0;32m"; BLUE="\033[0;34m"; YELLOW="\033[1;33m"; NC="\033[0m"

echo -e "${BLUE}🛰️ === Iniciando execução do MultiCloud Prowler Runner ===${NC}"

# === Variáveis obrigatórias ===
: "${CLOUD_PROVIDER:?${RED}❌ CLOUD_PROVIDER não definido (aws | azure | gcp)${NC}}"
: "${TARGET_ACCOUNTS:?${RED}❌ TARGET_ACCOUNTS não definido (IDs separados por vírgula ou ALL)${NC}}"

CLOUD_PROVIDER="$(echo "$CLOUD_PROVIDER" | tr '[:upper:]' '[:lower:]')"
REGION="${AWS_REGION:-us-east-1}"

echo -e "${BLUE}🌩️  Provedor:${NC} $CLOUD_PROVIDER"
echo -e "${BLUE}🎯  Contas/Projetos:${NC} $TARGET_ACCOUNTS"
echo -e "${BLUE}📂  Saída:${NC} $OUTPUT_DIR"
echo -e "${BLUE}🕒  Timestamp:${NC} $TIMESTAMP"

# ============================================================
# 🔐 Função: Carregar credenciais do Parameter Store
# ============================================================
load_creds_from_ssm() {
  local client="$1"
  local account_id="$2"
  local base_path="/prowler/aws/credentials/${client}/${account_id}"

  echo -e "${BLUE}🔑 Buscando credenciais para cliente:${NC} $client conta:${account_id}"

  local access_key secret_key session_token
  access_key="$(aws ssm get-parameter --name "${base_path}/AccessKeyId" --with-decryption --query 'Parameter.Value' --output text 2>/dev/null || true)"
  secret_key="$(aws ssm get-parameter --name "${base_path}/SecretAccessKey" --with-decryption --query 'Parameter.Value' --output text 2>/dev/null || true)"
  session_token="$(aws ssm get-parameter --name "${base_path}/SessionToken" --with-decryption --query 'Parameter.Value' --output text 2>/dev/null || true)"

  if [[ -n "$access_key" && -n "$secret_key" ]]; then
    export AWS_ACCESS_KEY_ID="$access_key"
    export AWS_SECRET_ACCESS_KEY="$secret_key"
    export AWS_SESSION_TOKEN="$session_token"
    echo -e "${GREEN}✅ Credenciais carregadas com sucesso do SSM.${NC}"
  else
    echo -e "${RED}⚠️ Falha ao obter credenciais para $client/$account_id${NC}"
  fi
}

# ============================================================
# 📤 Upload para S3
# ============================================================
upload_to_s3() {
  local file="$1"
  local client="$2"
  local account="$3"
  local dest="s3://${BUCKET}/${client}/${CLOUD_PROVIDER}/${account}/${TIMESTAMP}/$(basename "$file")"
  echo -e "${BLUE}📤 Enviando${NC} $file → $dest"
  aws s3 cp "$file" "$dest" --acl bucket-owner-full-control || echo -e "${RED}⚠️ Falha no upload${NC}"
}

# ============================================================
# 🚀 Execução genérica
# ============================================================
run_prowler_generic() {
  local provider="$1"
  local client="$2"
  local id="$3"
  shift 3
  local extra_args=("$@")

  local OUT_FILE="${OUTPUT_DIR}/prowler-${client}-${id}-${TIMESTAMP}.json"

  echo -e "${BLUE}🚀 Executando Prowler para cliente:${NC} $client → conta/projeto ${id}"

  prowler "$provider" "${extra_args[@]}" \
      --output-formats json-asff \
      --output-filename "$(basename "$OUT_FILE" .json)" \
      --output-directory "$OUTPUT_DIR" \
      --ignore-exit-code-3 || true

  if [[ -f "$OUT_FILE" ]]; then
    echo -e "${GREEN}✅ Arquivo gerado:${NC} $OUT_FILE"
    OUTPUTS+=("$OUT_FILE")
    upload_to_s3 "$OUT_FILE" "$client" "$id"
  else
    echo -e "${RED}❌ Arquivo não encontrado para $id${NC}"
  fi
}

# ============================================================
# ☁️ AWS Execution
# ============================================================
if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
  echo -e "${BLUE}☁️  Iniciando varredura AWS...${NC}"

  declare -A CLIENT_ACCOUNTS

  # Se ALL → busca lista completa de clientes e contas
  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    echo "🔎 Coletando lista de clientes no Parameter Store..."
    CLIENTS="$(aws ssm get-parameter --name "/prowler/aws/clients" --query "Parameter.Value" --output text)"

    for CLIENT in $(echo "$CLIENTS" | tr ',' ' '); do
      echo -e "${YELLOW}📁 Coletando contas do cliente:${NC} $CLIENT"
      ACCOUNTS="$(aws ssm get-parameter --name "/prowler/aws/${CLIENT}/accounts" --query "Parameter.Value" --output text)"
      CLIENT_ACCOUNTS["$CLIENT"]="$ACCOUNTS"
    done
  else
    # Caso seja lista manual → cliente genérico “default”
    CLIENT_ACCOUNTS["default"]="$TARGET_ACCOUNTS"
  fi

  # === Loop principal ===
  for CLIENT in "${!CLIENT_ACCOUNTS[@]}"; do
    echo -e "${YELLOW}🏢 Iniciando execuções para cliente:${NC} $CLIENT"
    for ACCOUNT_ID in $(echo "${CLIENT_ACCOUNTS[$CLIENT]}" | tr ',' ' '); do
      echo "🎯 Conta alvo: $ACCOUNT_ID"
      load_creds_from_ssm "$CLIENT" "$ACCOUNT_ID"
      if [[ -z "${AWS_ACCESS_KEY_ID:-}" ]]; then
        echo -e "${RED}⚠️ Sem credenciais válidas no SSM. Pulando conta $ACCOUNT_ID.${NC}"
        continue
      fi
      run_prowler_generic aws "$CLIENT" "$ACCOUNT_ID" --region "$REGION"
      unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    done
  done
fi

# ============================================================
# ☁️ Azure Execution
# ============================================================
if [[ "$CLOUD_PROVIDER" == "azure" ]]; then
  echo -e "${BLUE}☁️  Iniciando varredura Azure...${NC}"

  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    TARGET_ACCOUNTS="$(aws ssm get-parameter --name "/prowler/azure/subscriptions" --query "Parameter.Value" --output text)"
  fi

  az login --identity || echo -e "${RED}⚠️ Falha no login via Managed Identity${NC}"

  for SUB in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    run_prowler_generic azure "azure" "$SUB" --subscription-id "$SUB"
  done
fi

# ============================================================
# ☁️ GCP Execution
# ============================================================
if [[ "$CLOUD_PROVIDER" == "gcp" ]]; then
  echo -e "${BLUE}☁️  Iniciando varredura GCP...${NC}"

  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    TARGET_ACCOUNTS="$(aws ssm get-parameter --name "/prowler/gcp/projects" --query "Parameter.Value" --output text)"
  fi

  aws ssm get-parameter \
    --name "/prowler/gcp/serviceAccountKey" \
    --with-decryption \
    --query "Parameter.Value" \
    --output text | base64 -d > /tmp/prowler-sa.json

  export GOOGLE_APPLICATION_CREDENTIALS="/tmp/prowler-sa.json"
  gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS"

  for PROJECT in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    run_prowler_generic gcp "gcp" "$PROJECT" --project-id "$PROJECT"
  done
fi

# ============================================================
# 🧾 Resumo
# ============================================================
echo -e "${BLUE}🧾 === Execução finalizada. Relatórios gerados: ===${NC}"
printf '%s\n' "${OUTPUTS[@]}"


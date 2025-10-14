#!/bin/bash
set -euo pipefail
trap 'echo "[ERRO] ❌ Linha $LINENO: comando \"$BASH_COMMAND\" falhou com código $?."' ERR

echo "[RUNNER] 🧭 Iniciando execução do Multicloud Assessment Runner"

# ==============================
# 1️⃣ VARIÁVEIS BÁSICAS
# ==============================
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
OUTPUT_DIR="/tmp/output-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# ==============================
# 2️⃣ FUNÇÕES AUXILIARES
# ==============================

get_param() {
  local name="$1"
  aws ssm get-parameter --name "$name" --with-decryption --query "Parameter.Value" --output text 2>/dev/null || echo ""
}

decode_base64_safe() {
  local data="$1"
  if [ -z "$data" ]; then
    echo "[WARN] ⚠️ Base64 vazio recebido — ignorando decodificação."
    return 1
  fi
  echo "$data" | tr -d '\r' | base64 --decode 2>/dev/null || {
    echo "[ERRO] ❌ Falha ao decodificar Base64 (input inválido ou truncado)."
    return 1
  }
}

fetch_credentials() {
  local path="/clients/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/credentials/access"
  echo "[RUNNER] 🔹 Buscando credenciais em $path"
  get_param "$path"
}

# ==============================
# 3️⃣ AUTENTICAÇÃO MULTICLOUD
# ==============================
authenticate() {
  local creds
  creds=$(fetch_credentials)

  if [ -z "$creds" ]; then
    echo "[RUNNER] ⚠️ Nenhum parâmetro encontrado no SSM. Solicitando credenciais manualmente..."
  fi

  case "$CLOUD_PROVIDER" in
    aws)
      if [ -z "$creds" ]; then
        read -rp "AWS_ACCESS_KEY_ID: " AWS_ACCESS_KEY_ID
        read -rp "AWS_SECRET_ACCESS_KEY: " AWS_SECRET_ACCESS_KEY
        read -rp "AWS_SESSION_TOKEN (opcional): " AWS_SESSION_TOKEN || true
      else
        decode_base64_safe "$creds" > /tmp/aws_creds.json || true
        export AWS_ACCESS_KEY_ID=$(jq -r '.AWS_ACCESS_KEY_ID' /tmp/aws_creds.json)
        export AWS_SECRET_ACCESS_KEY=$(jq -r '.AWS_SECRET_ACCESS_KEY' /tmp/aws_creds.json)
        export AWS_SESSION_TOKEN=$(jq -r '.AWS_SESSION_TOKEN // empty' /tmp/aws_creds.json)
        export AWS_DEFAULT_REGION=$(jq -r '.AWS_DEFAULT_REGION // "us-east-1"' /tmp/aws_creds.json)
      fi

      echo "[RUNNER] ✅ AWS credenciais carregadas para conta ${ACCOUNT_ID}"
      aws sts get-caller-identity >/dev/null 2>&1 || {
        echo "[ERRO] Falha ao validar credenciais AWS."
        exit 1
      }
      ;;
    azure)
      if [ -z "$creds" ]; then
        read -rp "AZURE_TENANT_ID: " AZURE_TENANT_ID
        read -rp "AZURE_CLIENT_ID: " AZURE_CLIENT_ID
        read -rp "AZURE_CLIENT_SECRET: " AZURE_CLIENT_SECRET
        read -rp "AZURE_SUBSCRIPTION_ID: " AZURE_SUBSCRIPTION_ID
      else
        decode_base64_safe "$creds" > /etc/prowler/credentials/azure.env || true
        source /etc/prowler/credentials/azure.env
      fi

      echo "[RUNNER] 🔐 Autenticando no Azure..."
      az login --service-principal \
        -u "$AZURE_CLIENT_ID" \
        -p "$AZURE_CLIENT_SECRET" \
        --tenant "$AZURE_TENANT_ID" --output none || {
          echo "[ERRO] Falha ao autenticar no Azure CLI."
          exit 1
        }
      ;;
    gcp)
      mkdir -p /root/.config/gcloud
      if [ -z "$creds" ]; then
        read -rp "Caminho do arquivo JSON da Service Account: " SA_PATH
        cp "$SA_PATH" /root/.config/gcloud/application_default_credentials.json
      else
        decode_base64_safe "$creds" > /root/.config/gcloud/application_default_credentials.json || true
      fi

      echo "[RUNNER] 🔐 Ativando conta de serviço GCP..."
      gcloud auth activate-service-account \
        --key-file=/root/.config/gcloud/application_default_credentials.json >/dev/null 2>&1 || {
          echo "[ERRO] Falha ao ativar service account GCP."
          exit 1
        }
      ;;
    *)
      echo "[ERRO] ❌ Provedor de nuvem desconhecido: $CLOUD_PROVIDER"
      exit 1
      ;;
  esac
}

# ==============================
# 4️⃣ EXECUÇÃO DO SCAN
# ==============================
run_scan() {
  local output_file="${OUTPUT_DIR}/${CLOUD_PROVIDER}_${ACCOUNT_ID}_${TIMESTAMP}.json"
  echo "[RUNNER] ▶️ Executando Prowler (${CLOUD_PROVIDER})..."

  case "$CLOUD_PROVIDER" in
    aws)
      prowler aws --account-id "$ACCOUNT_ID" -M json-asff -o "$output_file" || true
      ;;
    azure)
      prowler azure -M json -o "$output_file" || true
      ;;
    gcp)
      prowler gcp --project-ids "$ACCOUNT_ID" -M json -o "$output_file" || true
      ;;
  esac

  if [ -f "$output_file" ]; then
    echo "[RUNNER] 📄 Relatório gerado: $output_file"
  else
    echo "[ERRO] ⚠️ Nenhum arquivo de saída gerado para ${CLOUD_PROVIDER}_${ACCOUNT_ID}"
  fi
}

# ==============================
# 5️⃣ UPLOAD DOS RESULTADOS
# ==============================
upload_to_s3() {
  if [ "${CLOUD_PROVIDER}" != "aws" ]; then
    echo "[RUNNER] 🌐 Upload S3 é aplicável apenas para AWS. Pulando etapa."
    return
  fi

  local s3_prefix="${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}"
  echo "[RUNNER] 📤 Enviando resultados para s3://${S3_BUCKET}/${s3_prefix}/"
  aws s3 cp "$OUTPUT_DIR" "s3://${S3_BUCKET}/${s3_prefix}/" --recursive --region "${AWS_DEFAULT_REGION:-us-east-1}" || {
    echo "[ERRO] Falha no upload para S3."
    exit 1
  }
  echo "[RUNNER] ✅ Upload concluído!"
}

# ==============================
# 6️⃣ EXECUÇÃO PRINCIPAL
# ==============================
echo "[RUNNER] 🚀 CLIENTE=${CLIENT_NAME} CLOUD=${CLOUD_PROVIDER} ACCOUNT=${ACCOUNT_ID}"

authenticate
run_scan
upload_to_s3

echo "[RUNNER] ✅ Scan finalizado com sucesso."
echo "[RUNNER] Resultados disponíveis em: s3://${S3_BUCKET}/${CLIENT_NAME}/${CLOUD_PROVIDER}/${ACCOUNT_ID}/${TIMESTAMP}/"



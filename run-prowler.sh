#!/usr/bin/env bash
set -Eeuo pipefail

echo "=== Iniciando execução do Prowler Runner ==="

# Resolve binário do prowler (imagem base instala via pyenv)
resolve_prowler_bin() {
  # 1) Se já está no PATH
  if command -v prowler >/dev/null 2>&1; then
    echo "$(command -v prowler)"
    return 0
  fi
  # 2) Pyenv (caminho típico da imagem oficial)
  local p
  p="$(find /root/.pyenv/versions -type f -name prowler 2>/dev/null | head -n 1 || true)"
  if [[ -n "$p" ]]; then
    echo "$p"
    return 0
  fi
  return 1
}

PROWLER_BIN="$(resolve_prowler_bin || true)"
if [[ -z "${PROWLER_BIN:-}" ]]; then
  echo "❌ prowler não encontrado no PATH nem no pyenv."
  echo "   Dica: dentro do container de debug, rode:  find / -type f -name prowler 2>/dev/null"
  # NÃO sai com erro — deixa o entrypoint segurar o container vivo
  exit 127
fi

echo "✅ Binário do Prowler: ${PROWLER_BIN}"
"${PROWLER_BIN}" --version || true

# =======================
# Leitura de variáveis
# =======================
: "${CLOUD_PROVIDER:?❌ CLOUD_PROVIDER não definido (aws | azure | gcp)}"
: "${TARGET_ACCOUNTS:?❌ TARGET_ACCOUNTS não definido (IDs separados por vírgula ou ALL)}"

REGION="${AWS_REGION:-us-east-1}"
BUCKET="${RESULTS_BUCKET:-my-prowler-results}"
TIMESTAMP="$(date +%Y%m%d%H%M)"
OUTPUT_DIR="/tmp"
OUTPUTS=()

CLOUD_PROVIDER="$(echo "$CLOUD_PROVIDER" | tr '[:upper:]' '[:lower:]')"

upload_to_s3() {
  local file="$1" account="$2"
  local dest="s3://${BUCKET}/${CLOUD_PROVIDER}/${account}/${TIMESTAMP}/$(basename "$file")"
  echo "📤 Upload: $file → $dest"
  aws s3 cp "$file" "$dest" --acl bucket-owner-full-control || {
    echo "❌ Falha no upload de $file"
    return 1
  }
}

run_prowler_generic() {
  local provider="$1" id="$2"; shift 2
  local extra_args=( "$@" )
  local out="${OUTPUT_DIR}/prowler-output-${id}-${TIMESTAMP}.json"

  echo "--- Rodando Prowler para ${provider^^} → ${id} ---"
  "${PROWLER_BIN}" "$provider" "${extra_args[@]}" \
    --output-formats json-asff \
    --output-filename "$(basename "$out" .json)" \
    --output-directory "$OUTPUT_DIR" \
    --ignore-exit-code-3

  if [[ -f "$out" ]]; then
    echo "✅ Gerado: $out"
    OUTPUTS+=( "$out" )
    upload_to_s3 "$out" "$id"
  else
    echo "❌ Não gerou arquivo para $id"
  fi
}

# =======================
# AWS
# =======================
if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
  echo "☁️  Selecionado AWS"
  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    TARGET_ACCOUNTS="$(aws ssm get-parameter --name "/prowler/aws/accounts" --query "Parameter.Value" --output text)"
  fi
  for ACCOUNT_ID in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    echo "🎯 Conta alvo: $ACCOUNT_ID"
    CREDS="$(aws sts assume-role --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/ProwlerAuditRole" --role-session-name "prowler-session")"
    export AWS_ACCESS_KEY_ID="$(echo "$CREDS" | jq -r .Credentials.AccessKeyId)"
    export AWS_SECRET_ACCESS_KEY="$(echo "$CREDS" | jq -r .Credentials.SecretAccessKey)"
    export AWS_SESSION_TOKEN="$(echo "$CREDS" | jq -r .Credentials.SessionToken)"
    run_prowler_generic aws "$ACCOUNT_ID" --region "$REGION"
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  done
fi

# (Azure/GCP: mesmas ideias; mantenha aqui se precisar)

echo "🧾 === Relatórios gerados ==="
printf '%s\n' "${OUTPUTS[@]}"

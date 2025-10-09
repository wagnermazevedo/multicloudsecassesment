#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# Prowler Runner – robusto para qualquer ambiente/venv
# ============================================================

# 1) PATH razoável e locais candidatos do projeto
export PATH="/usr/local/bin:/usr/bin:/bin:/root/.local/bin:/home/prowler/.local/bin:$PATH"
PROJECT_DIR=""

for d in \
  "/home/prowler/prowler" \
  "/opt/prowler" \
  "/prowler" \
  "/code/prowler" \
  "/workspace/prowler"
do
  if [[ -d "$d" ]]; then
    PROJECT_DIR="$d"
    break
  fi
done

if [[ -z "${PROJECT_DIR}" ]]; then
  echo "❌ Diretório do projeto Prowler não foi encontrado."
  echo "   Dicas: garanta que o repositório foi clonado/copied para /home/prowler/prowler ou /opt/prowler."
  exit 1
fi

cd "$PROJECT_DIR"

# 2) Função para resolver o comando do Prowler
#    Prioridade: binário no PATH -> venv (root/prowler) -> poetry run -> python -m
resolve_prowler_cmd() {
  local -a CANDIDATE_VENV_DIRS=(
    "/root/.cache/pypoetry/virtualenvs"
    "/home/prowler/.cache/pypoetry/virtualenvs"
    "/root/.virtualenvs"
    "/home/prowler/.virtualenvs"
  )

  # 2.1 Se já está no PATH, use
  if command -v prowler >/dev/null 2>&1; then
    PROWLER_CMD=( "$(command -v prowler)" )
    echo "🔎 Prowler encontrado no PATH: ${PROWLER_CMD[0]}"
    return 0
  fi

  # 2.2 Procura binário do prowler dentro de virtualenvs comuns
  for base in "${CANDIDATE_VENV_DIRS[@]}"; do
    if [[ -d "$base" ]]; then
      # pega o primeiro venv que comece com 'prowler'
      local venv
      venv="$(find "$base" -maxdepth 1 -type d -name 'prowler*' | head -n 1 || true)"
      if [[ -n "$venv" && -x "$venv/bin/prowler" ]]; then
        export PATH="$venv/bin:$PATH"
        PROWLER_CMD=( "$venv/bin/prowler" )
        echo "🔎 Prowler encontrado no venv: $venv"
        return 0
      fi
    fi
  done

  # 2.3 Tenta poetry run
  if command -v poetry >/dev/null 2>&1; then
    if POETRY_ACTIVE_DIR="$(poetry -C "$PROJECT_DIR" env info --path 2>/dev/null || true)"; then
      if [[ -x "$POETRY_ACTIVE_DIR/bin/prowler" ]]; then
        export PATH="$POETRY_ACTIVE_DIR/bin:$PATH"
        PROWLER_CMD=( "$POETRY_ACTIVE_DIR/bin/prowler" )
        echo "🔎 Prowler do poetry venv: $POETRY_ACTIVE_DIR"
        return 0
      fi
    fi
    # fallback via poetry run (sem path fixo)
    PROWLER_CMD=( poetry run prowler )
    echo "ℹ️ Usando 'poetry run prowler' (fallback)."
    return 0
  fi

  # 2.4 Último fallback: python -m prowler
  if command -v python3 >/dev/null 2>&1; then
    PROWLER_CMD=( python3 -m prowler )
    echo "⚠️ Usando 'python3 -m prowler' (fallback)."
    return 0
  fi

  return 1
}

if ! resolve_prowler_cmd; then
  echo "❌ Não foi possível resolver o comando do Prowler."
  exit 127
fi

# 3) Diagnóstico rápido
echo "✅ Comando Prowler: ${PROWLER_CMD[*]}"
( "${PROWLER_CMD[@]}" --version || true ) 2>&1 | sed 's/^/   > /'
echo "📂 PWD: $(pwd)"
echo "👤 User: $(whoami)"
echo "🔧 PATH: $PATH"

# 4) Variáveis obrigatórias
: "${CLOUD_PROVIDER:?❌ CLOUD_PROVIDER não definido (aws | azure | gcp)}"
: "${TARGET_ACCOUNTS:?❌ TARGET_ACCOUNTS não definido (IDs separados por vírgula ou ALL)}"

REGION="${AWS_REGION:-us-east-1}"
BUCKET="my-prowler-results"
TIMESTAMP="$(date +%Y%m%d%H%M)"
OUTPUT_DIR="/tmp"
OUTPUTS=()

CLOUD_PROVIDER="$(echo "$CLOUD_PROVIDER" | tr '[:upper:]' '[:lower:]')"

# 5) Upload S3
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

# 6) Execução genérica
run_prowler_generic() {
  local provider="$1"
  local id="$2"
  shift 2
  local extra_args=( "$@" )

  echo "🚀 Executando Prowler para ${provider^^} → $id"
  local out_file="${OUTPUT_DIR}/prowler-output-${id}-${TIMESTAMP}.json"

  # Execução principal
  "${PROWLER_CMD[@]}" "$provider" "${extra_args[@]}" \
    --output-formats json-asff \
    --output-filename "$(basename "$out_file" .json)" \
    --output-directory "$OUTPUT_DIR" \
    --ignore-exit-code-3

  # Upload e verificação
  if [[ -f "$out_file" ]]; then
    echo "✅ Arquivo gerado: $out_file"
    OUTPUTS+=( "$out_file" )
    upload_to_s3 "$out_file" "$id"
  else
    echo "❌ Arquivo não encontrado para $id"
  fi
}

# 7) Provedor: AWS
if [[ "$CLOUD_PROVIDER" == "aws" ]]; then
  echo "☁️  Selecionado AWS"
  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    echo "🔎 Buscando contas AWS no SSM..."
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

# 8) Provedor: Azure
if [[ "$CLOUD_PROVIDER" == "azure" ]]; then
  echo "☁️  Selecionado Azure"
  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    echo "🔎 Buscando subscriptions Azure no SSM..."
    TARGET_ACCOUNTS="$(aws ssm get-parameter \
      --name "/prowler/azure/subscriptions" \
      --query "Parameter.Value" \
      --output text)"
  fi

  for SUB in $(echo "$TARGET_ACCOUNTS" | tr ',' ' '); do
    run_prowler_generic azure "$SUB" --subscription-id "$SUB"
  done
fi

# 9) Provedor: GCP
if [[ "$CLOUD_PROVIDER" == "gcp" ]]; then
  echo "☁️  Selecionado GCP"
  if [[ "$TARGET_ACCOUNTS" == "ALL" ]]; then
    echo "🔎 Buscando projetos GCP no SSM..."
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

# 10) Resumo
echo "🧾 === Execução finalizada. Relatórios gerados: ==="
printf '%s\n' "${OUTPUTS[@]}"


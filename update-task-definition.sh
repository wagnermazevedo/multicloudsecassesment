#!/bin/bash
set -euo pipefail

# Variáveis passadas do CodeBuild ENV
AWS_REGION=$AWS_REGION
TASK_FAMILY=$TASK_FAMILY
CONTAINER_NAME=$CONTAINER_NAME
NEW_IMAGE_URI=$NEW_IMAGE_URI

TASK_DEF_FILE="task-definition-new.json"
TASK_DEF_UPDATED_FILE="task-definition-updated.json"

echo "=== 1. Validando e Puxando Task Definition ==="
LATEST_TASK_ARN=$(aws ecs list-task-definitions     --family-prefix "$TASK_FAMILY"     --status ACTIVE     --sort DESC     --max-items 1     --query 'taskDefinitionArns[0]'     --output text)

if [ "$LATEST_TASK_ARN" = "None" ] || [ -z "$LATEST_TASK_ARN" ]; then
    echo "❌ ERRO: Família de Tarefa '$TASK_FAMILY' não encontrada. Abortando atualização."
    exit 1
fi

echo "✅ ARN ativo: $LATEST_TASK_ARN. Puxando JSON..."

aws ecs describe-task-definition     --task-definition "$LATEST_TASK_ARN"     --query 'taskDefinition'     | jq 'del(.taskDefinitionArn) | del(.revision) | del(.status) | del(.requiresAttributes) | del(.compatibilities)'     > "$TASK_DEF_FILE"

echo "=== 2. Atualizando URI da Imagem ($CONTAINER_NAME) ==="

jq --arg img "$NEW_IMAGE_URI"    --arg name "$CONTAINER_NAME"    '(.containerDefinitions[] | select(.name == $name).image) = $img'    "$TASK_DEF_FILE" > "$TASK_DEF_UPDATED_FILE"

UPDATED_COUNT=$(cat "$TASK_DEF_UPDATED_FILE" | jq "(.containerDefinitions[] | select(.name == \"$CONTAINER_NAME\") | .image) | select(.)" | wc -l)

if [ "$UPDATED_COUNT" -eq 0 ]; then
    echo "❌ ERRO: Não foi possível atualizar o contêiner '$CONTAINER_NAME'. Nome incorreto?"
    exit 1
fi

echo "✅ URI da imagem atualizada para $NEW_IMAGE_URI."

echo "=== 3. Registrando Nova Revisão ==="

NEW_REVISION_ARN=$(aws ecs register-task-definition     --cli-input-json file://"$TASK_DEF_UPDATED_FILE"     --query 'taskDefinition.taskDefinitionArn'     --output text)

echo "====================================================="
echo "           ✅ SUCESSO! NOVA REVISÃO CRIADA"
echo "Nova Revisão ARN: $NEW_REVISION_ARN"
echo "====================================================="

rm "$TASK_DEF_FILE" "$TASK_DEF_UPDATED_FILE"

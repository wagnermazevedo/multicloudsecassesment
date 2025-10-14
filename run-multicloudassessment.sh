###### Lambda Version 3.2 (Fix parse error 'accounts s' + enhanced validation)
import json
import boto3
import os
import re
import datetime
import traceback
import uuid

# ===== AWS Clients =====
ecs_client = boto3.client("ecs")
ssm_client = boto3.client("ssm")
dynamo_client = boto3.client("dynamodb")

# ===== Environment Variables =====
CLUSTER_ARN = os.getenv("ECS_CLUSTER_ARN")
SUBNET_ID = os.getenv("SUBNET_ID")
SECURITY_GROUP_ID = os.getenv("SECURITY_GROUP_ID")
LAUNCH_TYPE = os.getenv("LAUNCH_TYPE", "FARGATE")

SESSION_TABLE = os.getenv("SESSION_TABLE", "MulticloudChatbotSession")
HISTORY_TABLE = os.getenv("HISTORY_TABLE", "MulticloudChatbotHistory")

# ===== Logging Helper =====
def log(msg):
    print(f"[{datetime.datetime.utcnow().isoformat()}Z] {msg}")

# ===== Helpers =====
def normalize(s):
    return s.strip().lower() if isinstance(s, str) else s

def format_response(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        },
        "body": json.dumps(body, ensure_ascii=True)
    }

def get_user_id(event):
    try:
        ctx = event.get("requestContext", {})
        identity = ctx.get("identity", {})
        user = identity.get("userArn") or identity.get("cognitoIdentityId") or identity.get("sourceIp")
        if not user:
            user = "anonymous"
        return str(user)
    except Exception:
        return "anonymous"

# ===== Parameter Store Helpers =====
def get_ssm_parameter(path):
    if not path.startswith("/"):
        path = f"/{path}"
    try:
        response = ssm_client.get_parameter(Name=path)
        val = response["Parameter"]["Value"]
        if val.strip().startswith("PARAMETER"):
            val = re.sub(r"^PARAMETER.*?\{", "{", val, flags=re.S)
        return val
    except ssm_client.exceptions.ParameterNotFound:
        return None
    except Exception as e:
        log(f"SSM error for path {path}: {e}")
        raise

def list_all_clients():
    paginator = ssm_client.get_paginator("describe_parameters")
    clients = set()
    for page in paginator.paginate():
        for param in page.get("Parameters", []):
            name = param.get("Name", "")
            match = re.match(r"^/clients/([^/]+)/", name)
            if match:
                clients.add(match.group(1))
    return sorted(list(clients))

def list_accounts_for_client(client, cloud):
    legacy_param = f"/clients/{client}/{cloud}/accounts"
    value = get_ssm_parameter(legacy_param)
    if value:
        accounts = [a.strip() for a in value.split(",") if a.strip()]
        if accounts:
            log(f"Accounts resolved from legacy CSV at {legacy_param}: {accounts}")
            return accounts

    base_path = f"/clients/{client}/{cloud}/"
    accounts_set = set()
    paginator = ssm_client.get_paginator("get_parameters_by_path")
    for page in paginator.paginate(Path=base_path, Recursive=True):
        for param in page.get("Parameters", []):
            name = param.get("Name", "")
            if "/credentials/" in name:
                parts = name.split("/")
                if len(parts) >= 4 and parts[-2] == "credentials":
                    account_id = parts[-3]
                    if account_id:
                        accounts_set.add(account_id)
    accounts = sorted(accounts_set)
    log(f"Accounts resolved from SSM tree at {base_path}: {accounts}")
    return accounts

# ===== ECS Helpers =====
def get_latest_task_definition(family_prefix):
    resp = ecs_client.list_task_definitions(familyPrefix=family_prefix, sort="DESC")
    if not resp["taskDefinitionArns"]:
        raise Exception(f"No task definition found for '{family_prefix}'")
    return resp["taskDefinitionArns"][0]

def run_ecs_task(client, cloud, accounts, region):
    task_def_arn = get_latest_task_definition("MultiCloudSecurityAssessment")
    overrides = {
        "containerOverrides": [
            {
                "name": "MultiCloudSecurityAssessment",
                "environment": [
                    {"name": "CLIENT_NAME", "value": client},
                    {"name": "CLOUD_PROVIDER", "value": cloud},
                    {"name": "ACCOUNT_ID", "value": accounts},
                    {"name": "AWS_REGION", "value": region},
                    {"name": "S3_BUCKET", "value": "multicloud-assessments"}
                ]
            }
        ]
    }
    ecs_response = ecs_client.run_task(
        cluster=CLUSTER_ARN,
        taskDefinition=task_def_arn,
        launchType=LAUNCH_TYPE,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [SUBNET_ID],
                "securityGroups": [SECURITY_GROUP_ID],
                "assignPublicIp": "ENABLED"
            }
        },
        overrides=overrides
    )
    task_arns = [t["taskArn"] for t in ecs_response.get("tasks", [])]
    return {"taskArns": task_arns, "taskDefinition": task_def_arn}

# ===== DynamoDB Helpers =====
def save_session(user, data):
    dynamo_client.put_item(
        TableName=SESSION_TABLE,
        Item={
            "sessionId": {"S": user},
            "data": {"S": json.dumps(data, ensure_ascii=True)},
            "timestamp": {"S": datetime.datetime.utcnow().isoformat()}
        }
    )

def get_session(user):
    resp = dynamo_client.get_item(TableName=SESSION_TABLE, Key={"sessionId": {"S": user}})
    if "Item" in resp:
        return json.loads(resp["Item"]["data"]["S"])
    return None

def delete_session(user):
    dynamo_client.delete_item(TableName=SESSION_TABLE, Key={"sessionId": {"S": user}})

def save_history(user, command, result):
    try:
        dynamo_client.put_item(
            TableName=HISTORY_TABLE,
            Item={
                "id": {"S": str(uuid.uuid4())},
                "user": {"S": user},
                "command": {"S": command},
                "result": {"S": json.dumps(result, ensure_ascii=True)},
                "timestamp": {"S": datetime.datetime.utcnow().isoformat()}
            }
        )
    except Exception as e:
        log(f"DynamoDB logging failed: {e}")

# ===== Command Parser =====
def parse_command(text):
    text = normalize(text)

    # List all clients
    if re.search(r"\b(list|show|display)\s+all\s+(clients|customers)\b", text):
        return {"action": "list_clients"}

    # List accounts
    match = re.match(r".*list\s+all\s+([a-z0-9\-]+)\s+accounts\s+for\s+client\s+([a-z0-9\-]+).*", text)
    if match:
        return {"action": "list_accounts", "cloud": match.group(1), "client": match.group(2)}

    # Run scan (accepts flexible order)
    client = re.search(r"client\s+([a-z0-9\-]+)", text)
    cloud = re.search(r"\b(aws|azure|gcp)\b", text)
    region = re.search(r"region\s+([a-z0-9\-]+)", text)
    account = re.search(r"\baccounts?\s+([0-9a-z\-]{6,})\b", text)

    # Evita capturar 'aws' como 'accounts s'
    if "accounts s" in text or text.endswith("aws"):
        account = None

    if client and cloud and region and account:
        return {
            "action": "run_scan",
            "client": client.group(1),
            "cloud": cloud.group(1),
            "region": region.group(1),
            "accounts": account.group(1)
        }

    missing = []
    if not client: missing.append("client name")
    if not cloud: missing.append("cloud provider (aws, azure, gcp)")
    if not region: missing.append("region (e.g., us-east-1, eastus, us-central1)")
    if not account: missing.append("account/project ID")

    if missing:
        suggestion = (
            f"⚠️ Your last command seems incomplete.\n"
            f"Missing: {', '.join(missing)}.\n"
            f"👉 Example: run scan for client acme in aws region us-east-1 accounts 767397997901"
        )
        return {"error": suggestion, "last_command": text}

    if text in ["yes", "y"]:
        return {"action": "confirm"}

    if re.search(r"\b(show|list|display)\s+(last|recent)\s+(scans|executions)\b", text):
        return {"action": "list_history"}

    return {"action": "unknown", "last_command": text}

# ===== Lambda Handler =====
def lambda_handler(event, context):
    log("=== Incoming event ===")
    log(json.dumps(event, indent=2, ensure_ascii=True))

    if event.get("httpMethod") == "OPTIONS":
        return format_response(200, {"ok": True})

    try:
        body = json.loads(event.get("body", "{}"))
        command = body.get("text", "")
        user = get_user_id(event)
        parsed = parse_command(command)

        if "error" in parsed:
            log(f"⚠️ Parser feedback: {parsed['error']}")
            return format_response(400, parsed)

        if parsed["action"] == "list_clients":
            clients = list_all_clients()
            return format_response(200, {"clients": clients or []})

        if parsed["action"] == "list_accounts":
            accounts = list_accounts_for_client(parsed["client"], parsed["cloud"])
            return format_response(200, {"client": parsed["client"], "cloud": parsed["cloud"], "accounts": accounts})

        if parsed["action"] == "run_scan":
            save_session(user, parsed)
            msg = (
                f"Do you want to start a security assessment for client '{parsed['client']}', "
                f"cloud '{parsed['cloud']}', region '{parsed['region']}', accounts '{parsed['accounts']}'? "
                "Reply 'yes' to confirm."
            )
            return format_response(200, {"message": msg})

        if parsed["action"] == "confirm":
            session = get_session(user)
            if not session:
                return format_response(400, {"error": "No previous command found for confirmation."})
            result = run_ecs_task(session["client"], session["cloud"], session["accounts"], session["region"])
            delete_session(user)
            save_history(
                user,
                f"scan {session['client']} {session['cloud']} {session['region']} {session['accounts']}",
                result
            )
            return format_response(200, {
                "ok": True,
                "message": f"Scan started for {session['client']} ({session['cloud']}:{session['region']}) -> {session['accounts']}",
                **result
            })

        if parsed["action"] == "list_history":
            resp = dynamo_client.scan(TableName=HISTORY_TABLE, Limit=5)
            items = sorted(resp.get("Items", []), key=lambda x: x["timestamp"]["S"], reverse=True)
            history = [
                {"timestamp": i["timestamp"]["S"], "command": i["command"]["S"], "result": json.loads(i["result"]["S"])}
                for i in items
            ]
            return format_response(200, {"recent_scans": history or []})

        return format_response(400, {"error": f"Unknown command: '{parsed.get('last_command', command)}'"})

    except Exception as e:
        log(traceback.format_exc())
        return format_response(500, {"error": str(e)})

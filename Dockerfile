# =======================================================
# Dockerfile - MultiCloud Prowler Runner (AWS + Azure + GCP + M365)
# =======================================================

FROM public.ecr.aws/prowler-cloud/prowler:latest

LABEL maintainer="Wagner Azevedo"
LABEL description="Prowler MultiCloud Runner com suporte AWS, Azure, GCP e M365 (auto-detect Poetry venv)"

USER root

# === Dependências básicas ===
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        jq curl unzip bash wget ca-certificates gnupg lsb-release apt-transport-https dos2unix && \
    rm -rf /var/lib/apt/lists/*

# === Azure CLI ===
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# === PowerShell ===
ARG POWERSHELL_VERSION=7.5.0
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
      wget -q https://github.com/PowerShell/PowerShell/releases/download/v${POWERSHELL_VERSION}/powershell-${POWERSHELL_VERSION}-linux-x64.tar.gz -O /tmp/pwsh.tar.gz ; \
    else \
      wget -q https://github.com/PowerShell/PowerShell/releases/download/v${POWERSHELL_VERSION}/powershell-${POWERSHELL_VERSION}-linux-arm64.tar.gz -O /tmp/pwsh.tar.gz ; \
    fi && \
    mkdir -p /opt/microsoft/powershell/7 && \
    tar zxf /tmp/pwsh.tar.gz -C /opt/microsoft/powershell/7 && \
    ln -sf /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh && \
    chmod +x /usr/bin/pwsh && \
    rm /tmp/pwsh.tar.gz

# === Google Cloud SDK ===
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
      | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg \
      | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update -y && \
    apt-get install -y --no-install-recommends google-cloud-cli && \
    rm -rf /var/lib/apt/lists/*

# === Copia scripts ===
COPY run-prowler.sh /usr/local/bin/run-prowler.sh
COPY entrypoint.sh   /usr/local/bin/entrypoint.sh

RUN dos2unix /usr/local/bin/run-prowler.sh /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/run-prowler.sh /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/bin/pwsh

# === Detecta automaticamente e fixa o virtualenv no PATH durante build ===
RUN VENV_PATH=$(find /home/prowler/.cache/pypoetry/virtualenvs -type d -name "prowler-*-py3.*" | head -n 1 || true) && \
    if [ -n "$VENV_PATH" ]; then \
        echo "export PATH=\"$VENV_PATH/bin:\$PATH\"" >> /etc/profile.d/prowler.sh && \
        echo "[Dockerfile] Virtualenv detectado e adicionado ao PATH: $VENV_PATH"; \
    else \
        echo "[Dockerfile] Nenhum virtualenv do prowler encontrado durante build."; \
    fi

# === Variáveis de ambiente ===
ENV PYTHONUNBUFFERED=1
ENV PROWLER_DEBUG=0

USER root
WORKDIR /prowler

ENTRYPOINT ["/bin/bash", "/usr/local/bin/entrypoint.sh"]

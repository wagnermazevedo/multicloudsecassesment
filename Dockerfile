# =======================================================
# Dockerfile - MultiCloud Prowler Runner (AWS + Azure + GCP + M365)
# Executa como root, com debug opcional
# =======================================================
FROM public.ecr.aws/prowler-cloud/prowler:latest

LABEL maintainer="Wagner Azevedo"
LABEL description="Prowler MultiCloud Runner com suporte AWS, Azure, GCP e M365 (root mode + debug hold)"

USER root

# === 1. Dependências básicas ===
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        jq curl unzip bash wget ca-certificates gnupg lsb-release apt-transport-https dos2unix && \
    rm -rf /var/lib/apt/lists/*

# === 2. Instala AWS CLI ===
ARG AWS_CLI_VERSION=2.15.55
RUN curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-${AWS_CLI_VERSION}.zip" -o "awscliv2.zip" && \
    unzip -q awscliv2.zip && ./aws/install && \
    rm -rf awscliv2.zip ./aws

# === 3. Instala Azure CLI ===
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# === 4. Instala PowerShell (para M365 / Entra ID) ===
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
    rm /tmp/pwsh.tar.gz

# === 5. Instala Google Cloud SDK ===
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
      | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg \
      | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update -y && \
    apt-get install -y --no-install-recommends google-cloud-cli && \
    rm -rf /var/lib/apt/lists/*

# === 6. Copia scripts ===
COPY run-prowler.sh /usr/local/bin/run-prowler.sh
COPY entrypoint.sh  /usr/local/bin/entrypoint.sh

RUN dos2unix /usr/local/bin/run-prowler.sh /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/run-prowler.sh /usr/local/bin/entrypoint.sh

# === 7. Ambiente e PATH ===
WORKDIR /root
ENV PATH="/root/.pyenv/versions/3.11.13/bin:/usr/local/bin:/usr/bin:/bin"
ENV PYTHONUNBUFFERED=1
ENV PROWLER_DEBUG=0

# === 8. Healthcheck opcional (garante CLIs no path) ===
HEALTHCHECK --interval=1m --timeout=5s CMD aws --version && az version && gcloud version && pwsh --version || exit 1

# === 9. EntryPoint ===
ENTRYPOINT ["/bin/bash", "/usr/local/bin/entrypoint.sh"]


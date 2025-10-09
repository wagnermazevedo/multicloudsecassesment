# =======================================================
# Dockerfile - MultiCloud Prowler Runner (com AWS, Azure e GCP)
# =======================================================

FROM public.ecr.aws/prowler-cloud/prowler:latest

LABEL maintainer="Wagner Azevedo"
LABEL description="Prowler MultiCloud Runner com suporte AWS, Azure, GCP e M365"

USER root

# === 1. Dependências básicas ===
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        jq curl unzip bash ca-certificates gnupg apt-transport-https lsb-release && \
    rm -rf /var/lib/apt/lists/*

# === 2. Instala Azure CLI ===
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# === 3. Instala PowerShell (para M365 e Entra ID) ===
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

# === 4. Instala Google Cloud SDK ===
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
      | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg \
      | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update -y && \
    apt-get install -y --no-install-recommends google-cloud-cli && \
    rm -rf /var/lib/apt/lists/*

# === 5. Copia o script de execução ===
COPY run-prowler.sh /usr/local/bin/run-prowler.sh
RUN chmod +x /usr/local/bin/run-prowler.sh

USER prowler
WORKDIR /home/prowler

ENV PATH="/usr/local/bin:/usr/bin:/bin:/home/prowler/.local/bin"
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/bin/bash", "/usr/local/bin/run-prowler.sh"]

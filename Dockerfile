# =======================================================
# Dockerfile - MultiCloud Prowler Runner (AWS + Azure + GCP + M365)
# Base: Imagem oficial do Prowler com Python e Pyenv pré-configurado
# =======================================================
FROM public.ecr.aws/prowler-cloud/prowler:latest

LABEL maintainer="Wagner Azevedo"
LABEL description="Prowler MultiCloud Runner com suporte AWS, Azure, GCP e M365"

USER root

# 1. Dependências básicas
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        jq curl unzip bash wget ca-certificates gnupg lsb-release apt-transport-https dos2unix && \
    rm -rf /var/lib/apt/lists/*

# 2. Instala Azure CLI
#RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash && \
#    az version && echo "Azure CLI instalado com sucesso."

# 3. Instala PowerShell
#ARG POWERSHELL_VERSION=7.5.0
#RUN ARCH=$(uname -m) && \
#    if [ "$ARCH" = "x86_64" ]; then \
#        wget -q https://github.com/PowerShell/PowerShell/releases/download/v${POWERSHELL_VERSION}/powershell-${POWERSHELL_VERSION}-linux-x64.tar.gz -O /tmp/pwsh.tar.gz ; \
#    else \
#        wget -q https://github.com/PowerShell/PowerShell/releases/download/v${POWERSHELL_VERSION}/powershell-${POWERSHELL_VERSION}-linux-arm64.tar.gz -O /tmp/pwsh.tar.gz ; \
#    fi && \
#    mkdir -p /opt/microsoft/powershell/7 && \
#    tar zxf /tmp/pwsh.tar.gz -C /opt/microsoft/powershell/7 && \
#    chmod +x /opt/microsoft/powershell/7/pwsh && \
#    ln -sf /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh && \
#    rm /tmp/pwsh.tar.gz && pwsh -Command '$PSVersionTable'

# 4. Instala Google Cloud SDK
#RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
#      | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
##    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg \
 #     | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
 #   apt-get update -y && \
 #   apt-get install -y --no-install-recommends google-cloud-cli && \
 #   gcloud version && echo "Google Cloud SDK instalado com sucesso." && \
 #   rm -rf /var/lib/apt/lists/*

# 5. Detecta automaticamente e fixa o virtualenv no PATH durante build
RUN VENV_PATH=$(find /home/prowler/.cache/pypoetry/virtualenvs -type d -name "prowler-*-py3.*" | head -n 1 || true) && \
    if [ -n "$VENV_PATH" ]; then echo "export PATH=\"$VENV_PATH/bin:\$PATH\"" >> /etc/profile.d/prowler.sh; fi

# 6. Copia scripts
COPY run-prowler.sh /usr/local/bin/run-prowler.sh
COPY run-multicloudassessment.sh /usr/local/bin/run-multicloudassessment.sh

COPY entrypoint.sh   /usr/local/bin/entrypoint.sh
RUN dos2unix /usr/local/bin/run-prowler.sh /usr/local/bin/entrypoint.sh  /usr/local/bin/run-multicloudassessment.sh && \
    chmod +x /usr/local/bin/run-prowler.sh /usr/local/bin/entrypoint.sh /usr/local/bin/run-multicloudassessment.sh


# 7. Configura PATH
ENV PATH="/usr/local/bin:/usr/bin:/bin"
ENV PYTHONUNBUFFERED=1

WORKDIR /home/prowler
ENTRYPOINT ["/bin/bash", "/usr/local/bin/entrypoint.sh"]

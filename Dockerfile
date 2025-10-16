# MultiCloud Assessment Runner
# build-id: 20251016-1435

FROM public.ecr.aws/prowler-cloud/prowler:latest
LABEL maintainer="Wagner Azevedo"
LABEL description="Prowler MultiCloud Runner com suporte AWS, Azure, GCP e M365"

USER root

# Dependências básicas
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends jq curl unzip bash wget ca-certificates gnupg lsb-release apt-transport-https dos2unix uuid-runtime && \
    rm -rf /var/lib/apt/lists/*

# Corrige PATH do virtualenv (adiciona permanentemente)
ENV PATH="/home/prowler/.cache/pypoetry/virtualenvs/prowler-NnJNioq7-py3.12/bin:${PATH}"

# Copia scripts
COPY run-prowler.sh /usr/local/bin/run-prowler.sh
COPY run-multicloudassessment.sh /usr/local/bin/run-multicloudassessment.sh
COPY run-multicloud-wrapper.sh /usr/local/bin/run-multicloud-wrapper.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# Normaliza permissões e line endings
RUN dos2unix /usr/local/bin/*.sh && chmod +x /usr/local/bin/*.sh

WORKDIR /home/prowler
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# 5. Detecta automaticamente e fixa o virtualenv no PATH durante build
RUN VENV_PATH=$(find /home/prowler/.cache/pypoetry/virtualenvs -type d -name "prowler-*-py3.*" | head -n 1 || true) && \
    if [ -n "$VENV_PATH" ]; then echo "export PATH=\"$VENV_PATH/bin:\$PATH\"" >> /etc/profile.d/prowler.sh; fi

# 6. Copia scripts
COPY run-prowler.sh /usr/local/bin/run-prowler.sh
COPY run-multicloudassessment.sh /usr/local/bin/run-multicloudassessment.sh
COPY run-multicloud-wrapper.sh /usr/local/bin/
COPY entrypoint.sh   /usr/local/bin/entrypoint.sh

# Normaliza permissões e line endings
RUN dos2unix /usr/local/bin/run-prowler.sh /usr/local/bin/entrypoint.sh  /usr/local/bin/run-multicloudassessment.sh  /usr/local/bin/run-multicloud-wrapper.sh&& \
    chmod +x /usr/local/bin/run-prowler.sh /usr/local/bin/entrypoint.sh /usr/local/bin/run-multicloudassessment.sh /usr/local/bin/run-multicloud-wrapper.sh


# 7. Configura PATH
ENV PATH="/home/prowler/.cache/pypoetry/virtualenvs/prowler-NnJNioq7-py3.12/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

WORKDIR /home/prowler
ENTRYPOINT ["/bin/bash","/usr/local/bin/entrypoint.sh"]

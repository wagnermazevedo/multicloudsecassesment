FROM python:3.11-slim

# 1. Instalar dependências e ferramentas
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        unzip \
        curl \
        build-essential && \
    rm -rf /var/lib/apt/lists/*

# 2. Clonar Prowler
RUN git clone https://github.com/prowler-cloud/prowler.git /prowler

WORKDIR /prowler

# 3. Instalar Prowler
RUN pip install . --no-cache-dir

# 4. Copiar script de execução
COPY run-prowler.sh /usr/local/bin/run-prowler.sh
RUN chmod +x /usr/local/bin/run-prowler.sh

# 5. Definir ENTRYPOINT
ENTRYPOINT ["/usr/local/bin/run-prowler.sh"]

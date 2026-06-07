FROM python:3.11-slim

RUN pip install --no-cache-dir \
    safetensors numpy modelscan h5py pip-audit \
    torch==2.5.1+cpu \
    --extra-index-url https://download.pytorch.org/whl/cpu

RUN apt-get update && apt-get install -y curl binutils && rm -rf /var/lib/apt/lists/* && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app

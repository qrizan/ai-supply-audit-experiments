FROM python:3.11-slim

RUN pip install --no-cache-dir \
    safetensors numpy modelscan h5py pip-audit \
    torch==2.5.1+cpu \
    --extra-index-url https://download.pytorch.org/whl/cpu

RUN apt-get update && apt-get install -y curl binutils && rm -rf /var/lib/apt/lists/* && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# cosign (Sigstore), pinned and checksum-verified
RUN COSIGN_VERSION=v2.4.1 && \
    curl -sSfL -o /usr/local/bin/cosign \
      "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" && \
    curl -sSfL -o /tmp/cosign_checksums.txt \
      "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign_checksums.txt" && \
    grep 'cosign-linux-amd64$' /tmp/cosign_checksums.txt | sed 's# cosign-linux-amd64# /usr/local/bin/cosign#' | sha256sum -c - && \
    chmod +x /usr/local/bin/cosign && rm -f /tmp/cosign_checksums.txt

WORKDIR /app

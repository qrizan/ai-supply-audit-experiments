# AI Supply Audit Experiments

Hands-on experiments for understanding AI supply chain security audit techniques.

## Setup

Build the Docker image once:

```bash
docker build -t ai-audit .
```

## Running Experiments

Each experiment runs in an isolated Docker container with network disabled. Instructions are in each experiment's `AUDIT.md`.

## Samples

| File | Description |
|---|---|
| `samples/models/safe/sentiment_model.pkl` | Safe pickle - numpy arrays, no executable code. |
| `samples/models/safe/embeddings.safetensors` | SafeTensors - data-only format, no code execution possible. |
| `samples/models/vulnerable/malicious_model.pkl` | Pickle with `__reduce__` payload that executes a shell command at load time. Payload writes to `/tmp` only. |
| `samples/models/vulnerable/tampered_embeddings.safetensors` | Valid SafeTensors file with an intentionally wrong hash in `checksums.json`. |
| `samples/models/checksums.json` | SHA-256 records. One entry is intentionally wrong. |
| `samples/requirements/safe_requirements.txt` | Clean dependencies - no known vulnerabilities. |
| `samples/requirements/vulnerable_requirements.txt` | Dependencies pinned to versions with known CVEs. |

> [!WARNING]
> This repository intentionally contains malicious and tampered sample model files (under `samples/models/vulnerable/`) for security education only. The payload in `malicious_model.pkl` runs a shell command when loaded; it is harmless and only writes a marker file to `/tmp` inside the container. Run every experiment in the provided Docker container (`--network none`, samples read-only), never on a host or production system.

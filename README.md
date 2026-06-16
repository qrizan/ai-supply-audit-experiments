# AI Supply Audit Experiments

Hands-on experiments for understanding AI supply chain security audit techniques.

Scope: this covers the security of the **model artifact and its dependencies**. It does not cover data poisoning, backdoors hidden in model weights (a model that misbehaves with no code at all), or the LLM/agent ecosystem (malicious tools, prompt injection, RAG poisoning).

## How the experiments fit together

A model never arrives alone: it comes as a file plus the dependencies around it. Each step of its journey into your pipeline has a control, and the layers back each other up (defense in depth).

```
  THE MODEL FILE
  --------------
  is it intact?              ->  02  integrity (checksum)
  is it really theirs?       ->  07  provenance (signature)
  is the format real?        ->  10  extension spoofing (check magic bytes, not name)
  unpacking the bundle?      ->  12  path traversal (validate paths on extract)
  does it carry code?        ->  01  safe serialisation (refuse code at load)
  is malicious code in it?   ->  03  static scanning (detect before loading)
  what does it do?           ->  08  behavioural analysis (watch / stop at runtime)
  can a scan be evaded?      ->  11  static scan evasion (why 03 needs 08 alongside)
  does it bring its own code?->  09  trust_remote_code (run only code you trust)

  ITS DEPENDENCIES
  ----------------
  known vulnerabilities?     ->  04  dependency audit
  a look-alike name?         ->  05  typosquatting
  what is even in here?      ->  06  SBOM (inventory)
```

Core idea: loading a model = running code, so treat it like untrusted software - verify it, inspect it, watch it, and keep it in a sandbox.

## Setup

Build the Docker image once:

```bash
docker build -t ai-audit .
```

## Running Experiments

Run every command from the repository root. The commands use `$(pwd)` to mount paths into the container, so running from a subfolder will mount the wrong directories and fail.

Each experiment runs in an isolated Docker container. Loading untrusted models runs with `--network none`; the one exception is experiment 04 (dependency audit), which must reach an advisory database and runs with network on - it executes no untrusted code, so the isolation rule does not apply. Instructions are in each experiment's `AUDIT.md`.

## Samples

| File | Description |
|---|---|
| `samples/models/safe/sentiment_model.pkl` | Safe pickle - numpy arrays, no executable code. |
| `samples/models/safe/embeddings.safetensors` | SafeTensors - data-only format, no code execution possible. |
| `samples/models/vulnerable/malicious_model.pkl` | Pickle with `__reduce__` payload that executes a shell command at load time. Payload writes to `/tmp` only. |
| `samples/models/vulnerable/tampered_embeddings.safetensors` | Valid SafeTensors file with an intentionally wrong hash in `checksums.json`. |
| `samples/models/vulnerable/disguised_model.safetensors` | A pickle with an `os.system` payload saved under a `.safetensors` name. The extension is a lie; the bytes are pickle. Payload writes to `/tmp` only. |
| `samples/models/vulnerable/evasion_model.pkl` | A pickle that reaches `os.system` via `cProfile.run` to dodge modelscan's blocklist. Payload writes to `/tmp` only. |
| `samples/models/vulnerable/evil_bundle.tar` | A tar bundle with a `../` path-traversal entry. Runs no code; on naive extraction it writes a marker file outside the target directory (`/tmp` only). |
| `samples/models/checksums.json` | SHA-256 records. One entry is intentionally wrong. |
| `samples/requirements/safe_requirements.txt` | Dependencies audited clean as of 2026-06-14. Carries an audit date because a clean set turns vulnerable as new advisories land - re-audit before relying on it. |
| `samples/requirements/vulnerable_requirements.txt` | Dependencies pinned to versions with known CVEs. |
| `samples/requirements/typosquat_requirements.txt` | Names only - several imitate real packages (e.g. `reqeusts`). For static name analysis; never install this file. |
| `samples/models/remote_code_model/` | A model directory with clean `safetensors` weights but a `modeling_evil.py` that runs a shell command on import, reached via `trust_remote_code`. Payload writes to `/tmp` only. |

> [!WARNING]
> This repository intentionally contains malicious and tampered sample model files (under `samples/models/vulnerable/` and `samples/models/remote_code_model/`) for security education only. The payloads in `malicious_model.pkl`, `modeling_evil.py`, `disguised_model.safetensors`, and `evasion_model.pkl` run a shell command when loaded; `evil_bundle.tar` runs no code but writes a file outside the extraction directory when unpacked naively. All are harmless and only write a marker file to `/tmp` inside the container. Run every experiment in the provided Docker container (`--network none`, samples read-only), never on a host or production system.

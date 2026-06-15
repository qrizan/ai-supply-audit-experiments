# Experiment 03 - Static Model Scanning

## Scenario

A team receives a model, runs every check they have, and it passes: the checksum matches the published value, and the file came from the author's official account. They load it, and a payload buried inside runs. The author's build pipeline had been compromised, so the malicious file is genuinely theirs, with a matching hash and a credible origin. Both checks only ever asked whether the file was the one the author released, never whether that file was safe to run. Integrity confirms the bytes are unchanged and provenance confirms who sent them, but neither looks at what the bytes actually do. The only thing that catches a payload like this is reading the file's contents before it is loaded.

## How it works

A static scanner reads a model file and inspects what it would do, without executing it. modelscan (Protect AI) scans multiple model formats - PyTorch, TensorFlow, Keras, SafeTensors - and assigns a severity to each finding. A PyTorch file is a ZIP archive with the pickle inside; modelscan reads into the archive directly and flags unsafe operators such as `os.system`. The model is never loaded, so the payload never runs.

```
malicious_model.pkl (PyTorch = ZIP + pickle)
│
└── modelscan ──► reads into the archive ──► CRITICAL: unsafe operator 'system'

embeddings.safetensors
│
└── modelscan ──► No issues found
```

## Run

Samples:
- `samples/models/vulnerable/malicious_model.pkl` - PyTorch file with an `os.system` payload
- `samples/models/safe/embeddings.safetensors` - data-only format, nothing to execute

**1. Scan the malicious model:**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit modelscan -p samples/models/vulnerable/malicious_model.pkl
```

```
--- Summary ---

Total Issues: 1

Total Issues By Severity:

    - LOW: 0
    - MEDIUM: 0
    - HIGH: 0
    - CRITICAL: 1

--- CRITICAL ---

Unsafe operator found:
  - Severity: CRITICAL
  - Description: Use of unsafe operator 'system' from module 'posix'
  - Source: /app/samples/models/vulnerable/malicious_model.pkl:malicious_model/data.pkl
```

modelscan also prints startup lines and `Errors` / `Skipped` sections for the other (non-pickle) entries inside the archive. Those are cosmetic - focus on the `Summary` and severity sections, shown above.

**2. Scan the SafeTensors model:**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit modelscan -p samples/models/safe/embeddings.safetensors
```

```
--- Summary ---

 No issues found! 🎉
```

modelscan flags the malicious file CRITICAL for the `system` operator and finds nothing in the SafeTensors file. Both checks read the files without loading them.

## Takeaway

Run modelscan on every model before it is loaded - it detects a payload without executing it. It covers multiple formats and rates severity; treat CRITICAL findings (`os.system`, `subprocess`) as automatic rejection. Static scanning detects known patterns only - a sophisticated attacker can obfuscate to evade it, so it is one layer of defence, used alongside integrity and provenance checks, not a guarantee on its own.

## References

- modelscan (Protect AI) - multi-format model scanner - https://github.com/protectai/modelscan

# Experiment 01 - Safe Serialisation Formats

## Scenario

A team pulls a model from an external source, such as a public hub, a vendor, or a colleague, and loads it into their pipeline. What they do not see is a payload inside the file that executes the moment `torch.load()` is called. It runs silently and the load completes without error, so nothing looks wrong. The only thing the attacker needed was for the victim to load the file, and the result is code execution on the machine running the pipeline, typically a host with access to data, credentials, and the training cluster.

## How it works

PyTorch serialises models using pickle, which supports a `__reduce__` method that embeds executable code. Any code in `__reduce__` runs automatically when the file is loaded - no explicit call needed. Before PyTorch 2.6, `weights_only=False` was the default, so this ran with no warning in most ML code in the wild.

Two controls stop it. Restricting the unpickler to tensors with `weights_only=True` blocks the call before it runs. Using SafeTensors avoids the problem entirely - it stores raw tensor bytes behind a JSON header and has no code execution path by design.

The payload command is stored as a literal string in the pickle, so it can be read straight out of the file with `strings` before the file is ever loaded.

```
malicious_model.pkl
│
├── strings | grep                 → payload command is plaintext in the file → no execution
│
├── torch.load(weights_only=False) → payload executes → file written to /tmp
│   (default in PyTorch < 2.6)
│
└── torch.load(weights_only=True)  → posix.system blocked → exception raised → no execution

embeddings.safetensors
│
└── safe_open()                    → JSON header parsed → tensor bytes read → no code possible
```

## Run

Samples:
- `samples/models/vulnerable/malicious_model.pkl` - pickle with an `os.system` payload in `__reduce__`
- `samples/models/safe/embeddings.safetensors` - safetensors, data-only format

Four proofs, run in order, each a single command.

**1. Prove the file contains a malicious command, without loading it:**

Run `strings` on the file and grep for the command. The payload is stored as plaintext, so it shows up directly - no loading, no execution:

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit bash -c "strings samples/models/vulnerable/malicious_model.pkl | grep tmp"
```

```
echo 'ai-gate: pickle payload executed' > /tmp/ai_gate_pickle_pwned.txtq
```

The file plainly contains a shell command that writes to `/tmp`. This is enough to reject it before any load. The trailing `q` is the next pickle opcode byte (`BINPUT`) that happens to be printable, so `strings` shows it joined to the command.

**2. Prove loading the file runs that command:**

Load the model, then check `/tmp` for the file the payload writes:

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit bash -c "python3 -c \"import torch; torch.load('samples/models/vulnerable/malicious_model.pkl', weights_only=False)\"; ls /tmp/ai_gate_pickle_pwned.txt; cat /tmp/ai_gate_pickle_pwned.txt"
```

```
/tmp/ai_gate_pickle_pwned.txt
ai-gate: pickle payload executed
```

The file did not exist before the load. `torch.load()` ran the payload, which created it.

**3. Prove `weights_only=True` blocks it:**

Load the same file with the safe option and grep the error it raises:

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit bash -c "python3 -c \"import torch; torch.load('samples/models/vulnerable/malicious_model.pkl', weights_only=True)\" 2>&1 | grep blocked"
```

```
Trying to load unsupported GLOBAL posix.system whose module posix is blocked.
```

The load raises an error instead of running the payload. No `/tmp` file is created.

**4. Prove SafeTensors has no execution path:**

Read the SafeTensors file and list its tensors:

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit python3 -c "from safetensors import safe_open; f=safe_open('samples/models/safe/embeddings.safetensors', framework='np'); print(list(f.keys()))"
```

```
['embedding_0', 'embedding_1']
```

The file is read as pure data. The format cannot encode executable code, so there is no payload to run.

## Takeaway

For existing pickle-based workflows, always pass `weights_only=True`. For new model distribution, use SafeTensors. Both controls have limits: `weights_only=True` restricts pickle to tensor reconstruction but does not stop threats embedded in the model architecture, such as custom layers that execute code at inference time. SafeTensors removes code execution at load time, but a file extension cannot be trusted on its own - an attacker can ship a pickle file with a `.safetensors` name, so the actual file contents still need scanning (experiment 03).

## References

- Python pickle docs - https://docs.python.org/3/library/pickle.html
- PyTorch torch.load docs - https://pytorch.org/docs/stable/generated/torch.load.html
- SafeTensors specification - https://huggingface.co/docs/safetensors/index
- SafeTensors security audit (Trail of Bits, 2023) - https://huggingface.co/blog/safetensors-security-audit
- CVE-2023-6730 - deserialization of untrusted data (CWE-502) in Hugging Face Transformers before 4.36 - https://nvd.nist.gov/vuln/detail/CVE-2023-6730

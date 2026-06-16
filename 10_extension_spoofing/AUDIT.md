# Experiment 10 - Extension Spoofing

## Scenario

A team takes the advice from experiment 01 to heart: only load `safetensors`, never pickle. A file arrives named `model.safetensors`, so they load it, trusting the extension to mean the safe format. The file is actually a pickle with a payload, and the `.safetensors` name was just a label the attacker typed. Their rule checked the file's name, not its contents, and the filename is set by whoever created the file.

## How it works

A file extension is just text at the end of a filename. Whoever creates the file chooses it, and it carries no guarantee about what is actually inside. The real format is decided by the bytes. Those bytes start with a recognisable signature, the "magic":

- a pickle usually starts with the `\x80` PROTO opcode (protocol 2 and up); older protocols use plain ASCII opcodes and do not
- a PyTorch archive starts with `PK\x03\x04` (a ZIP)
- a safetensors file starts with an 8-byte little-endian header length, then a JSON object beginning with `{`

The robust approach is not to enumerate every bad format, it is to verify the file really is safetensors and reject anything that is not. `format_check.py` does exactly this: it confirms the 8-byte header length and a valid JSON header, and if that check fails it rejects the file whatever it is. The format labels it prints are a convenience, the `\x80` signature catches modern pickles, while an older-protocol pickle simply shows as `unknown`, but the decision is fail-closed: not provably safetensors means rejected. It never loads the file, so it runs offline and cannot trigger a payload.

This is the gap experiment 01 named in its own takeaway: a `.safetensors` extension cannot be trusted on its own, because an attacker can ship a pickle under that name. A "safetensors only" policy is only as strong as the check that enforces it, and an extension is not that check.

```
model.safetensors
        │
   read first bytes, ignore the name
        │
   ┌────┴────────────────────┐
 valid 8-byte length      anything else
 + '{' JSON header        (pickle, zip, garbage)
 = real safetensors       = name lied, reject (fail-closed)
```

## Run

Samples:
- `samples/models/safe/embeddings.safetensors` - a genuine safetensors file
- `samples/models/vulnerable/disguised_model.safetensors` - a pickle with an `os.system` payload, saved under a `.safetensors` name
- `10_extension_spoofing/format_check.py` - the magic-byte format check

**1. Check the disguised file:**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  -v $(pwd)/10_extension_spoofing:/app/check:ro \
  ai-audit python3 /app/check/format_check.py samples/models/vulnerable/disguised_model.safetensors
```

```
file:           disguised_model.safetensors
claimed (ext):  safetensors
actual (bytes): pickle
MISMATCH: named .safetensors but is actually pickle - reject before loading
```

The name says `safetensors`, but the first byte is `\x80`, the pickle opcode. The check calls it out and exits non-zero, so it can block a build, all without loading the file.

**2. Check a genuine safetensors file:**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  -v $(pwd)/10_extension_spoofing:/app/check:ro \
  ai-audit python3 /app/check/format_check.py samples/models/safe/embeddings.safetensors
```

```
file:           embeddings.safetensors
claimed (ext):  safetensors
actual (bytes): safetensors
ok: contents match the extension
```

The real file's bytes match its name, so it passes.

**3. Why it matters: the file is a pickle, not data:**

Treating the disguised file as the pickle it really is runs its payload:

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit sh -c "python3 -c \"import pickle; pickle.load(open('samples/models/vulnerable/disguised_model.safetensors','rb'))\"; cat /tmp/ai_gate_disguised.txt 2>&1"
```

```
ai-gate: disguised pickle executed
```

A real safetensors file is pure data and could never do this. This file ran a shell command, because despite the `.safetensors` name it is a pickle. The extension told you nothing about whether it was safe.

A strict safetensors parser does not execute this file: `safetensors.safe_open` on it fails with `SafetensorError: header too large` and runs nothing, because the pickle bytes are not a valid safetensors header. The risk appears when something reaches the file through a pickle path instead: `torch.load`, which auto-detects and falls back to pickle, or code that calls `pickle.load` on a file because the name looked safe. The byte check rejects the file before it can reach one of those paths.

## Takeaway

Decide a file's format from its bytes, not its name, and do it before you load it or before you wave it through as "the safe format". A "safetensors only" rule protects you only if something actually verifies that each file is safetensors, and a filename is not that verification. Add a magic-byte check at your ingest point and reject any mismatch. One limit: confirming a file truly is safetensors tells you it cannot carry code, but confirming a file truly is a pickle does not make that pickle safe, so a file that genuinely is the format it claims still goes through scanning (experiment 03) and the load-time controls (experiments 01 and 08).

## References

- SafeTensors format specification (the 8-byte header length and JSON header) - https://github.com/huggingface/safetensors#format
- Python pickle docs (the `\x80` PROTO opcode and pickle structure) - https://docs.python.org/3/library/pickle.html
- ZIP file format signature `PK\x03\x04` - https://en.wikipedia.org/wiki/ZIP_(file_format)

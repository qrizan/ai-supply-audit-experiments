# Experiment 02 - Integrity Verification

## The risk

A model file is swapped or modified somewhere between the author publishing it and the team loading it - on a mirror, in transit, or in a shared registry. The file name, extension, and format all look correct, so nothing seems wrong. The weights inside, however, are not the ones the author released. Without a way to confirm the file matches what was published, the team has no way to notice the substitution.

## How it works

A checksum is a fixed-length string computed from the entire contents of a file. Change a single byte and the checksum changes completely. SHA-256 is the standard used for file integrity in ML pipelines. The author publishes the expected SHA-256 of each file; the consumer recomputes it on the received file and compares. A match confirms the file was not altered in transit. A mismatch means the file is not what the author published - it must be rejected.

This check confirms integrity (the file is unchanged), not provenance (who published it). For the stronger guarantee of who signed a file, see the cryptographic signing references below.

```
checksums.json (expected)        file on disk (actual)
        │                                │
        └──────────► sha256sum ◄─────────┘
                        │
            ┌───────────┴───────────┐
         match                   mismatch
       file is intact        file was altered - reject
```

## Run

Samples:
- `samples/models/checksums.json` - expected SHA-256 hashes published with the models
- `samples/models/safe/sentiment_model.pkl`, `samples/models/safe/embeddings.safetensors` - files that match
- `samples/models/vulnerable/tampered_embeddings.safetensors` - file recorded in `checksums.json` but altered after publication

**1. Show the expected hashes:**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit cat samples/models/checksums.json
```

```
{
  "sentiment_model.pkl": "dcdfecefedc1e08d93fd43b2ee59121cae74c69e150010b23f1dd5bc5de63eb7",
  "embeddings.safetensors": "4be82d14f23862dfadf92e0cf530d98b8f763186537856a99f21cc0f542c524b",
  "tampered_embeddings.safetensors": "111698349d591d8c29a64c9e82b48cae80dd7032add19f578e362302a5f23026"
}
```

**2. Compute the actual hashes and compare:**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit sha256sum \
    samples/models/safe/sentiment_model.pkl \
    samples/models/safe/embeddings.safetensors \
    samples/models/vulnerable/tampered_embeddings.safetensors
```

```
dcdfecefedc1e08d93fd43b2ee59121cae74c69e150010b23f1dd5bc5de63eb7  samples/models/safe/sentiment_model.pkl
4be82d14f23862dfadf92e0cf530d98b8f763186537856a99f21cc0f542c524b  samples/models/safe/embeddings.safetensors
14bc154694cb6402e5cb92a68301b4a80410a7f547d6bbd2b2fccb225789c229  samples/models/vulnerable/tampered_embeddings.safetensors
```

Compare each computed hash to the expected value:
- `sentiment_model.pkl` - matches, file is intact
- `embeddings.safetensors` - matches, file is intact
- `tampered_embeddings.safetensors` - computed `14bc...` does not match the published `1116...`, the file was altered and must be rejected

## Takeaway

Recompute the SHA-256 of every model on receipt and compare it to the value the author published. A mismatch means the file changed after publication - reject it. A checksum only proves the file is unchanged; it does not prove who published it. For that, look for cryptographic signatures on the model artefact, which verify the publisher as well as the contents.

## References

- GNU coreutils sha256sum - https://www.gnu.org/software/coreutils/manual/html_node/sha2-utilities.html
- NIST FIPS 180-4, Secure Hash Standard (SHS) - https://csrc.nist.gov/pubs/fips/180-4/upd1/final
- Sigstore model signing - https://github.com/sigstore/model-transparency

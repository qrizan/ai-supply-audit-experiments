# Experiment 07 - Provenance and Signing

## Scenario

A team downloads a model and the checksum published next to it, recomputes the hash, gets a clean match, and loads the file. The weights are an attacker's. Whoever swapped the file on the mirror updated the checksum beside it at the same time, and a hash recomputed from a file will always match a hash the attacker chose for it. The check confirmed the file was intact; it did not confirm the file came from the publisher the team trusts. Nothing in the check reveals the substitution, because it only asked whether the file was unchanged, not where it came from.

## How it works

A digital signature binds a file to the holder of a private key. The publisher signs the file with a private key only they hold; anyone can verify with the matching public key. Verification answers two questions at once: the file is unchanged (integrity) and it was signed by the holder of that key (provenance). Change one byte and the signature no longer matches. Sign with a different key and verification against the expected public key fails. The consumer needs only the publisher's public key, obtained once from a trusted source, instead of a per-file checksum they have to trust separately.

This is the control experiment 02 pointed to. A checksum proves integrity only if you already trust the checksum's source. A signature moves that trust onto a single public key you verify once, and then proves origin as well as integrity for every file signed with it.

cosign (Sigstore) performs the signing and verification. This experiment uses a local key pair so the whole flow runs offline under `--network none`. The full Sigstore workflow goes further: keyless signing tied to an OIDC identity, recorded in a public transparency log (Rekor), which is what makes "who signed it" auditable without anyone managing long-lived keys. That part needs network, and cosign warns about its absence here with the `Skipping tlog verification` message. The local-key flow below is the cryptographic core of it.

```
publisher                              consumer
   │ sign with PRIVATE key                │ verify with PUBLIC key
   ▼                                       ▼
model + signature ──────────────────►  does it match this key and file?
                                           ├─ yes  → authentic and intact
                                           └─ no   → tampered or wrong signer, reject
```

## Run

Samples:
- `samples/models/safe/embeddings.safetensors` - the model the publisher signs
- `samples/models/vulnerable/tampered_embeddings.safetensors` - a modified copy, to show verification fails
- `07_provenance_signing/sign_and_verify.sh` - the sign-and-verify flow (each `cosign` command is visible in the script)

The demo generates a key pair, signs the model, then runs three verifications: the genuine file, a tampered file, and the genuine file against a different key.

```bash
docker run --rm --network none -e COSIGN_PASSWORD="" \
  -v $(pwd)/samples:/app/samples:ro \
  -v $(pwd)/07_provenance_signing:/app/check:ro \
  ai-audit sh /app/check/sign_and_verify.sh
```

```
Publisher: generate a key pair and sign the model
  signed embeddings.safetensors -> embeddings.sig (cosign.pub is the public key)

Consumer: verify each file against a public key
  embeddings.safetensors           with publisher key  -> PASS (authentic and intact)
  tampered_embeddings.safetensors  with publisher key  -> FAIL (rejected)
  embeddings.safetensors           with attacker key   -> FAIL (rejected)
```

Each verify line names the file checked, the public key used, and the verdict. The genuine file with the publisher's key passes. The tampered file with the same key fails because its bytes no longer match the signature, which is the integrity property a checksum also gives. The genuine file checked against a different key fails too, which is the provenance property a checksum cannot give: it is not enough for the file to be intact, it must be intact *and* signed by the key you expected. PASS/FAIL reflects cosign's exit status; the script hides cosign's per-call `Skipping tlog` warning, which only notes that the transparency log was bypassed because the run is offline.

## Takeaway

Sign the artifacts you publish, and verify signatures on the artifacts you consume against a public key you obtained from a trusted source out of band. A signature gives provenance and integrity in one check, which a checksum alone cannot. Two limits matter. A signature is only as trustworthy as your confidence that the public key really belongs to the publisher, so key distribution is the hard part, not the maths. And the local-key flow here skips the transparency log, so for production prefer keyless Sigstore with Rekor (see model-transparency) where verification ties to an identity and a public, auditable record. A signature proves who produced a file and that it is unchanged; it does not prove the model is safe, so keep running the load-time and scanning checks from experiments 01 and 03.

## References

- cosign (Sigstore) - signing and verification - https://github.com/sigstore/cosign
- Sigstore model-transparency - signing for ML models - https://github.com/sigstore/model-transparency
- Rekor - Sigstore transparency log - https://github.com/sigstore/rekor
- The Update Framework (TUF) - securing software distribution - https://theupdateframework.io/

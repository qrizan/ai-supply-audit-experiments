#!/bin/sh
# Provenance demo: a publisher signs a model with a private key, then a consumer
# verifies it with the matching public key. A tampered file and a wrong key are
# both rejected. Fully offline: a local cosign key pair, no transparency log.
#
# PASS/FAIL below reflects cosign's exit status (0 = verified, non-zero =
# rejected). cosign's own "Skipping tlog" warning and raw error text are hidden
# so each line reads as "file + key -> verdict".
set -e
cd /tmp
cp /app/samples/models/safe/embeddings.safetensors embeddings.safetensors
cp /app/samples/models/vulnerable/tampered_embeddings.safetensors tampered_embeddings.safetensors

# verify <file> <public-key> <key-label>
verify() {
  printf '  %-32s with %-14s -> ' "$1" "$3"
  if cosign verify-blob --key "$2" --signature embeddings.sig \
       --insecure-ignore-tlog "$1" >/dev/null 2>&1; then
    echo "PASS (authentic and intact)"
  else
    echo "FAIL (rejected)"
  fi
}

echo "Publisher: generate a key pair and sign the model"
cosign generate-key-pair >/dev/null 2>&1
cosign sign-blob --key cosign.key --tlog-upload=false --yes \
  embeddings.safetensors --output-signature embeddings.sig >/dev/null 2>&1
echo "  signed embeddings.safetensors -> embeddings.sig (cosign.pub is the public key)"

# a second, unrelated key pair, standing in for an attacker's key
mkdir -p attacker && (cd attacker && cosign generate-key-pair >/dev/null 2>&1)

echo
echo "Consumer: verify each file against a public key"
verify embeddings.safetensors          cosign.pub          "publisher key"
verify tampered_embeddings.safetensors cosign.pub          "publisher key"
verify embeddings.safetensors          attacker/cosign.pub "attacker key"

# Experiment 06 - Software Bill of Materials (SBOM)

## Scenario

A new advisory drops for a widely used library, and the question lands on the team: are we shipping the affected version anywhere. Without a record of what is inside each artifact, answering it means re-discovering the contents of every model bundle, image, and service by hand, under time pressure, while the window of exposure stays open. The components were always there; what was missing was a written inventory. You cannot audit, patch, or even reason about a component you do not know you have.

## How it works

A Software Bill of Materials is a complete, machine-readable list of the components inside an artifact, written in a standard format so any tool can read it. The two common formats are CycloneDX and SPDX. syft (Anchore) catalogs the components of a source, a requirements file, a directory, a container image, or a whole filesystem, and emits the SBOM.

Each component carries a package URL (purl) such as `pkg:pypi/requests@2.33.0`, which names the ecosystem, package, and version unambiguously. That purl is the key a vulnerability scanner matches against advisories, which is exactly how the dependency audit in experiment 04 decides what is affected. The SBOM is the inventory, "what is here"; the audit is the assessment, "which of these is dangerous". The audit depends on the inventory: you can only check what you know you have.

Cataloging reads metadata only and resolves nothing over the wire, so it runs fully offline under `--network none`. The one network call syft makes is an optional self-update check, which `SYFT_CHECK_FOR_APP_UPDATE=false` turns off so the run stays clean. The intended workflow is to generate the SBOM once, store it alongside the artifact, and re-query that stored file whenever a new advisory lands, without ever touching the original again.

```
artifact (requirements / directory / image)
        │
        └──► syft ──► SBOM (CycloneDX or SPDX)
                          │
              ┌───────────┴────────────┐
        store it                  feed purls to a scanner
        (answer "what is here"     (experiment 04: "which are
         later, instantly)          vulnerable")
```

## Run

Samples:
- `samples/requirements/safe_requirements.txt` - the artifact whose contents we inventory

**1. Human-readable inventory:**

```bash
docker run --rm --network none -e SYFT_CHECK_FOR_APP_UPDATE=false \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit syft file:/app/samples/requirements/safe_requirements.txt
```

```
NAME         VERSION  TYPE
numpy        1.26.4   python
pillow       12.2.0   python
requests     2.33.0   python
safetensors  0.4.3    python
```

**2. Standard machine-readable SBOM (CycloneDX), saved to a file:**

```bash
docker run --rm --network none -e SYFT_CHECK_FOR_APP_UPDATE=false \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit syft file:/app/samples/requirements/safe_requirements.txt -o cyclonedx-json \
  > sbom.cdx.json
```

The saved file looks like this (trimmed to the key fields; the real output also carries `bom-ref` ids and `properties`):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "file",
      "name": "safe_requirements.txt",
      "version": "sha256:ca46701b...9636fa7"
    }
  },
  "components": [
    { "type": "library", "name": "numpy",       "version": "1.26.4", "purl": "pkg:pypi/numpy@1.26.4" },
    { "type": "library", "name": "pillow",      "version": "12.2.0", "purl": "pkg:pypi/pillow@12.2.0" },
    { "type": "library", "name": "requests",    "version": "2.33.0", "purl": "pkg:pypi/requests@2.33.0" },
    { "type": "library", "name": "safetensors", "version": "0.4.3",  "purl": "pkg:pypi/safetensors@0.4.3" },
    { "type": "file",    "name": "/app/samples/requirements/safe_requirements.txt",
      "hashes": [ { "alg": "SHA-256", "content": "ca46701b...9636fa7" } ] }
  ]
}
```

Every library has a purl a scanner can act on, and the source file itself is recorded with its SHA-256, which ties the inventory back to the integrity check in experiment 02. This one file is now a durable answer to "what is in this artifact".

## Takeaway

Generate an SBOM for every artifact you ship or consume, store it, and treat it as the inventory the rest of your supply-chain checks build on. Its value shows up later: when a new advisory lands, you query stored SBOMs instead of rescanning everything, and you can diff two SBOMs to see exactly what a rebuild changed. Two limits matter. An SBOM only lists what the cataloger could see, so vendored or statically linked code can be missed, and an SBOM is a snapshot, so it has to be regenerated when the artifact changes. It records what is present; it does not say what is safe. Pair it with the audit (experiment 04) for vulnerabilities and the name check (experiment 05) for trust.

## References

- syft (Anchore) - SBOM generator - https://github.com/anchore/syft
- CycloneDX specification - https://cyclonedx.org/specification/overview/
- SPDX specification - https://spdx.dev/
- Package URL (purl) specification - https://github.com/package-url/purl-spec
- NTIA, "The Minimum Elements For a Software Bill of Materials (SBOM)" (2021) - https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom

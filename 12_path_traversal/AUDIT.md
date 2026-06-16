# Experiment 12 - Path Traversal on Extraction

## Scenario

Models routinely arrive as archives: a PyTorch `.pt`/`.pth` file is a ZIP (the malicious sample in experiment 01 began with `PK\x03\x04`), and checkpoints and datasets are commonly shipped as `.tar.gz`. So a team downloads a model bundle and unpacks it into a working directory with the obvious one-liner, `tarfile.extractall()`. Most of the entries are ordinary, `model/weights.bin` and friends, but one is named `../ai_gate_escaped.txt`. As the archive extracts, that entry is written outside the target directory, into a location the team never chose. No model was loaded, no pickle was involved, no code ran from inside a file. The damage was done by the act of unpacking, because the extractor trusted the paths the archive author wrote.

> Note: path traversal on extraction is not specific to AI. It is a general archive-handling flaw (CVE-2007-4559) that affects any software unpacking an untrusted archive. It is included here because models and datasets are distributed as archives and ML pipelines routinely extract them, often automatically and as root, so the flaw falls on the path a model takes into a system.

## How it works

Every entry in a tar archive carries a name, and that name is a path chosen by whoever built the archive. A naive `extractall()` joins each name onto the target directory and writes it, so a name like `../../etc/cron.d/x` or `../weights/__init__.py` lands wherever the `..` sequence points. An attacker can use this to overwrite a file that gets imported or executed later, drop a file in an auto-run location, or plant credentials, all before the model is ever loaded. This is an old and well-known class, tracked as CVE-2007-4559, and re-disclosed at scale by Trail of Bits in 2022.

The fix is to never trust the entry path. Before writing anything, resolve where each member would actually land and confirm it stays inside the target directory; refuse the archive if any entry escapes or is a link that could escape. `safe_extract.py` does this check by hand so the rule is explicit. For each member it computes the real destination with `os.path.realpath(os.path.join(target, name))`, which follows both `..` and symlinks to the actual path, then confirms that path is still inside the target with `os.path.commonpath`. If any member resolves outside the target, or is a symlink or hard link, it refuses the whole archive and writes nothing. The check is fail-closed and runs before extraction, so a malicious bundle never lands a single file. Python 3.12 (backported to 3.11.4+) ships the same idea built in: `extractall(filter="data")` refuses members whose resolved path would fall outside the destination.

One detail worth knowing: extractors are not uniform. Python's `zipfile` already sanitises `..` out of entry names, so the same trick fails on a ZIP. `tarfile` does not sanitise by default, so it succeeds. Never assume "extracting an archive" is a single, safe operation.

```
archive entry name:  ../ai_gate_escaped.txt
        │
   naive extractall()  -> joins to target, follows ..  -> writes OUTSIDE target
   safe_extract.py     -> resolves path, sees it escapes -> refuses, writes nothing
   zipfile (same name) -> sanitises ..                  -> stays inside target
```

## Run

Samples:
- `samples/models/vulnerable/evil_bundle.tar` - a tar with a normal entry and one `../` traversal entry (benign marker payload)
- `12_path_traversal/safe_extract.py` - an extractor that validates each path before writing

**1. Naive extraction lets an entry escape:**

Extract the bundle into an `out` subdirectory, then list the whole tree to see where the files actually went:

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit sh -c "mkdir -p /tmp/job/out && cd /tmp/job && python3 -c \"import tarfile; tarfile.open('/app/samples/models/vulnerable/evil_bundle.tar').extractall('out')\" && find /tmp/job"
```

```
/tmp/job
/tmp/job/ai_gate_escaped.txt
/tmp/job/out
/tmp/job/out/model
/tmp/job/out/model/weights.bin
```

Everything the archive held should be under `/tmp/job/out`. `model/weights.bin` is, but `ai_gate_escaped.txt` is sitting in `/tmp/job`, a sibling of `out`, not inside it: one entry's `../` climbed a level out of the directory we extracted into. Nothing announced this, and the filename was not known in advance, it just turned up where it should not be. A real attacker would aim that `../` at a file the pipeline later imports.

**2. The safe extractor refuses the escaping entry:**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  -v $(pwd)/12_path_traversal:/app/check:ro \
  ai-audit python3 /app/check/safe_extract.py samples/models/vulnerable/evil_bundle.tar /tmp/safe_out
```

```
ok: model/weights.bin
REFUSED: '../ai_gate_escaped.txt' would extract outside /tmp/safe_out -> /tmp/ai_gate_escaped.txt
```

The normal entry passes, the traversal entry is caught by resolving its final path, and the archive is refused. Because the check runs before any write, nothing escaped and no file was created outside the target.

**3. The same entry name in a ZIP does not escape:**

Build a ZIP with the same `../` entry name, extract it into `out` the same way, and list the tree:

```bash
docker run --rm --network none ai-audit sh -c "mkdir -p /tmp/job2/out && cd /tmp/job2 && python3 -c \"import zipfile; zipfile.ZipFile('/tmp/b.zip','w').writestr('../escaped_via_zip.txt','x')\" && python3 -c \"import zipfile; zipfile.ZipFile('/tmp/b.zip').extractall('out')\" && find /tmp/job2"
```

```
/tmp/job2
/tmp/job2/out
/tmp/job2/out/escaped_via_zip.txt
```

This time the whole tree is under `/tmp/job2/out`: the file with the `../` name stayed inside the target. `zipfile` strips the `..`, `tarfile` does not. The guarantee has to come from your own check, not from "extraction" being uniformly safe.

## Takeaway

Unpacking a model bundle is part of the supply chain, and it is an attack surface on its own, before any model is loaded and without any code inside the files. When you extract an untrusted archive, validate that every entry's resolved path stays inside the target directory and refuse anything that escapes, or use `tarfile.extractall(filter="data")` on a recent Python. Do not assume all extractors behave the same: `tarfile` is unsafe by default while `zipfile` sanitises, so the guarantee has to come from your own check, not from the format. And as with every other experiment here, extract untrusted archives as a non-root user inside an isolated directory, so a missed escape still cannot reach anything that matters.

## References

- CVE-2007-4559 - directory traversal in Python `tarfile` extract/extractall via `..` in entry names - https://nvd.nist.gov/vuln/detail/CVE-2007-4559
- PEP 706 - Filter for tarfile.extractall (the `filter="data"` defense) - https://peps.python.org/pep-0706/
- Python tarfile docs - extraction filters - https://docs.python.org/3/library/tarfile.html#extraction-filters

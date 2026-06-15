#!/usr/bin/env python3
"""Flag dependency names that look like typosquats of popular packages.

Static check only: it reads names from a requirements file and compares them
to a curated list of popular packages by string similarity. Nothing is
resolved, downloaded, or installed, so this runs fully offline.

A name that exactly matches a known package is fine. A name that is highly
similar to a known package but not identical is a likely typosquat. A name
that resembles nothing on the list is unknown, not proven safe.

Exit code is non-zero when anything is flagged, so it can gate a build.
"""
import re
import sys
from difflib import SequenceMatcher, get_close_matches

# A curated set of popular packages a typosquat would imitate. A real pipeline
# would use a much larger, maintained allowlist of approved package names.
POPULAR = {
    "requests", "urllib3", "certifi", "idna", "charset-normalizer",
    "numpy", "scipy", "pandas", "pillow", "scikit-learn", "matplotlib",
    "torch", "tensorflow", "transformers", "safetensors", "huggingface-hub",
    "python-dateutil", "pyyaml", "setuptools", "wheel", "flask", "fastapi",
}

# Similarity ratio above which two names are treated as confusingly similar.
SIMILARITY = 0.80


def parse_names(path):
    """Return lowercased package names from a requirements file."""
    names = []
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # drop version specifiers, extras, and environment markers
            name = re.split(r"[<>=!~;\[ ]", line, 1)[0].strip().lower()
            if name:
                names.append(name)
    return names


def closest(name):
    """Return (closest_popular_name, ratio) or (None, 0.0)."""
    match = get_close_matches(name, POPULAR, n=1, cutoff=SIMILARITY)
    if not match:
        return None, 0.0
    return match[0], SequenceMatcher(None, name, match[0]).ratio()


def main(path):
    flagged = []
    for name in parse_names(path):
        if name in POPULAR:
            print(f"OK       {name}  (exact match to a known package)")
            continue
        target, ratio = closest(name)
        if target:
            print(f"SUSPECT  {name}  ->  looks like '{target}' (similarity {ratio:.2f})")
            flagged.append((name, target))
        else:
            print(f"UNKNOWN  {name}  (not similar to any known package; verify the source)")

    print()
    if flagged:
        print(f"Flagged {len(flagged)} possible typosquat(s). Reject until verified.")
        return 1
    print("No typosquats detected against the known-package list.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: typosquat_check.py <requirements.txt>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))

#!/usr/bin/env python3
"""A minimal stand-in for transformers' from_pretrained(trust_remote_code=...).

It mirrors the real mechanism: read config.json, and if the model declares custom
code in "auto_map", run that code only when remote code is trusted. Two things are
simplified to stay light and offline, and neither changes the lesson:
  - the custom .py is read from a local model directory instead of being
    downloaded from the Hugging Face Hub
  - the loader is hand-rolled instead of installing transformers
The step that matters - importing and running repo-provided code, gated by a
flag - is identical to the real library.
"""
import importlib
import json
import sys
from pathlib import Path


def load(model_dir, trust_remote_code):
    model_dir = Path(model_dir)
    config = json.loads((model_dir / "config.json").read_text())

    # the weights are a data-only safetensors file: there is no code in them
    from safetensors import safe_open
    with safe_open(str(model_dir / "weights.safetensors"), framework="np") as f:
        print(f"weights.safetensors loaded: {list(f.keys())} (data only, no code)")

    auto_map = config.get("auto_map")
    if not auto_map:
        print("no custom code declared; nothing to trust")
        return

    target = auto_map["AutoModel"]          # e.g. "modeling_evil.EvilModel"
    module_name, class_name = target.split(".")
    print(f"this model declares custom code: {target}")

    if not trust_remote_code:
        print("REFUSED: this model requires remote code; "
              "re-run with trust_remote_code=True to allow it")
        return

    print("trust_remote_code=True -> importing and running the model's own code")
    sys.path.insert(0, str(model_dir))
    module = importlib.import_module(module_name)   # runs the module's top-level code
    getattr(module, class_name)()                   # instantiate the custom class
    print("custom model instantiated")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("trust", "notrust"):
        print("usage: load_model.py <trust|notrust> <model_dir>", file=sys.stderr)
        sys.exit(2)
    load(sys.argv[2], sys.argv[1] == "trust")

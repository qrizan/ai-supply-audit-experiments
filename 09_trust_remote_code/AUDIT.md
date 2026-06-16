# Experiment 09 - Trusting Remote Code

## Scenario

A team wants to use a popular model from a public hub. Loading it fails with a message: this model requires `trust_remote_code=True`. Plenty of legitimate models say the same, so the team sets the flag and moves on. What that flag actually means is: download the Python files the model author put in the repo and run them in our process. The author's code runs at load time, before any inference, with the team's privileges. Nothing was hidden: enabling the flag is what allowed the author's code to run.

## How it works

In plain terms: a normal model is just data, and loading it is like opening a PDF, it cannot act on its own. A `trust_remote_code` model is different, it carries its own small program, and the flag is you agreeing to run that program. Think of an email attachment where the document is harmless but a script is bundled next to it, and the flag is you clicking "yes, run it".

Some models ship more than weights: they include their own Python (`modeling_*.py`) and point to it from `config.json` under an `auto_map` key. When you load such a model with remote code trusted, the loader imports that file and runs it. The class named in the config is instantiated, and any code in the module runs as it imports. It is arbitrary Python from a third party, executing with your permissions.

This is the same outcome as the pickle payload in experiment 01, code execution at load, but reached a different way. The pickle hides code inside the weights file and runs it without consent. This runs code from a separate file, with your explicit `trust_remote_code=True`. One is smuggled; the other is sanctioned. Both confirm the theme that loading a model can mean running code.

The safe-format advice from experiment 01 does not help here. The weights below are a clean `safetensors` file with no code in them, yet the model still runs arbitrary code, because the code lives in a sidecar `.py`, not in the weights. Switching weights to safetensors closes one door; remote code is a different door.

One more trap: the remote code can change after you first trusted it. Unless you pin the model to a specific revision, a later push to the repo means you silently run new code on the next load.

```
config.json (auto_map -> modeling_evil.EvilModel)
        │
   load with trust_remote_code = ?
        │
   ┌────┴─────────────────────────┐
 False                          True
 refuse, code never imported    import modeling_evil.py -> code runs at load
```

> This experiment hand-rolls a minimal loader and reads the custom `.py` from a local directory, instead of installing `transformers` and downloading from the Hub, so it stays light and offline. The mechanism that matters, importing and running repo-provided code gated by a flag, is identical to the real library.

## Run

Samples:
- `samples/models/remote_code_model/` - a model directory: clean `weights.safetensors`, a `config.json` with an `auto_map`, and `modeling_evil.py` whose code runs on import
- `09_trust_remote_code/load_model.py` - a minimal stand-in for `from_pretrained(trust_remote_code=...)`

**1. Default: refuse the remote code:**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  -v $(pwd)/09_trust_remote_code:/app/check:ro \
  ai-audit sh -c "python3 /app/check/load_model.py notrust samples/models/remote_code_model; ls /tmp/ai_gate_remote_code.txt 2>&1"
```

```
weights.safetensors loaded: ['embedding_0', 'embedding_1'] (data only, no code)
this model declares custom code: modeling_evil.EvilModel
REFUSED: this model requires remote code; re-run with trust_remote_code=True to allow it
ls: cannot access '/tmp/ai_gate_remote_code.txt': No such file or directory
```

The weights load fine and are pure data. The loader sees that the model declares custom code and, because remote code is not trusted, refuses to import it. Nothing from the author runs, and no marker file is created.

**2. Trust the remote code: the author's code runs:**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  -v $(pwd)/09_trust_remote_code:/app/check:ro \
  ai-audit sh -c "python3 /app/check/load_model.py trust samples/models/remote_code_model; cat /tmp/ai_gate_remote_code.txt 2>&1"
```

```
weights.safetensors loaded: ['embedding_0', 'embedding_1'] (data only, no code)
this model declares custom code: modeling_evil.EvilModel
trust_remote_code=True -> importing and running the model's own code
custom model instantiated
ai-gate: remote code executed
```

Same model, same clean weights, but trusting the remote code imported `modeling_evil.py` and ran its payload, which wrote the marker file. The only difference between the two runs is the flag. Note that experiment 01's safe-format control did not help: the weights were clean safetensors throughout, and the code ran anyway because it lived in the sidecar `.py`.

## Where this appears in real code

In a real project you do not run a separate loader. The flag goes inside the normal load call, as one argument:

```python
from transformers import AutoModel

model = AutoModel.from_pretrained(
    "some-org/some-model",
    trust_remote_code=True,   # this one argument lets the model's own .py download and run
)
```

That single argument is the whole decision. `load_model.py` in this experiment is a small stand-in for that `from_pretrained` call: its `trust` and `notrust` arguments map to `trust_remote_code=True` and `False`. People usually reach this line because loading the model without the flag fails with an error telling them to add it, which is exactly how the habit of setting it forms.

## Takeaway

Treat `trust_remote_code=True` as what it is: permission to run a stranger's Python on your machine. Leave it off by default, and turn it on only for code you have actually read, from a publisher you have reason to trust. When you must use it, pin the model to a specific revision so the code cannot change under you, and load it inside a sandbox, because trusting the code does not make it safe. Safetensors weights do not protect you here, the danger is in the sidecar code, not the weights. The durable habit is the same one running through every experiment: loading a model is running code, so decide whose code you are willing to run, and contain it when you do.

## References

- Hugging Face - models with custom code and `trust_remote_code` - https://huggingface.co/docs/transformers/en/models#custom-models
- Hugging Face - building custom models and the `auto_map` config - https://huggingface.co/docs/transformers/en/custom_models
- Python importlib - https://docs.python.org/3/library/importlib.html

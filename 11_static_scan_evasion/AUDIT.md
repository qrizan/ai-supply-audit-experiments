# Experiment 11 - Static Scan Evasion

## Scenario

An attacker knows the defender runs modelscan on every model before loading it, the control from experiment 03. So they write the payload to avoid the patterns modelscan looks for. The dangerous call never appears where the scanner can see it: the pickle reaches code execution through a helper the scanner's list does not cover, and the actual `os.system` is just text inside a string. The scan comes back clean, the team treats that as a pass and loads the model, and the payload runs. The scanner was not defeated; the payload used an operator that is not on its list.

## How it works

modelscan inspects a pickle's `GLOBAL` opcodes and flags any that reference a name on its list of unsafe operators (`os`, `posix`, `subprocess`, `eval`, `exec`, `__import__`, `getattr`, `runpy`, `operator.attrgetter`, and more). That list is a blocklist, and a blocklist can only catch what it enumerates.

The evasion uses a code-execution helper that is *not* on the list. We did not guess it: we read modelscan's own list (`modelscan/settings.py`, the `unsafe_globals` table in version 0.8.8, the version in this image) and looked for a module that runs code but is absent. `cProfile.run(code_string)` executes its string argument, and `cProfile` is not on the list. This specific bypass is therefore tied to that version: a later modelscan could add `cProfile` to the list and close it. The general point, that a blocklist only catches what it enumerates, does not depend on the version. So the malicious pickle calls `cProfile.run("import os; os.system(...)")` instead of `os.system(...)` directly. The only `GLOBAL` opcode in the file is `cProfile.run`; the string `os.system` is just bytes inside a string literal, not a global the scanner resolves. modelscan sees nothing it recognises and reports clean.

This is not a bug in modelscan, it is the inherent limit of pattern matching: a clean static scan means "no known-bad pattern was found", not "safe". The same payload behaves identically at load, so the behavioural check from experiment 08 still catches it: the payload must still call `os.system` at runtime, and the hook sees that call.

```
direct pickle           -> GLOBAL os.system        -> modelscan: CRITICAL (caught)
evasion pickle          -> GLOBAL cProfile.run      -> modelscan: no issues (missed)
                           "os.system" only a string
both, when loaded       -> os.system actually runs  -> audit hook (exp 08): caught
```

## Run

Samples:
- `samples/models/vulnerable/malicious_model.pkl` - calls `os.system` directly (from experiment 01)
- `samples/models/vulnerable/evasion_model.pkl` - reaches `os.system` through `cProfile.run`, to dodge the scanner
- the behavioural check from experiment 08 is reused for the runtime step

**1. Scan the evasion pickle (modelscan misses it):**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit modelscan -p samples/models/vulnerable/evasion_model.pkl
```

```
No settings file detected at /app/modelscan-settings.toml. Using defaults.

Scanning /app/samples/models/vulnerable/evasion_model.pkl using modelscan.scanners.PickleUnsafeOpScan model scan

--- Summary ---

 No issues found! 🎉
```

modelscan did scan the file (the `PickleUnsafeOpScan` line), it just found nothing to flag, because the only global it saw was `cProfile.run`.

**2. Scan the direct pickle (modelscan catches it):**

This is the control: the same scanner flags the straightforward payload, confirming the tool works and that the miss above is the evasion, not a broken scan.

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit modelscan -p samples/models/vulnerable/malicious_model.pkl
```

```
Scanning /app/samples/models/vulnerable/malicious_model.pkl using modelscan.scanners.PickleUnsafeOpScan model scan
Scanning /app/samples/models/vulnerable/malicious_model.pkl:malicious_model/data.pkl using modelscan.scanners.PickleUnsafeOpScan model scan

--- Summary ---

Total Issues: 1

Total Issues By Severity:

    - LOW: 0
    - MEDIUM: 0
    - HIGH: 0
    - CRITICAL: 1

--- Issues by Severity ---

--- CRITICAL ---

Unsafe operator found:
  - Severity: CRITICAL
  - Description: Use of unsafe operator 'system' from module 'posix'
  - Source: /app/samples/models/vulnerable/malicious_model.pkl:malicious_model/data.pkl
```

(modelscan also prints a startup settings line and, for this archive, `Errors` and `Skipped` sections for the non-pickle entries; those are cosmetic, the Summary is the result.)

**3. The evasion is real: it runs when loaded:**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  ai-audit sh -c "python3 -c \"import pickle; pickle.load(open('samples/models/vulnerable/evasion_model.pkl','rb'))\" >/dev/null 2>&1; cat /tmp/ai_gate_evasion.txt 2>&1"
```

```
ai-gate: evasion payload executed
```

The pickle modelscan called clean executed a shell command on load.

**4. The behavioural check catches what the scanner missed:**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  -v $(pwd)/08_behavioural_analysis:/app/check:ro \
  ai-audit python3 /app/check/behaviour_check.py block samples/models/vulnerable/evasion_model.pkl
```

```
loading samples/models/vulnerable/evasion_model.pkl  (mode: block)
[audit] sensitive operation during load: os.system (b"echo 'ai-gate: evasion payload executed' > /tmp/ai_gate_evasion.txt",)
         4 function calls in 0.000 seconds

   Ordered by: standard name

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.000    0.000    0.000    0.000 <string>:1(<module>)
        1    0.000    0.000    0.000    0.000 {built-in method builtins.exec}
        1    0.000    0.000    0.000    0.000 {built-in method posix.system}
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}


[blocked] load aborted: blocked os.system - the operation never ran
```

The indirection through `cProfile.run` hid the call from the static scanner, but at runtime the payload still has to call `os.system`, and the audit hook fires on it regardless of how it was reached. The cProfile table is the profiler's own output, and it shows the call chain: `builtins.exec` ran the hidden string, which called `posix.system`, the chain the scanner could not see and the hook caught.

## Takeaway

A clean static scan means no known-bad pattern was found, not that a file is safe. Blocklist scanners like modelscan are valuable and they catch the common, direct payloads, but a determined attacker who can read the same blocklist can route around it, so do not treat a green scan as the final word. Defend in depth: keep static scanning (experiment 03) as a cheap first filter, add a runtime behavioural check (experiment 08) that watches the actual operations an evasion cannot avoid performing, and run everything inside isolation. Better still, avoid the pickle attack surface entirely where you can (safetensors, experiment 01): evasion only matters because there is a pickle to scan in the first place.

## References

- modelscan (Protect AI) and its `unsafe_globals` list - https://github.com/protectai/modelscan
- fickling (Trail of Bits) - a pickle decompiler and security analysis tool that documents these evasion techniques - https://github.com/trailofbits/fickling
- Python pickle docs - https://docs.python.org/3/library/pickle.html
- Python cProfile docs (`cProfile.run` executes a statement string) - https://docs.python.org/3/library/profile.html

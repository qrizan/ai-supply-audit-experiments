# Experiment 08 - Behavioural Analysis

## Scenario

A model loads in a pipeline and, in the same instant, runs a shell command that was never supposed to be there: writing a file, spawning a process, or opening a connection back to the attacker. The load returns normally and the model works afterwards, so nothing looks wrong. Static scanning (experiment 03) would have flagged the payload, but a scanner only catches patterns it recognises, and an obfuscated or novel payload can slip past it. Once that file is already loading in production, the only thing left that can catch the payload is watching what the process actually does, as it does it.

## How it works

Static analysis reads a file and asks "does it contain a known-bad pattern". Behavioural (dynamic) analysis runs the file and asks "what does it actually do". The difference matters: a scanner has to recognise the attack in advance, while this reacts to the dangerous action itself, so it can catch an attack no one has seen before. A payload can obfuscate its bytes to dodge a scanner, but to have any effect it still has to call `os.system`, spawn a process, or open a socket, and those calls are observable.

Python exposes them through its audit subsystem (PEP 578). At every security-sensitive operation, the interpreter calls `sys.audit(event, args)`: running a shell command raises `os.system`, spawning a process raises `subprocess.Popen`, a network connection raises `socket.connect`. A hook installed with `sys.addaudithook` receives every such event and can either log it or raise, and raising from the hook aborts the operation before it happens.

The guard here, `behaviour_check.py`, installs such a hook and then loads the model. It is the dynamic counterpart to experiment 03: the scanner catches the malicious `GLOBAL posix system` opcode by reading the file; the hook catches the same payload one step later, at the `REDUCE` opcode, the moment `os.system` is actually called. Two modes show the two uses:

```
                load the model
                      │
        sys.audit("os.system", cmd) fires
                      │
        ┌─────────────┴─────────────┐
     observe                      block
   log it, let it run        raise, operation never happens
   (monitoring)              (active tripwire)
```

This is a tripwire for observability, not a security boundary. The hook runs in the same process as the model code, so a determined payload can use lower-level calls that raise no Python audit event, or act before the hook is reached. The real containment stays at the OS level: the container, `--network none`, a non-root user, seccomp. The hook tells you what the code tried to do; the container makes sure it cannot actually cause harm.

## Run

Samples:
- `samples/models/vulnerable/malicious_model.pkl` - the pickle whose payload runs `os.system` at load (from experiment 01)
- `08_behavioural_analysis/behaviour_check.py` - installs the audit hook, takes a mode (`observe` or `block`)

**1. Observe: watch the payload run, without stopping it:**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  -v $(pwd)/08_behavioural_analysis:/app/check:ro \
  ai-audit sh -c "python3 /app/check/behaviour_check.py observe samples/models/vulnerable/malicious_model.pkl; ls /tmp/ai_gate_pickle_pwned.txt 2>&1"
```

```
loading samples/models/vulnerable/malicious_model.pkl  (mode: observe)
[audit] sensitive operation during load: os.system (b"echo 'ai-gate: pickle payload executed' > /tmp/ai_gate_pickle_pwned.txt",)
load completed - the operation above was allowed to run
/tmp/ai_gate_pickle_pwned.txt
```

The hook prints the exact command the model tried to run, including the full shell string. Because the mode is `observe`, the command is allowed to proceed, so the marker file the payload writes is present afterwards. This is monitoring: you see the behaviour and record it.

**2. Block: stop the payload before it runs:**

```bash
docker run --rm --network none \
  -v $(pwd)/samples:/app/samples:ro \
  -v $(pwd)/08_behavioural_analysis:/app/check:ro \
  ai-audit sh -c "python3 /app/check/behaviour_check.py block samples/models/vulnerable/malicious_model.pkl; ls /tmp/ai_gate_pickle_pwned.txt 2>&1"
```

```
loading samples/models/vulnerable/malicious_model.pkl  (mode: block)
[audit] sensitive operation during load: os.system (b"echo 'ai-gate: pickle payload executed' > /tmp/ai_gate_pickle_pwned.txt",)
[blocked] load aborted: blocked os.system - the operation never ran
ls: cannot access '/tmp/ai_gate_pickle_pwned.txt': No such file or directory
```

Same file, same payload, but the hook raised at the `os.system` event, so the command never executed and the marker file was never created. Compare this directly with experiment 01, where loading this exact pickle did create the file: here the behaviour was caught and stopped at the moment it happened.

In both runs the `[audit]` line is identical, so detection is the same. The only difference is whether the hook raises, which determines whether the attack is recorded (observe) or prevented (block).

## Using it in real code

The command above runs the check as a standalone script so you can see it work, but that is only demo packaging, and it is why this can look like just another scanner. You do not normally run a separate "behaviour scan" step. Instead you install the hook once, at the start of your own program, and from then on it guards every model load in that process automatically:

```python
# app.py - your own model-serving code
import sys, torch

# install the guard once, at startup
def guard(event, args):
    if event in ("os.system", "os.exec", "socket.connect") or event.startswith("subprocess."):
        raise PermissionError(f"model tried a forbidden operation: {event}")
sys.addaudithook(guard)

# from here on, every load in this process is protected
model = torch.load("downloaded_model.pkl", weights_only=False)
# if that file is malicious, this line raises instead of running the payload
```

That is the real difference from a scanner. A scanner (experiment 03) is a separate step you run before loading, against one file at a time. The hook is part of your application: installed once, always on, and covering everything the process does afterwards, without you calling it again.

## Takeaway

Watch what a model does as it loads, as a runtime complement to static scanning, not a replacement for it. Use `observe` for monitoring and forensics, and `block` as an active tripwire that stops a sensitive operation before it runs. Two limits matter. An audit hook is not a sandbox: it shares the process with the model, so a payload can use calls that raise no audit event, stay dormant while watched, or detect the hook, which is why real isolation has to come from the OS, and every experiment here runs inside a locked-down container for exactly that reason. And dynamic analysis only sees what actually runs during observation, so it can miss a payload that waits for a trigger you did not provide. For this specific pickle path, `weights_only=True` (experiment 01) prevents the call outright; behavioural analysis is for when you must run untrusted code anyway, or want a runtime record of what a model did.

## References

- PEP 578 - Python Runtime Audit Hooks - https://peps.python.org/pep-0578/
- sys.addaudithook and sys.audit - https://docs.python.org/3/library/sys.html#sys.addaudithook
- Python audit events table - https://docs.python.org/3/library/audit_events.html
- seccomp - restricting syscalls for OS-level sandboxing - https://man7.org/linux/man-pages/man2/seccomp.2.html

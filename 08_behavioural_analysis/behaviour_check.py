#!/usr/bin/env python3
"""Watch what a model does as it loads, using a Python audit hook.

Static scanning (experiment 03) reads a file without running it. This is the
dynamic counterpart: it loads the model, and a sys.audit hook fires the moment
the model performs a sensitive operation - running a shell command, spawning a
process, or opening a network connection. The mode decides what happens then:

  observe  log the attempt and let it run (monitoring)
  block    raise from the hook, stopping the operation before it happens

This is a tripwire for observability, not a security boundary. The hook runs in
the same process as the model code, so OS-level isolation (the container,
--network none, a non-root user) stays the real containment.
"""
import sys

# Operations a model has no business performing while it loads.
WATCHED = ("os.system", "os.exec", "socket.connect")


def is_watched(event):
    return event in WATCHED or event.startswith("subprocess.")


def main(mode, path):
    import torch  # imported before the hook, so only the load is watched

    def hook(event, args):
        if is_watched(event):
            print(f"[audit] sensitive operation during load: {event} {args!r}")
            if mode == "block":
                raise PermissionError(f"blocked {event}")

    sys.addaudithook(hook)

    print(f"loading {path}  (mode: {mode})")
    try:
        torch.load(path, weights_only=False)
        print("load completed - the operation above was allowed to run")
    except PermissionError as exc:
        print(f"[blocked] load aborted: {exc} - the operation never ran")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("observe", "block"):
        print("usage: behaviour_check.py <observe|block> <model_file>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))

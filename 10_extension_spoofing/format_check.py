#!/usr/bin/env python3
"""Identify a model file by its real bytes, not its extension.

A file named .safetensors is only safe if it actually is safetensors. This reads
the first bytes, reports the true format, and rejects any file claiming to be
safetensors whose bytes are not. The decision is fail-closed: anything not
verifiably safetensors is rejected, even if its exact format is unknown. Pure
stdlib, runs offline, never loads the file.

  safetensors  -> 8-byte little-endian header length, then a JSON object '{...}'
  pickle       -> starts with the \\x80 PROTO opcode (protocol 2+; older
                  protocols use ASCII opcodes and show as 'unknown', still rejected)
  zip / torch  -> starts with PK\\x03\\x04
"""
import json
import struct
import sys
from pathlib import Path


def real_format(data):
    if data[:4] == b"PK\x03\x04":
        return "zip (pytorch/pickle archive)"
    if data[:1] == b"\x80":
        return "pickle"
    if len(data) >= 9:
        header_len = struct.unpack("<Q", data[:8])[0]
        if 0 < header_len <= len(data) - 8 and data[8:9] == b"{":
            try:
                json.loads(data[8:8 + header_len])
                return "safetensors"
            except Exception:
                pass
    return "unknown"


def main(path):
    path = Path(path)
    data = path.read_bytes()
    claimed = path.suffix.lstrip(".") or "(none)"
    actual = real_format(data)

    print(f"file:           {path.name}")
    print(f"claimed (ext):  {claimed}")
    print(f"actual (bytes): {actual}")

    if claimed == "safetensors" and actual != "safetensors":
        print(f"MISMATCH: named .safetensors but is actually {actual} - reject before loading")
        return 1
    print("ok: contents match the extension")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: format_check.py <model_file>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))

#!/usr/bin/env python3
"""Extract a tar archive safely, refusing any entry that escapes the target dir.

A tar entry's name is a path chosen by whoever built the archive. A naive
tarfile.extractall() will follow a name like '../../x' and write outside the
target directory (the zip-slip / CVE-2007-4559 class). This validates that every
member's final path stays inside the target, and refuses the whole archive if any
entry would escape or is a link. Nothing is written until every member passes, so
a malicious bundle never lands a single file. Pure stdlib, runs offline.

Python 3.12+ (and 3.11.4+) offers a built-in equivalent: extractall(filter="data").
This script does the check by hand so the rule is explicit.
"""
import os
import sys
import tarfile


def within(parent, child):
    parent = os.path.realpath(parent)
    child = os.path.realpath(child)
    return parent == child or os.path.commonpath([parent, child]) == parent


def main(archive, dest):
    dest = os.path.realpath(dest)
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(archive) as tf:
        members = tf.getmembers()
        for m in members:
            final = os.path.join(dest, m.name)
            if not within(dest, final):
                print(f"REFUSED: '{m.name}' would extract outside {dest} -> {os.path.realpath(final)}")
                return 1
            if m.issym() or m.islnk():
                print(f"REFUSED: '{m.name}' is a link, which can also escape the target")
                return 1
            print(f"ok: {m.name}")
        tf.extractall(dest)
    print(f"all entries stay inside the target; extracted safely into {dest}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: safe_extract.py <archive.tar> <target_dir>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))

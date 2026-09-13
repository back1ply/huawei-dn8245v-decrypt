#!/usr/bin/env python3
"""
Compare two decrypted Huawei DN8245V configs and show which settings changed.

Great for "what did this toggle actually do?" (dump before, change one thing,
dump after, diff) or spotting what a firmware update rewrote.

Usage:
    python3 config_diff.py OLD.xml NEW.xml

Secret-named attributes are masked to *** before comparing, so a changed
password shows as "(secret changed)" -- never the value.
"""
import re
import sys
import xml.etree.ElementTree as ET

SECRET_NAME = re.compile(
    r"(?i)(pass|secret|psk|salt|key|token|credential|hash|hmac|md5|sha1|sha256|privat)"
)
MASK = "***"


def diff(old_path, new_path):
    changed, added, removed = compare(flatten(load(old_path)), flatten(load(new_path)))
    _print_group("CHANGED", changed, lambda k, v: f"  {k}: {v[0]} -> {v[1]}")
    _print_group("ADDED (only in new)", added, lambda k, v: f"  {k} = {v}")
    _print_group("REMOVED (only in old)", removed, lambda k, v: f"  {k} = {v}")
    total = len(changed) + len(added) + len(removed)
    print(f"\n{total} difference(s): {len(changed)} changed, "
          f"{len(added)} added, {len(removed)} removed")
    return total


def _is_secret(key):
    return bool(SECRET_NAME.search(key.rsplit("@", 1)[-1]))   # match the attr, not the path


def compare(old, new):
    """Return (changed, added, removed) dicts keyed by 'path@attr'; secrets masked."""
    changed, added, removed = {}, {}, {}
    for key in sorted(set(old) | set(new)):
        if key not in new:
            removed[key] = MASK if _is_secret(key) else old[key]
        elif key not in old:
            added[key] = MASK if _is_secret(key) else new[key]
        elif old[key] != new[key]:
            # detected on the real values, but never report a secret's contents
            changed[key] = ("(secret)", "(secret changed)") if _is_secret(key) else (old[key], new[key])
    return changed, added, removed


def flatten(root):
    """Map 'Tag/Child[i]@attr' -> value for every attribute (real values, kept local)."""
    out = {}
    stack = [(root, root.tag)]
    while stack:                                   # bounded by element count
        el, path = stack.pop()
        for name, value in el.attrib.items():
            out[f"{path}@{name}"] = value
        children = list(el)
        repeats = {}
        for child in children:
            repeats[child.tag] = repeats.get(child.tag, 0) + 1
        seen = {}
        for child in children:
            seen[child.tag] = seen.get(child.tag, 0) + 1
            index = f"[{seen[child.tag]}]" if repeats[child.tag] > 1 else ""
            stack.append((child, f"{path}/{child.tag}{index}"))
    return out


def load(path):
    return ET.parse(path).getroot()


def _print_group(title, items, fmt):
    if not items:
        return
    print(f"== {title} ({len(items)}) ==")
    for key in sorted(items):
        print(fmt(key, items[key]))
    print()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        raise SystemExit(1)
    raise SystemExit(0 if diff(sys.argv[1], sys.argv[2]) == 0 else 1)

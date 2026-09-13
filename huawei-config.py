#!/usr/bin/env python3
"""
One entry point for the Huawei DN8245V config toolkit. Each subcommand just
forwards its arguments to the matching standalone script, so the individual
tools stay runnable on their own too.

    python3 huawei-config.py fetch    config.bin
    python3 huawei-config.py decrypt  config.bin config.xml
    python3 huawei-config.py dump     --file config.xml wifi wan
    python3 huawei-config.py diff     old.xml new.xml

    python3 huawei-config.py --selftest
"""
import os
import subprocess
import sys

TOOLS = {
    "fetch": "fetch-config.py",
    "decrypt": "decrypt_dn8245v.py",
    "dump": "router-dump.py",
    "diff": "config-diff.py",
}


def main(argv):
    if not argv or argv[0] in ("-h", "--help") or argv[0] not in TOOLS:
        print(__doc__)
        print("commands:", ", ".join(TOOLS))
        return 0 if argv[:1] in (["-h"], ["--help"]) else 2
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), TOOLS[argv[0]])
    return subprocess.call([sys.executable, script, *argv[1:]])


def _selftest():
    assert set(TOOLS) == {"fetch", "decrypt", "dump", "diff"}
    here = os.path.dirname(os.path.abspath(__file__))
    for filename in TOOLS.values():
        assert os.path.exists(os.path.join(here, filename)), f"missing tool: {filename}"
    assert main(["nonsense"]) == 2          # unknown command -> usage + exit 2
    print("selftest ok")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--selftest"]:
        _selftest()
        raise SystemExit(0)
    raise SystemExit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""
One entry point for the Huawei DN8245V config toolkit. Each subcommand just
forwards its arguments to the matching standalone script, so the individual
tools stay runnable on their own too.

    python3 huawei_config.py fetch    config.bin
    python3 huawei_config.py decrypt  config.bin config.xml
    python3 huawei_config.py dump     --file config.xml wifi wan
    python3 huawei_config.py diff     old.xml new.xml
"""

import os
import subprocess
import sys

TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")
TOOLS = {
    "fetch": "fetch_config.py",
    "decrypt": "decrypt_dn8245v.py",
    "dump": "router_dump.py",
    "diff": "config_diff.py",
}


def main(argv):
    if not argv or argv[0] in ("-h", "--help") or argv[0] not in TOOLS:
        print(__doc__)
        print("commands:", ", ".join(TOOLS))
        return 0 if argv[:1] in (["-h"], ["--help"]) else 2
    script = os.path.join(TOOLS_DIR, TOOLS[argv[0]])
    return subprocess.call([sys.executable, script, *argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

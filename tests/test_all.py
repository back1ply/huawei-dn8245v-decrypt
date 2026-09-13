#!/usr/bin/env python3
"""
Run the whole test suite with one command:

    python3 tests/test_all.py

Each tool has a normal test file under tests/ (the tools use underscore names,
so they import cleanly). This runner invokes each file as a subprocess and
reports pass/fail; the files are also plain pytest-discoverable test functions.

(The decryptor suite needs pycryptodome; the other tools are stdlib-only.)
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUITE = [
    ("decryptor", ["tests/test_decrypt.py"]),
    ("router-dump", ["tests/test_router_dump.py"]),
    ("config-diff", ["tests/test_config_diff.py"]),
    ("fetch-config", ["tests/test_fetch_config.py"]),
    ("huawei-config", ["tests/test_huawei_config.py"]),
]


def main():
    failed = []
    for name, argv in SUITE:
        script = os.path.join(ROOT, *argv[0].split("/"))
        result = subprocess.run([sys.executable, script, *argv[1:]],
                                capture_output=True, text=True)
        ok = result.returncode == 0
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failed.append(name)
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
    print(f"\n{len(SUITE) - len(failed)}/{len(SUITE)} suites passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

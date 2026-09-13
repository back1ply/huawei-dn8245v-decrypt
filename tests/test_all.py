#!/usr/bin/env python3
"""
Run the whole test suite with one command:

    python3 tests/test_all.py

The decryptor has a classic external test file (it is importable). The other
tools carry their tests inside themselves as --selftest, because their file
names contain hyphens and so cannot be imported as modules. This runner invokes
each one as a subprocess and reports pass/fail.

(The decryptor suite needs pycryptodome; the other tools are stdlib-only.)
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUITE = [
    ("decryptor tests", ["tests/test_decrypt.py"]),
    ("router-dump", ["tools/router-dump.py", "--selftest"]),
    ("config-diff", ["tools/config-diff.py", "--selftest"]),
    ("fetch-config", ["tools/fetch-config.py", "--selftest"]),
    ("huawei-config", ["huawei-config.py", "--selftest"]),
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

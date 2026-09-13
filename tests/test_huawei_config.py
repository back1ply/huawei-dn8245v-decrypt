#!/usr/bin/env python3
"""Tests for huawei_config.py — run with:  python3 tests/test_huawei_config.py"""

import contextlib
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
import huawei_config as m


def test_every_subcommand_points_at_an_existing_tool():
    for filename in m.TOOLS.values():
        assert os.path.exists(os.path.join(m.TOOLS_DIR, filename)), f"missing tool: {filename}"


def test_unknown_command_prints_usage_and_returns_2():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = m.main(["nonsense"])
    assert rc == 2
    assert "commands:" in buf.getvalue()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} tests passed")

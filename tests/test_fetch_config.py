#!/usr/bin/env python3
"""Tests for fetch_config.py — run with:  python3 tests/test_fetch_config.py

Covers the offline-testable logic: onttoken extraction and the guard that
rejects an HTML/error page. The live HTTP flow is device-specific and not
exercised here.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import fetch_config as m


def test_onttoken_extracted_from_page():
    page = '<input type="hidden" name="onttoken" id="onttoken" value="A1B2C3D4E5F60789ABCD"/>'
    assert m.TOKEN_RE.search(page).group(1) == "A1B2C3D4E5F60789ABCD"


def test_token_shorter_than_16_hex_is_not_matched():
    assert m.TOKEN_RE.search('name="onttoken" value="short"') is None


def test_html_error_page_is_rejected():
    for page in (b"<html><body>login</body></html>", b"<!DOCTYPE html>" + b"x" * 100, b"short"):
        try:
            m._reject_if_not_config(page)
            raise AssertionError(f"should have rejected: {page[:20]!r}")
        except SystemExit:
            pass


def test_real_container_passes_the_guard():
    m._reject_if_not_config(b"\x02\x00\x00\x00" + b"\x00" * 80)  # version-2 magic, no raise


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} tests passed")

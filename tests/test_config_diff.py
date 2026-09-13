#!/usr/bin/env python3
"""Tests for config_diff.py — run with:  python3 tests/test_config_diff.py"""
import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import config_diff as m


def test_changed_attribute_reports_old_and_new_value():
    old = ET.fromstring('<cfg><WLAN Channel="6"/></cfg>')
    new = ET.fromstring('<cfg><WLAN Channel="11"/></cfg>')
    changed, _, _ = m.compare(m.flatten(old), m.flatten(new))
    assert changed["cfg/WLAN@Channel"] == ("6", "11")


def test_added_and_removed_elements_are_reported():
    old = ET.fromstring('<cfg><WAN Enable="1"/></cfg>')
    new = ET.fromstring('<cfg><DHCP Range="192.168.1.2"/></cfg>')
    _, added, removed = m.compare(m.flatten(old), m.flatten(new))
    assert "cfg/DHCP@Range" in added
    assert "cfg/WAN@Enable" in removed


def test_changed_secret_is_masked_never_revealed():
    old = ET.fromstring('<cfg><WLAN KeyPassphrase="oldpw"/></cfg>')
    new = ET.fromstring('<cfg><WLAN KeyPassphrase="newpw"/></cfg>')
    changed, _, _ = m.compare(m.flatten(old), m.flatten(new))
    assert changed["cfg/WLAN@KeyPassphrase"] == ("(secret)", "(secret changed)")
    assert "oldpw" not in str(changed) and "newpw" not in str(changed)


def test_repeated_siblings_get_distinct_indexed_paths():
    root = ET.fromstring('<cfg><Item V="a"/><Item V="b"/></cfg>')
    flat = m.flatten(root)
    assert flat["cfg/Item[1]@V"] == "a" and flat["cfg/Item[2]@V"] == "b"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} tests passed")

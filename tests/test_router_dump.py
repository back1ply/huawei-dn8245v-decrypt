#!/usr/bin/env python3
"""Tests for router_dump.py — run with:  python3 tests/test_router_dump.py"""

import contextlib
import io
import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import router_dump as m

# One synthetic config touching several sections, with secret-bearing attrs.
SAMPLE = (
    '<WLANConfigurationInstance SSID="MyHome" Enable="1" Channel="6" '
    'X_HW_RFBand="2.4GHz" BeaconType="11i" KeyPassphrase="secretpsk" '
    'SSIDAdvertisementEnabled="1"/>\n'
    '<WANPPPConnectionInstance Enable="1" ConnectionType="IP_Routed" '
    'Password="pppsecret" X_HW_SERVICELIST="TR069_INTERNET" X_HW_VLAN="10"/>\n'
    '<X_HW_WebUserInfoInstance UserName="admin" UserLevel="0" Enable="1" '
    'Password="hash" Salt="s"/>\n'
    '<X_HW_UserDevInstance HostName="laptop" IpAddr="192.168.1.5" '
    'MacAddr="aa:bb:cc:dd:ee:ff" BrandName="Dell" X_HW_NegotiatedRate="300" '
    'X_HW_RSSI="-55"/>\n'
    '<ManagementServer URL="http://acs.example/cwmp" PeriodicInformEnable="1" '
    'PeriodicInformInterval="86400" Password="acssecret"/>'
)


def _dump(only=None):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        m.dump(SAMPLE, only)
    return buf.getvalue()


def test_sections_render_their_known_values():
    out = _dump()
    for value in ("MyHome", "TR069_INTERNET", "admin", "laptop", "acs.example"):
        assert value in out, value


def test_secret_values_are_never_printed():
    out = _dump()
    for leaked in ("secretpsk", "pppsecret", "hash", "acssecret"):
        assert leaked not in out, leaked


def test_section_filter_prints_only_the_named_section():
    out = _dump(["wifi"])
    assert "== WiFi ==" in out and "== WAN ==" not in out


def test_full_snapshot_redacts_secret_named_attributes():
    root = ET.fromstring('<root><WLAN SSID="x" KeyPassphrase="topsecret"/></root>')
    snap, redacted = m.full_snapshot(root)
    assert 'SSID="x"' in snap
    assert "topsecret" not in snap and redacted == 1


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} tests passed")

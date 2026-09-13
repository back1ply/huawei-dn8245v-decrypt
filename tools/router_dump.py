#!/usr/bin/env python3
"""
Dump the human-useful settings from a decrypted Huawei DN8245V config in one go
(22 sections: WiFi, WAN, DHCP, DNS, devices, QoS, VoIP, security, ...). Read-only.

Usage:
    python3 router_dump.py                    # all sections (readable summary)
    python3 router_dump.py wifi wan           # just the sections you name
    python3 router_dump.py --list             # list section names
    python3 router_dump.py --full             # 100% snapshot to a file
    python3 router_dump.py --file X.xml ...   # use a different config file
    python3 router_dump.py --out Y.txt --full # write the snapshot somewhere else

Sections: system wifi wan vlan dhcp dns ports devices users qos voip ipv6
          parental remote alg iptv wifiextra usb security firewall time acs

Feed it the XML that decrypt_dn8245v.py produces.

Safe by construction: every section pulls only non-secret attributes by name, so
WiFi keys, PPPoE passwords, and user password hashes are never read or printed.
The --full snapshot redacts secret-named attributes across the whole tree.
"""

import re
import sys
import xml.etree.ElementTree as ET

DEFAULT_XML = "decrypted-config.xml"  # in the current directory; override with --file
DEFAULT_SNAPSHOT = "router-snapshot.txt"

# Redact any attribute whose NAME looks secret-bearing. Over-redaction is safe;
# a leaked key is not. Matches Password/Passphrase/*Key/Secret/Salt/PSK/Token/hash.
SECRET_NAME = re.compile(
    r"(?i)(pass|secret|psk|salt|key|token|credential|hash|hmac|md5|sha1|sha256|privat)"
)


def system_section(text):
    print("== System / device ==")
    print("  (model & firmware are hardware, not stored in the config backup)")
    for t in tags("DeviceInfo", text):
        print(f"  first used:       {attr(t, 'FirstUseDate') or attr(t, 'FirstOnlineTime')}")
        print(f"  hardware reboots: {attr(t, 'X_HW_TotalHWReboot')}")
    for t in tags("ExtDeviceInfo", text):
        led = attr(t, "X_HW_LedSwitch")
        if led:
            print(f"  status LED:       {'on' if led == '1' else 'off'}")


def wifi_section(text):
    print("== WiFi ==")
    print(f"  {'SSID':<24} {'band':<7} {'chan':<5} {'security':<10} {'on':<4} hidden")
    for t in tags("WLANConfigurationInstance", text):
        ssid = attr(t, "SSID") or "(empty)"
        band = attr(t, "X_HW_RFBand") or attr(t, "X_HW_Band") or "?"
        chan = attr(t, "Channel")
        if chan in ("", "0") or attr(t, "AutoChannelEnable") == "1":
            chan = "auto"
        sec = attr(t, "BeaconType") or "?"
        hidden = "yes" if attr(t, "SSIDAdvertisementEnabled") == "0" else "no"
        print(f"  {ssid:<24} {band:<7} {chan:<5} {sec:<10} {on(t):<4} {hidden}")


def wan_section(text):
    print("== WAN ==")
    print(f"  {'#':>2} {'service':<16} {'type':<14} on")
    for i, t in enumerate(tags(r"WAN(?:PPP|IP)ConnectionInstance", text), start=1):
        routed = attr(t, "ConnectionType") == "IP_Routed"
        ppp = "WANPPPConnection" in t
        typ = f"{'PPPoE' if ppp else 'IPoE'} {'routed' if routed else 'bridged'}"
        flag = (
            "  <-- internet default candidate"
            if (on(t) == "yes" and routed and "INTERNET" in attr(t, "X_HW_SERVICELIST"))
            else ""
        )
        print(f"  {i:>2} {attr(t, 'X_HW_SERVICELIST') or '?':<16} {typ:<14} {on(t)}{flag}")


def dns_section(text):
    print("== DNS ==")
    seen = []
    for servers in re.findall(r'DNSServers="([^"]+)"', text):
        if servers not in seen:
            seen.append(servers)
    print(f"  handed to devices: {', '.join(seen) or '(inherited from ISP)'}")


def vlan_section(text):
    print("== VLAN tags (need these to move to your own router) ==")
    term = sorted(
        {attr(t, "VLANID") for t in tags("VLANTerminationInstance", text) if attr(t, "VLANID")}
    )
    print(f"  line / termination VLAN: {', '.join(term) or 'none (untagged)'}")
    svc = sorted(
        {
            attr(t, "X_HW_VLAN")
            for t in tags(r"WAN(?:PPP|IP)ConnectionInstance", text)
            if on(t) == "yes" and "INTERNET" in attr(t, "X_HW_SERVICELIST")
        }
    )
    print(f"  internet WAN service VLAN(s): {', '.join(svc) or '0 (none)'}")


def dhcp_section(text):
    print("== LAN / DHCP ==")
    for t in tags("IPInterfaceInstance", text):
        ip = attr(t, "IPInterfaceIPAddress")
        if ip and on(t) == "yes":
            print(f"  router IP {ip}  mask {attr(t, 'IPInterfaceSubnetMask')}")
    for t in tags("DHCPConditionalServingPoolInstance", text) + tags(
        "LANHostConfigManagement", text
    ):
        lo, hi = attr(t, "MinAddress"), attr(t, "MaxAddress")
        if not lo and not hi:
            continue
        print(f"  range {lo} - {hi}  mask {attr(t, 'SubnetMask')}  dns {attr(t, 'DNSServers')}")


def devices_section(text):
    print("== Known devices ==")
    print(f"  {'host':<20} {'ip':<15} {'mac':<18} {'brand':<12} {'rate':<6} rssi")
    for t in tags("X_HW_UserDevInstance", text):
        host = attr(t, "HostName") or attr(t, "UserDevAlias") or "(unnamed)"
        print(
            f"  {host:<20} {attr(t, 'IpAddr'):<15} {attr(t, 'MacAddr'):<18} "
            f"{attr(t, 'BrandName'):<12} {attr(t, 'X_HW_NegotiatedRate'):<6} "
            f"{attr(t, 'X_HW_RSSI')}"
        )


def users_section(text):
    print("== Login users ==")
    for t in tags("X_HW_WebUserInfoInstance", text):
        name = attr(t, "UserName") or "(unknown)"
        print(f"  {name:<16} level {attr(t, 'UserLevel')}  enabled {on(t)}")


def acs_section(text):
    print("== ISP management (TR-069 / ACS) ==")
    for t in tags("ManagementServer", text):
        url = attr(t, "URL")
        if not url:
            continue
        every = attr(t, "PeriodicInformInterval")
        print(f"  ACS URL: {url}")
        print(
            f"  checks in every {every}s (enabled={on(t, 'PeriodicInformEnable')})"
            "  <- this is what re-pushes ISP settings"
        )


def ports_section(text):
    print("== LAN Ethernet ports ==")
    print(f"  {'port':<10} {'status':<8} {'duplex':<8} {'maxrate':<8} on")
    for t in tags("LANEthernetInterfaceConfigInstance", text):
        name = attr(t, "Name") or attr(t, "Alias") or f"port{attr(t, 'InstanceID')}"
        print(
            f"  {name:<10} {attr(t, 'Status') or '?':<8} {attr(t, 'DuplexMode') or '?':<8} "
            f"{attr(t, 'MaxBitRate') or '?':<8} {on(t)}"
        )


def firewall_section(text):
    print("== Firewall ==")
    for t in tags("Firewall", text):
        print(f"  enabled {on(t)}  type {attr(t, 'Type') or '?'}")


def time_section(text):
    print("== Time / NTP ==")
    for t in tags("Time", text):
        if "LocalTimeZone" not in t:
            continue
        ntp = [attr(t, f"NTPServer{i}") for i in range(1, 6)]
        ntp = [n for n in ntp if n]
        print(f"  timezone: {attr(t, 'LocalTimeZoneName') or attr(t, 'LocalTimeZone') or '?'}")
        print(f"  DST used: {attr(t, 'DaylightSavingsUsed') or '?'}")
        print(f"  NTP servers: {', '.join(ntp) or 'none'}")


def qos_section(text):
    print("== QoS ==")
    for t in tags("X_HW_QosEnable", text):
        print(f"  global QoS enabled: {on(t, 'enable')}")
    for t in tags("QueueManagement", text):
        print(
            f"  queue management: {on(t)}  (defined rules: {attr(t, 'ClassificationNumberOfEntries')})"
        )
    active = sum(
        1 for t in tags("ClassificationInstance", text) if attr(t, "ClassificationEnable") == "1"
    )
    print(f"  ACTIVE traffic rules: {active}  <- 0 = no shaping (why bufferbloat isn't fixed)")


def voip_section(text):
    print("== VoIP / phone ==")
    for t in tags("VoiceProfileInstance", text):
        print(
            f"  profile: enabled={attr(t, 'Enable')}  protocol={attr(t, 'SignalingProtocol') or '(unset)'}"
        )
    for t in tags("LineInstance", text):
        print(
            f"  line {attr(t, 'InstanceID')}: number {attr(t, 'DirectoryNumber') or '(none)'}  "
            f"enabled {attr(t, 'Enable')}"
        )


def ipv6_section(text):
    print("== IPv6 ==")
    caps = sorted({on(t, "IPv6Capable") for t in tags("X_HW_IPv6", text)})
    print(f"  IPv6 enabled: {', '.join(caps) or '?'}")
    for t in tags("IPv6AddressInstance", text):
        addr = attr(t, "IPv6Address")
        if addr:
            print(f"  address: {addr} ({attr(t, 'Alias')})")


def parental_section(text):
    print("== Parental controls / filters ==")
    for t in tags("ParentalCtrl", text):
        print(f"  parental control: {on(t)}  default policy {attr(t, 'DefaultPolicy')}")
    for label, tag in (
        ("URL filter", "UrlFilter"),
        ("MAC filter", "MacFilter"),
        ("WiFi MAC filter", "WLANMacFilter"),
    ):
        for t in tags(tag, text):
            print(f"  {label} rules: {attr(t, 'NumberOfInstances')}")


def remote_section(text):
    print("== Remote access & management ==")
    for t in tags("X_HW_RemoteAccess", text):
        print(f"  remote (WAN) access: {on(t)}  allowed protocols {attr(t, 'SupportedProtocols')}")
    for t in tags("X_HW_LocalAccess", text):
        print(f"  local (LAN) access: {on(t)}  {attr(t, 'Protocol')} on port {attr(t, 'Port')}")
    for t in tags("X_HW_CLITelnetAccess", text):
        print(
            f"  telnet: {'on' if attr(t, 'Access') == '1' else 'off'} (port {attr(t, 'TelnetPort')})"
        )
    for t in tags("X_HW_CLISSHControl", text):
        print(f"  ssh: {on(t)}")
    for t in tags("X_HW_MainUPnP", text):
        print(f"  UPnP: {on(t)}")


def alg_section(text):
    print("== ALG (protocol passthrough) ==")
    for t in tags("X_HW_ALG", text):
        flags = [
            f"{label}={'on' if attr(t, a) == '1' else 'off'}"
            for label, a in (
                ("SIP", "SipEnable"),
                ("FTP", "FtpEnable"),
                ("RTSP", "RTSPEnable"),
                ("H323", "H323Enable"),
                ("PPTP", "PptpEnable"),
                ("L2TP", "L2TPEnable"),
                ("IPSec", "IpSecEnable"),
                ("TFTP", "TftpEnable"),
            )
        ]
        print("  " + "  ".join(flags))


def iptv_section(text):
    print("== IPTV / multicast ==")
    for t in tags("X_HW_IPTV", text):
        if not attr(t, "IGMPVersion"):
            continue
        igmp = "on" if attr(t, "IGMPEnable") == "1" else "off"
        snoop = "on" if attr(t, "SnoopingEnable") == "1" else "off"
        print(
            f"  IGMP: {igmp} (v{attr(t, 'IGMPVersion')})  snooping {snoop}  "
            f"set-top boxes {attr(t, 'STBNumber')}"
        )


def wifiextra_section(text):
    print("== WiFi extras (steering / mesh / WPS) ==")
    for t in tags("X_HW_UseBandSteering", text):
        print(
            f"  band steering: {attr(t, 'NumberOfInstances')} band(s), current {attr(t, 'CurrentBand')}"
        )
    for t in tags("EasyMesh", text):
        print(f"  EasyMesh: {on(t)} (role {attr(t, 'Role')})")
    wps = sorted({on(t) for t in tags("WPS", text)})
    print(f"  WPS: {', '.join(wps) or '?'}")
    for t in tags("X_HW_WLANSwitchTimer", text):
        print(f"  WiFi on/off schedule: {on(t)}")


def usb_section(text):
    print("== USB / storage sharing ==")
    for t in tags("LANUSBInterfaceConfigInstance", text):
        print(f"  USB port: {attr(t, 'Status')} (enabled {on(t)})")
    for t in tags("StorageServiceInstance", text):
        print(f"  storage service: {on(t)}  volumes {attr(t, 'LogicalVolumeNumberOfEntries')}")
    for t in tags("X_HW_Printer", text):
        print(f"  printer sharing: {on(t)}")


def security_section(text):
    print("== Security (DoS / misc) ==")
    for t in tags("Dosfilter", text):
        active = [
            n[:-2]
            for n in ("SynFloodEn", "SmurfEn", "LandEn", "WinnukeEn", "PingSweepEn")
            if attr(t, n) == "1"
        ]
        print(f"  DoS protections on: {', '.join(active) or 'none'}")
    for t in tags("AntiDNSRebind", text):
        print(f"  anti-DNS-rebind: {on(t)}")
    for t in tags("X_HW_AutoBlackList", text):
        print(f"  auto-blacklist: {on(t)}")
    for t in tags("X_HW_AutoReboot", text):
        print(f"  scheduled auto-reboot: {on(t)}")
    for t in tags("NAT", text):
        print(f"  NAT port-mappings: {attr(t, 'PortMappingNumberOfEntries')}")


# Registry: name -> section, in print order. The names are the CLI arguments.
SECTIONS = [
    ("system", system_section),
    ("wifi", wifi_section),
    ("wan", wan_section),
    ("vlan", vlan_section),
    ("dhcp", dhcp_section),
    ("dns", dns_section),
    ("ports", ports_section),
    ("devices", devices_section),
    ("users", users_section),
    ("qos", qos_section),
    ("voip", voip_section),
    ("ipv6", ipv6_section),
    ("parental", parental_section),
    ("remote", remote_section),
    ("alg", alg_section),
    ("iptv", iptv_section),
    ("wifiextra", wifiextra_section),
    ("usb", usb_section),
    ("security", security_section),
    ("firewall", firewall_section),
    ("time", time_section),
    ("acs", acs_section),
]
SECTION_NAMES = [name for name, _ in SECTIONS]


def dump(text, only=None):
    """Print all sections, or just the named ones (in the fixed order above)."""
    for name, section in SECTIONS:
        if only is None or name in only:
            section(text)
            print()


# ---- low-level helpers the sections above are built from ------------------
def tags(name, text):
    """All opening tags <Name ...> for an element, each as a flat string."""
    return re.findall(rf"<{name}\b[^>]*>", text)


def attr(tag, name, default=""):
    m = re.search(rf'(?:^|\s){name}="([^"]*)"', tag)
    return m.group(1) if m else default


def on(tag, name="Enable"):
    return "yes" if attr(tag, name) == "1" else "no"


# ---- full snapshot (every element, redacted) ------------------------------
def full_snapshot(root):
    """Walk the whole config tree iteratively; return (indented text, redact count)."""
    lines, redacted = [], 0
    stack = [(root, 0)]
    while stack:  # bounded by element count (~1700)
        el, depth = stack.pop()
        parts = []
        for name, value in el.attrib.items():
            safe = "REDACTED" if SECRET_NAME.search(name) else value
            if safe != value and value:
                redacted += 1
            parts.append(f'{name}="{safe}"')
        text = (el.text or "").strip()
        line = "  " * depth + el.tag
        if parts:
            line += " " + " ".join(parts)
        if text:
            line += f"  ::= {text}"
        lines.append(line)
        for child in reversed(list(el)):  # reversed so children print in order
            stack.append((child, depth + 1))
    return "\n".join(lines), redacted


def write_full_snapshot(path_in, path_out):
    root = ET.parse(path_in).getroot()
    text, redacted = full_snapshot(root)
    with open(path_out, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    print(f"[+] full snapshot: {len(text.splitlines())} elements -> {path_out}")
    print(f"[+] {redacted} secret value(s) redacted by name")


def _pop_value(args, flag, default):
    """Remove '--flag VALUE' from args and return VALUE (or default)."""
    if flag in args:
        i = args.index(flag)
        if i + 1 >= len(args):
            raise SystemExit(f"{flag} needs a value, e.g. {flag} PATH")
        value = args[i + 1]
        del args[i : i + 2]
        return value
    return default


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--list" in args:
        print("sections:", ", ".join(SECTION_NAMES))
        raise SystemExit(0)

    full = "--full" in args
    path = _pop_value(args, "--file", DEFAULT_XML)
    out = _pop_value(args, "--out", DEFAULT_SNAPSHOT)
    wanted = [a for a in args if not a.startswith("--")]  # section names

    if full:
        write_full_snapshot(path, out)
        raise SystemExit(0)

    bad = [n for n in wanted if n not in SECTION_NAMES]
    if bad:
        print(f"unknown section(s): {', '.join(bad)}")
        print("valid:", ", ".join(SECTION_NAMES))
        raise SystemExit(2)
    with open(path, encoding="latin-1") as f:
        dump(f.read(), wanted or None)

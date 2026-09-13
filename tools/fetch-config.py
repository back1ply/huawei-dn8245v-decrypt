#!/usr/bin/env python3
"""
Download the encrypted configuration backup from a Huawei DN8245V over the LAN,
so you can then decrypt it with decrypt_dn8245v.py. Stdlib only.

    ROUTER_PASS='...' python3 fetch-config.py config.bin
    python3 fetch-config.py config.bin        # prompts for the password instead

Environment:
    ROUTER_IP    default 192.168.1.1
    ROUTER_USER  default admin
    ROUTER_PASS  admin password (else you are prompted; never passed on argv)

Device-specific: it drives the DN8245V's login.cgi + cfgfiledown.cgi flow with a
per-page onttoken, mirroring the known-working shell version. The login uses the
router's self-signed HTTPS cert (verification is disabled for the LAN device).
The password is base64'd for the login form exactly as the web UI does; it is
never logged. Tested on DN8245V-56 / firmware V500R022.
"""
import base64
import getpass
import http.cookiejar
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request

RAND_URL = "https://{r}/asp/GetRandCount.asp"
LOGIN_URL = "https://{r}/login.cgi"
CFG_PAGE = "html/ssmp/cfgfile/cfgfile.asp"
# The download must be POST with the token in the body; a GET here 403s.
DOWNLOAD_URL = "https://{r}/cfgfiledown.cgi?&RequestFile=" + CFG_PAGE
TOKEN_RE = re.compile(r'name="onttoken"[^>]*value="([0-9a-fA-F]{16,})"')


def fetch(out_path):
    router = os.environ.get("ROUTER_IP", "192.168.1.1")
    user = os.environ.get("ROUTER_USER", "admin")
    password = os.environ.get("ROUTER_PASS")
    if not password:
        if not sys.stdin.isatty():
            raise SystemExit("No terminal to prompt on -- set ROUTER_PASS=... instead.")
        password = getpass.getpass("Router admin password: ")

    opener = _build_opener()
    _login(opener, router, user, password)
    del password

    token = _page_token(opener, router)
    print(f"[+] page token length: {len(token)}")
    blob = _post(opener, DOWNLOAD_URL.format(r=router),
                 {"x.X_HW_Token": token}, referer=_ref(router))
    _reject_if_not_config(blob)

    with open(out_path, "wb") as f:
        f.write(blob)
    print(f"[+] wrote {out_path} ({len(blob)} bytes)")
    print(f"    next: python3 huawei-config.py decrypt {out_path} config.xml")


def _login(opener, router, user, password):
    token = _get(opener, RAND_URL.format(r=router)).decode("ascii", "ignore").strip().lstrip("﻿")
    fields = {
        "UserName": user,
        "PassWord": base64.b64encode(password.encode()).decode(),
        "Language": "english",
        "x.X_HW_Token": token,
    }
    _post(opener, LOGIN_URL.format(r=router), fields,
          headers={"Cookie": "Cookie=body:Language:english:id=-1"})


def _page_token(opener, router):
    html = _get(opener, f"https://{router}/{CFG_PAGE}", referer=_ref(router)).decode("latin-1")
    m = TOKEN_RE.search(html)
    if not m:
        raise SystemExit("Could not find onttoken on the config page -- login likely failed.")
    return m.group(1)


def _reject_if_not_config(blob):
    """The download endpoint returns the login/error HTML page when auth failed."""
    head = blob[:16].lstrip()
    if len(blob) < 64 or head[:1] == b"<" or b"<html" in blob[:512].lower():
        raise SystemExit("Downloaded an HTML/error page, not a config (check password / router IP).")


# ---- HTTP plumbing --------------------------------------------------------
def _build_opener():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE       # router ships a self-signed LAN cert
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    )


def _get(opener, url, referer=None):
    return _open(opener, urllib.request.Request(url), referer)


def _post(opener, url, fields, headers=None, referer=None):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode())
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    return _open(opener, req, referer)


def _open(opener, req, referer):
    if referer:
        req.add_header("Referer", referer)
    with opener.open(req, timeout=20) as resp:
        return resp.read()


def _ref(router):
    return f"https://{router}/{CFG_PAGE}"


def _selftest():
    # token extraction from a realistic page fragment
    page = '<input type="hidden" name="onttoken" id="onttoken" value="A1B2C3D4E5F60789ABCD"/>'
    assert TOKEN_RE.search(page).group(1) == "A1B2C3D4E5F60789ABCD"
    assert TOKEN_RE.search('name="onttoken" value="short"') is None   # too short -> not matched
    # the HTML-page guard rejects an error page, accepts a real container
    for bad in (b"<html><body>login</body></html>", b"<!DOCTYPE html>" + b"x" * 100, b"short"):
        try:
            _reject_if_not_config(bad)
            raise AssertionError(f"should have rejected: {bad[:20]!r}")
        except SystemExit:
            pass
    _reject_if_not_config(b"\x02\x00\x00\x00" + b"\x00" * 80)   # version-2 container magic -> ok
    print("selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
        raise SystemExit(0)
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(1)
    fetch(sys.argv[1])

# Huawei DN8245V-56 config decryptor (WE Egypt / TE Data)

Decrypts the **configuration backup** exported from the web UI of a
**Huawei EchoLife DN8245V-56** (also branded **DG8245V-10**), as shipped by
**WE Egypt / TE Data**, firmware `V500R022*`.

It turns the encrypted backup into readable XML so you can recover **your own**
settings — for example your PPPoE username/password, so you can move to a
router you actually control.

> ⚠️ **Decrypt only a router you own.** This is an owner-recovery tool, the same
> category as the prior work it builds on (see Credits). Don't use it on devices
> or configs that aren't yours.

## What's actually new here

To be clear about novelty (it is easy to overclaim):

- The `$2...$` base-93 "Mode-2" field decoder **and** the AES key it uses are
  **already public** — one existing tool even targets DG8245V-10
  ([Jakiboy/Hwdecode](https://github.com/Jakiboy/Hwdecode)). But that only decodes
  individual field values inside an *already-plaintext* export.
- The general `gzip → AES → HMAC` container is documented too
  ([devilinside.me](https://devilinside.me/blogs/decrypt-configuration-files-exactly-how-huawei-ont-does)).

What this repo adds, as far as I could find (see **Prior art** — I could **not**
fully rule these out):

1. The exact WE/TE Data `fixed_str` string used by these units, and
2. A working decryptor for the **raw encrypted "version 2" backup container**
   (not just field values), which recovers that key string *dynamically* from
   the file header — so it should work for other ISP variants of the same
   container, not only TE Data.

If you find this already published somewhere, please open an issue — I'd rather
credit it than imply it's original.

## Container format (version 2)

```
[0:4]     magic            02 00 00 00
[4:8]     custom CRC-32
[8:12]    block length N   (little-endian)
[12:12+N] $2...$ block      base-93 "Mode-2" encoded ISP key string ("fixed_str")
[12+N:]   body = [16-byte salt/IV][AES-256-CBC ciphertext][32-byte HMAC-SHA256]
```

Key derivation:

```
fixed_str = decode_mode2( $2 block )          # e.g. b"HUAWEI...TEDATA"
key       = SHA-256^8192( salt || 16*0x00 || fixed_str )   # fixed_str fed in each round
body      = AES-256-CBC( key, iv = salt )
            → gzip-decompress → XML          # AES output is zero-padded to a block;
                                             # gzip stops at its own trailer, so the
                                             # trailing pad is simply ignored.
```

The container also carries an `HMAC-SHA256(key, ciphertext)` that the tool checks;
a mismatch is reported and the process exits non-zero.

## The pipeline

```
fetch-config.py  ->  decrypt_dn8245v.py  ->  router-dump.py  ->  config-diff.py
   download            decrypt                read              compare two
```

Or drive all four from one entry point:

```bash
python3 huawei-config.py fetch    config.bin
python3 huawei-config.py decrypt  config.bin config.xml
python3 huawei-config.py dump     --file config.xml
python3 huawei-config.py diff     old.xml new.xml
```

## Download it from the router (`fetch-config.py`)

Pulls the encrypted backup straight off the router over the LAN, so you don't
have to click through the web UI:

```bash
ROUTER_PASS='youradminpw' python3 fetch-config.py config.bin
python3 fetch-config.py config.bin            # or omit ROUTER_PASS to be prompted
```

Environment: `ROUTER_IP` (default `192.168.1.1`), `ROUTER_USER` (default `admin`),
`ROUTER_PASS`. The password is base64'd for the login form exactly as the web UI
does and is never logged or passed on the command line. Device-specific (drives
`login.cgi` + `cfgfiledown.cgi` with a per-page token); tested on DN8245V-56.

## Install & use

```bash
pip install -r requirements.txt          # pycryptodome
python3 decrypt_dn8245v.py  config.bin  config.xml
```

`config.bin` is the encrypted configuration backup the router's web UI produces
(look under its maintenance / configuration-file section, or hit the
`cfgfiledown.cgi` endpoint directly). The output is plaintext XML.

Passwords **inside** the XML are themselves `$2...$`-encoded. `decode_mode2()`
in `decrypt_dn8245v.py` decodes one such value to bytes — but those values are
XML-escaped inside the config, so unescape the string (`html.unescape`) **before**
passing it to `decode_mode2()`; the decoder deliberately does not unescape (that
would corrupt the raw header block).

## Read the config (`router-dump.py`)

Once you have the plaintext XML, `router-dump.py` prints it as readable sections
instead of 280+ raw tags:

```bash
python3 router-dump.py --file config.xml            # all sections
python3 router-dump.py --file config.xml wifi wan   # just the ones you name
python3 router-dump.py --list                        # section names
python3 router-dump.py --file config.xml --full      # 100% snapshot to a text file
```

Sections: `system wifi wan vlan dhcp dns ports devices users qos voip ipv6
parental remote alg iptv wifiextra usb security firewall time acs`.

Safe by construction: sections read only non-secret attributes, and `--full`
redacts every secret-named attribute across the whole tree — so WiFi keys, PPPoE
passwords, and user hashes are never printed.

## Compare two configs (`config-diff.py`)

See exactly what changed between two decrypted configs — handy for "what did
this toggle do?" (dump, change one thing, dump again, diff) or spotting what a
firmware update rewrote:

```bash
python3 config-diff.py old.xml new.xml
```

Secret-named values are masked before comparing, so a changed password shows as
`(secret changed)`, never the value.

## Tests

```bash
python3 test_decrypt.py        # no pytest needed; 9 tests
```

Covers a round-trip, all AES-pad residues, HMAC-mismatch, wrong-key, malformed
headers, and one known-answer test that pins the decoder against a real header
block (which decodes to the public ISP constant — no user data).

## Prior art / could-not-verify

I could not rule out that this is already documented in:

- The Hak5 thread *"How to decrypt hw_ctree of Huawei DN8245V-56?"*
  (`forums.hak5.org/topic/57207` — Cloudflare-blocked during research).
- Arabic "Prografor" videos claiming to decrypt dn8245v/dg8245v.

Check those before treating any of this as first-published.

## Credits

Built directly on:

- [Jakiboy/Hwdecode](https://github.com/Jakiboy/Hwdecode) & Ratr — `$2`/Mode-2 decode + key, for DG8245V-10.
- [coolrecep/Huawei-ONT-Firmware-Reverse-Engineering-Research](https://github.com/coolrecep/Huawei-ONT-Firmware-Reverse-Engineering-Research) — V500R022 container + 8192× SHA-256 KDF.
- [minanagehsalalma/huawei-dg8045-hg630-hg633-...](https://github.com/minanagehsalalma/huawei-dg8045-hg630-hg633-Config-file-decryption-and-password-decode) — DG8045/HG633 fixed-key decoder.

## License

MIT — see [LICENSE](LICENSE).

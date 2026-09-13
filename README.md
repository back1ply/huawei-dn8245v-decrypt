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
fetch_config.py  ->  decrypt_dn8245v.py  ->  router_dump.py  ->  config_diff.py
   download            decrypt                read              compare two
```

Or drive all four from one entry point:

```bash
python3 huawei_config.py fetch    config.bin
python3 huawei_config.py decrypt  config.bin config.xml
python3 huawei_config.py dump     --file config.xml
python3 huawei_config.py diff     old.xml new.xml
```

## Repo layout

```
huawei_config.py        # unified entry point (fetch|decrypt|dump|diff)
tools/
  fetch_config.py       # download the encrypted backup from the router
  decrypt_dn8245v.py    # decrypt it to plaintext XML
  router_dump.py        # print the settings as readable sections
  config_diff.py        # compare two decrypted configs
tests/
  test_*.py             # one test file per tool + test_all.py runner
```

The four tools also run standalone (`python3 tools/<name>.py ...`).

## Download it from the router (`fetch_config.py`)

Pulls the encrypted backup straight off the router over the LAN, so you don't
have to click through the web UI:

```bash
ROUTER_PASS='youradminpw' python3 tools/fetch_config.py config.bin
python3 tools/fetch_config.py config.bin       # or omit ROUTER_PASS to be prompted
```

Environment: `ROUTER_IP` (default `192.168.1.1`), `ROUTER_USER` (default `admin`),
`ROUTER_PASS`. The password is base64'd for the login form exactly as the web UI
does and is never logged or passed on the command line. Device-specific (drives
`login.cgi` + `cfgfiledown.cgi` with a per-page token); tested on DN8245V-56.

## Install & use

```bash
pip install -r requirements.txt          # pycryptodome (only the decryptor needs it)
python3 tools/decrypt_dn8245v.py  config.bin  config.xml
```

`config.bin` is the encrypted configuration backup the router's web UI produces
(look under its maintenance / configuration-file section, or hit the
`cfgfiledown.cgi` endpoint directly). The output is plaintext XML.

Passwords **inside** the XML are themselves `$2...$`-encoded. `decode_mode2()`
in `decrypt_dn8245v.py` decodes one such value to bytes — but those values are
XML-escaped inside the config, so unescape the string (`html.unescape`) **before**
passing it to `decode_mode2()`; the decoder deliberately does not unescape (that
would corrupt the raw header block).

## Read the config (`router_dump.py`)

Once you have the plaintext XML, `router_dump.py` prints it as readable sections
instead of 280+ raw tags:

```bash
python3 tools/router_dump.py --file config.xml            # all sections
python3 tools/router_dump.py --file config.xml wifi wan   # just the ones you name
python3 tools/router_dump.py --list                        # section names
python3 tools/router_dump.py --file config.xml --full      # 100% snapshot to a text file
```

Sections: `system wifi wan vlan dhcp dns ports devices users qos voip ipv6
parental remote alg iptv wifiextra usb security firewall time acs`.

Safe by construction: sections read only non-secret attributes, and `--full`
redacts every secret-named attribute across the whole tree — so WiFi keys, PPPoE
passwords, and user hashes are never printed.

## Compare two configs (`config_diff.py`)

See exactly what changed between two decrypted configs — handy for "what did
this toggle do?" (dump, change one thing, dump again, diff) or spotting what a
firmware update rewrote:

```bash
python3 tools/config_diff.py old.xml new.xml
```

Secret-named values are masked before comparing, so a changed password shows as
`(secret changed)`, never the value.

## Tests

```bash
python3 tests/test_all.py        # runs everything, no pytest needed
```

Every tool has its own test file under `tests/` (`test_decrypt.py`,
`test_router_dump.py`, `test_config_diff.py`, `test_fetch_config.py`,
`test_huawei_config.py`). They use plain `assert`s and a `__main__` runner, so
they need no pytest — but they are also pytest-discoverable if you prefer
(`pytest tests/`). `tests/test_all.py` runs them all; CI
(`.github/workflows/test.yml`) runs it on every push.

The decryptor file is the meatiest: a round-trip, all AES-pad residues,
HMAC-mismatch, corrupted-ciphertext, malformed headers, and a known-answer test
that pins the decoder to a real header block (which decodes to the public ISP
constant — no user data).

## Prior art / could-not-verify

**Checked (2026):** the Hak5 thread *"How to decrypt hw_ctree of Huawei
DN8245V-56?"*
([forums.hak5.org/topic/57207](https://forums.hak5.org/topic/57207-how-to-decrypt-hw_ctree-of-huawei-dn8245v-56/))
turned out to be an **unanswered, now-archived question** — no solution was ever
posted. The exact WE/TE Data `fixed_str` above still returns **zero** public
search hits.

**Checked the Arabic router-unlock scene (2026):** DN8245V-56 decryption there
circulates as a **private, paid "software"** among unlock sellers, not an open
method — public posts repeatedly ask *"has anyone decrypted the WE DN8245V-56?"*
and go unanswered, and the "unlock" videos demo a tool without revealing the
algorithm or key. No open write-up of the method **+** the WE `fixed_str` turned
up. In other words: this capability exists privately/for pay; the documented,
open version here appears to be the first public one for this container.

**Note — re-encryption is a separate, still-open problem.** Modifying a backup
and getting the router to accept it back is unsolved publicly: the container
carries an integrity/signature field nobody has reproduced (see this 2026 DG8045
write-up:
[reverseengineering.stackexchange.com/q/33737](https://reverseengineering.stackexchange.com/questions/33737/)).
This repo only **decrypts** — it does not re-sign.

## Sources & related work

Collected so nobody has to re-search this. See **Prior art** above for what each
does and doesn't cover.

**Method write-ups**
- devilinside.me — [gzip → AES → HMAC container, aescrypt2 emulation](https://devilinside.me/blogs/decrypt-configuration-files-exactly-how-huawei-ont-does)
- Fayaru — [Huawei config password encryption + the field key](https://blog.fayaru.me/posts/huawei_router_config/)

**Closest for the sibling model** (edits *plaintext* config, does not decrypt the v2 backup)
- Ratr — [DG8245V-10 config-edit guide](https://github.com/Jakiboy/Ratr/blob/main/docs/Huawei-DG8245V-10-Config.md) · [export guide](https://github.com/Jakiboy/Ratr/blob/main/docs/Huawei-DG8245V-10-Export.md)

**People asking for a DN8245V/DG8245V decryptor — all unanswered**
- Hak5 — ["How to decrypt hw_ctree of Huawei DN8245V-56?"](https://forums.hak5.org/topic/57207-how-to-decrypt-hw_ctree-of-huawei-dn8245v-56/)
- palmerc/AESCrypt2 — [issue #5 (DN8245V-56)](https://github.com/palmerc/AESCrypt2/issues/5)
- mkst/zte-config-utility — [issue #139 (DG8245V-10 super-admin)](https://github.com/mkst/zte-config-utility/issues/139)
- Reverse Engineering SE — [DG8045 re-encrypt / signature, 2026](https://reverseengineering.stackexchange.com/questions/33737/)

**The private "unlock" scene** — demos a paid tool; no method or key published
- YouTube — [«فك تشفير جميع راوترات هواوي» / "Decrypt all Huawei routers"](https://www.youtube.com/watch?v=-2sU4H805Rk)
- YouTube — [HG8245 decrypt/encrypt hw_ctree (old aescrypt2, GPON only)](https://www.youtube.com/watch?v=4cGYuwjDGO4)
- Facebook — [unlockWMFI: unlock via config file (seller)](https://www.facebook.com/unlockWMFI/videos/1351743516648316/)

## Credits

Built directly on:

- [Jakiboy/Hwdecode](https://github.com/Jakiboy/Hwdecode) & Ratr — `$2`/Mode-2 decode + key, for DG8245V-10.
- [coolrecep/Huawei-ONT-Firmware-Reverse-Engineering-Research](https://github.com/coolrecep/Huawei-ONT-Firmware-Reverse-Engineering-Research) — V500R022 container + 8192× SHA-256 KDF.
- [minanagehsalalma/huawei-dg8045-hg630-hg633-...](https://github.com/minanagehsalalma/huawei-dg8045-hg630-hg633-Config-file-decryption-and-password-decode) — DG8045/HG633 fixed-key decoder.

## License

MIT — see [LICENSE](LICENSE).

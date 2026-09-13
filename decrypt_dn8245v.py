#!/usr/bin/env python3
"""
Decrypt a Huawei EchoLife DN8245V-56 / DG8245V-10 (WE Egypt / TE Data) router
configuration backup (the encrypted file exported from the web UI).

This handles the "version 2" container: the per-ISP key string is itself hidden,
Mode-2 ($2...$ base-93) encoded, in the file header. The tool recovers that key
string dynamically, so it works for any ISP variant of this container -- not just
TE Data -- with no hardcoded ISP key.

Container layout (version 2):
    [0:4]   magic          02 00 00 00
    [4:8]   custom CRC-32
    [8:12]  block length N  (little-endian, e.g. 63)
    [12:12+N] $2...$ block  (base-93 Mode-2 encoded ISP "fixed_str")
    [12+N:]  body = [16-byte salt/IV][AES-256-CBC ciphertext][32-byte HMAC-SHA256]

Key derivation (from coolrecep's V500R022 research):
    key = SHA-256 iterated 8192x over ( salt || 16*0x00 || fixed_str )
    IV  = salt ; cipher = AES-256-CBC ; then gzip-decompress. The AES output is
    zero-padded to a block boundary; gzip stops at its own trailer, so the trailing
    pad needs no explicit trimming.

Usage:
    python3 decrypt_dn8245v.py <encrypted_config.bin> <output.xml>

Decrypt YOUR OWN router's config only. See README + LICENSE.
Credits: base-93 / Mode-2 decoder and PWD_KEY_MODE2 from
  - github.com/Jakiboy/Hwdecode
  - github.com/coolrecep/Huawei-ONT-Firmware-Reverse-Engineering-Research
  - github.com/minanagehsalalma/huawei-dg8045-hg630-hg633-...
"""
import hashlib
import hmac
import struct
import sys
import zlib

try:
    from Crypto.Cipher import AES
except ModuleNotFoundError:  # Debian ships pycryptodome under "Cryptodome"
    from Cryptodome.Cipher import AES

# Public constant (Huawei field-encryption "Mode 2" AES-256 key)
PWD_KEY_MODE2 = bytes.fromhex(
    "6fc6e3436a53b6310dc09a475494ac774e7afb21b9e58fc8e58b5660e48e2498"
)

# Cap on decompressed output: refuse a gzip bomb before it fills memory.
MAX_PLAINTEXT = 64 << 20  # 64 MiB; real configs are a few hundred KB


class ContainerError(ValueError):
    """The input is not a well-formed version-2 DN8245V container."""


# ---- base-93 / Mode-2 ($2...$) decoder ------------------------------------
def _b93_preprocess(text):
    # NOTE: caller unescapes XML entities first for $2 values pulled from inside
    # the decrypted XML. The header block is raw base-93 and must NOT be
    # unescaped -- its symbols include & < > ; which html.unescape would corrupt.
    vals = []
    for ch in text:
        c = ord(ch)
        vals.append(0x1e if c == 0x7e else c - 0x21)
    return vals


def _b93_decode(block):
    assert len(block) == 20, "base-93 group must be exactly 20 symbols"
    out = bytearray()
    for i in range(4):
        val, base = 0, 1
        for j in range(5):
            val += block[i * 5 + j] * base
            base *= 93
        out += struct.pack("<I", val & 0xFFFFFFFF)
    return bytes(out)


def decode_mode2(s):
    """Decode a $2...$ base-93 value to its plaintext bytes."""
    if not (s.startswith("$2") and s.endswith("$")):
        raise ContainerError("not a $2...$ value")
    vals = _b93_preprocess(s[2:-1])
    if len(vals) % 20 != 0 or len(vals) // 20 < 2:
        raise ContainerError("bad Mode-2 length")
    nb = len(vals) // 20
    iv = _b93_decode(vals[(nb - 1) * 20:])
    ct = bytearray()
    for b in range(nb - 1):
        ct += _b93_decode(vals[b * 20:(b + 1) * 20])
    d = AES.new(PWD_KEY_MODE2, AES.MODE_CBC, iv).decrypt(bytes(ct))
    n = d.find(0)
    return d[:n] if n != -1 else d


# ---- config container decrypt ---------------------------------------------
def derive_key(salt, fixed_str, iters=8192):
    assert len(salt) == 16, "salt must be 16 bytes"
    km = salt + b"\x00" * 16
    for _ in range(iters):
        h = hashlib.sha256()
        h.update(km)
        h.update(fixed_str)
        km = h.digest()
    assert len(km) == 32, "derived AES-256 key must be 32 bytes"
    return km


def _validate_header(data):
    """Check the 12-byte framing and return the $2 block length, bounded to the file."""
    if len(data) < 4 or data[:4] != b"\x02\x00\x00\x00":
        raise ContainerError("Not a version-2 DN8245V container (magic != 02 00 00 00).")
    if len(data) < 12:
        raise ContainerError("Truncated container: header is under 12 bytes.")
    # header block length is attacker-controlled: bound it before slicing.
    # need room for the 12-byte header + block + 16 salt + >=16 ciphertext + 32 HMAC.
    blk_len = struct.unpack("<I", data[8:12])[0]
    if 12 + blk_len + 64 > len(data):
        raise ContainerError("Corrupt container: header block length exceeds file size.")
    return blk_len


def parse_container(data):
    """Validate a version-2 container and split it into (fixed_str, salt, ct, sig)."""
    blk_len = _validate_header(data)
    block = data[12:12 + blk_len].decode("latin1")
    fixed_str = decode_mode2(block)                 # e.g. b"HUAWEIOPTICNETWORKTERMINALTEDATA"

    body = data[12 + blk_len:]
    salt, sig = body[:16], body[len(body) - 32:]
    ct = body[16:len(body) - 32]
    if len(ct) % 16 != 0:
        raise ContainerError("Ciphertext length is not a multiple of the AES block size.")
    # guaranteed by the length check above; assert so a bad bound-check fails loudly
    assert len(salt) == 16 and len(sig) == 32 and len(ct) >= 16
    return fixed_str, salt, ct, sig


def decompress_payload(dec):
    """Inflate the gzip payload, capping output and ignoring the trailing AES pad."""
    d = zlib.decompressobj(wbits=31)  # 31 = gzip framing (16) + max window (15)
    try:
        xml = d.decompress(dec, MAX_PLAINTEXT)
    except zlib.error as e:
        raise ContainerError(f"decryption produced no valid gzip stream (wrong key/format?): {e}")
    if d.unconsumed_tail:
        raise ContainerError("payload exceeds 64 MiB cap (possible gzip bomb).")
    if not d.eof:
        raise ContainerError("gzip stream did not terminate (truncated or wrong key?).")
    return xml


def decrypt(path_in, path_out):
    with open(path_in, "rb") as f:
        data = f.read()

    fixed_str, salt, ct, sig = parse_container(data)
    print(f"[+] recovered ISP fixed_str: {fixed_str.decode('latin1', 'ignore')!r}")

    key = derive_key(salt, fixed_str)
    hmac_ok = hmac.compare_digest(hmac.new(key, ct, hashlib.sha256).digest(), sig)
    print("[+] HMAC", "verified" if hmac_ok else "MISMATCH (output may be garbage)")

    dec = AES.new(key, AES.MODE_CBC, salt).decrypt(ct)
    xml = decompress_payload(dec)

    with open(path_out, "wb") as f:
        f.write(xml)
    print(f"[+] wrote {path_out} ({len(xml)} bytes of plaintext XML)")
    return hmac_ok


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        raise SystemExit(1)
    try:
        ok = decrypt(sys.argv[1], sys.argv[2])
    except ContainerError as exc:
        print(f"[!] {exc}")
        raise SystemExit(3)
    # non-zero exit if the HMAC did not verify, so callers can detect a bad decrypt
    raise SystemExit(0 if ok else 2)

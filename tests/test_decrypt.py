#!/usr/bin/env python3
"""
Tests for decrypt_dn8245v.py — run with:  python3 tests/test_decrypt.py

No pytest dependency (matches the repo's minimal footprint). Uses only
synthetic data plus one real header block that decodes to a public ISP
constant — no real router config or credentials.

The tool only decrypts, so most tests build a matching encoder locally to
round-trip, then assert the decrypt path and its malformed-input guards.
One known-answer test pins the decoder against a real file (below).
"""

import gzip
import hashlib
import hmac
import os
import struct
import sys
import tempfile

try:
    from Crypto.Cipher import AES
except ModuleNotFoundError:
    from Cryptodome.Cipher import AES

# the tool lives in ../tools relative to this test file
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import decrypt_dn8245v as m

# A real $2 header block from a WE/TE Data DN8245V backup. It is AES-CBC of the
# PUBLIC ISP constant below (Huawei's fixed_str for TE Data) — no user data.
# This is a known-answer test: it catches the decoder drifting from real files,
# which the self-built round-trip encoder cannot (both would drift together).
REAL_HEADER_BLOCK = r"$2r&FLPi/>~%XMOd:LH+*~HA{<8iIq(#U]Wz&U-LJPp\/`1*p[hKk;_4Rtr{@Z$"
REAL_FIXED_STR = b"HUAWEIOPTICNETWORKTERMINALTEDATA"


# ---- local encoder (inverse of the tool, test-only) -----------------------
def b93_encode_16(data16):
    """16 bytes -> 20 base-93 chars (inverse of the tool's _b93_decode)."""
    out = []
    for i in range(4):
        val = struct.unpack("<I", data16[i * 4 : i * 4 + 4])[0]
        for _ in range(5):
            d = val % 93
            val //= 93
            out.append("~" if d == 0x1E else chr(d + 0x21))
    return "".join(out)


def encode_mode2(plaintext):
    """Encode bytes as a $2...$ value the tool's decode_mode2() will recover."""
    padded = plaintext + b"\x00" * ((16 - len(plaintext) % 16) % 16 or 16)
    iv = os.urandom(16)
    ct = AES.new(m.PWD_KEY_MODE2, AES.MODE_CBC, iv).encrypt(padded)
    body = "".join(b93_encode_16(ct[i : i + 16]) for i in range(0, len(ct), 16))
    body += b93_encode_16(iv)
    return "$2" + body + "$"


def build_container(xml_bytes, fixed_str):
    """Build a full 'version 2' encrypted container the tool can decrypt.

    Pads the gzip payload to the AES block size with RANDOM bytes — the tool
    must ignore whatever the pad is (gzip stops at its own trailer), so random
    pad proves it does not depend on the router's zero padding.
    """
    gz = gzip.compress(xml_bytes)
    pad = (16 - len(gz) % 16) % 16
    salt = os.urandom(16)
    key = m.derive_key(salt, fixed_str)
    ct = AES.new(key, AES.MODE_CBC, salt).encrypt(gz + os.urandom(pad))
    sig = hmac.new(key, ct, hashlib.sha256).digest()
    block = encode_mode2(fixed_str).encode("latin1")
    header = b"\x02\x00\x00\x00" + b"\x00\x00\x00\x00" + struct.pack("<I", len(block))
    return header + block + salt + ct + sig


# ---- tests ----------------------------------------------------------------
def test_known_answer_real_block():
    # pins the decoder to a real file, independent of the test encoder
    assert m.decode_mode2(REAL_HEADER_BLOCK) == REAL_FIXED_STR


def test_decode_mode2_roundtrip():
    for s in (b"HELLO", b"HUAWEIOPTICNETWORKTERMINALTEST", b"x"):
        assert m.decode_mode2(encode_mode2(s)) == s


def test_full_roundtrip_and_exit_code():
    xml = b'<InternetGatewayDevice DBEncrypt="1"><Test A="1"/></InternetGatewayDevice>'
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "in.bin")
        out = os.path.join(d, "out.xml")
        with open(src, "wb") as fh:
            fh.write(build_container(xml, b"SOMEISPKEY123"))
        assert m.decrypt(src, out) is True  # returns hmac_ok
        with open(out, "rb") as fh:
            assert fh.read() == xml


def test_pad_residues_all_ignored():
    # gzip length mod 16 lands on 0, 1, and 15 -> pad of 0, 15, and 1 bytes.
    # Every case must decrypt: the tool must not depend on the pad amount.
    for pad_target in (0, 1, 15):
        xml = b"A" * 1  # start small, grow until gzip length hits pad_target mod 16
        while len(gzip.compress(xml)) % 16 != pad_target:
            xml += b"A"
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "in.bin")
            out = os.path.join(d, "out.xml")
            with open(src, "wb") as fh:
                fh.write(build_container(xml, b"KEY"))
            assert m.decrypt(src, out) is True
            with open(out, "rb") as fh:
                assert fh.read() == xml


def test_hmac_mismatch_returns_false():
    xml = b"<InternetGatewayDevice></InternetGatewayDevice>"
    data = bytearray(build_container(xml, b"KEY"))
    data[-1] ^= 0xFF  # corrupt the HMAC
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "in.bin")
        with open(src, "wb") as fh:
            fh.write(bytes(data))
        assert m.decrypt(src, os.path.join(d, "out")) is False  # decrypts, flags mismatch


def _expect_container_error(data):
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "in.bin")
        with open(src, "wb") as fh:
            fh.write(data)
        try:
            m.decrypt(src, os.path.join(d, "out"))
            raise AssertionError("expected ContainerError, none raised")
        except m.ContainerError:
            pass
        except IndexError as e:
            raise AssertionError(f"leaked IndexError instead of clean error: {e}") from e


def test_wrong_magic_rejected():
    _expect_container_error(b"\x99\x00\x00\x00" + b"\x00" * 100)


def test_too_short_rejected():
    _expect_container_error(b"\x02\x00\x00\x00" + b"\x00" * 8)


def test_lying_block_length_rejected():
    # valid magic, 200 bytes, but block length claims 0xffffffff -> must not crash
    data = b"\x02\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\xff\xff\xff\xff" + b"X" * 188
    _expect_container_error(data)


def test_corrupted_ciphertext_rejected():
    # key is correct; a flipped ciphertext byte makes the AES output un-gzippable
    data = bytearray(build_container(b"<x/>", b"KEY"))
    data[-40] ^= 0xFF  # flip a ciphertext byte (before HMAC)
    _expect_container_error(bytes(data))


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} tests passed")

"""Authentic output with malformed contents (only a key holder could make it) is rejected."""

import io
import struct

import pytest

import yace_codec as yace
from yace_codec import _algorithms, sealed

KEY = bytes(range(32))
SALT = bytes(range(16))
ALG = _algorithms.by_name("aes-256-gcm")


def forge_message(frame: bytes) -> bytes:
    prk = sealed._extract(SALT, KEY)
    ad = SALT + bytes([3, ALG.id]) + sealed._aad_block(b"")
    body = ALG.cipher(prk, 3, ad).seal(b"", frame)
    return SALT + sealed._xor(bytes([3, ALG.id]) + bytes(4), sealed._mask(prk)) + body


def forge_stream(chunks, log2: int = 6) -> bytes:
    """``chunks`` are plaintexts; the last one is sealed as the final chunk."""
    prk = sealed._extract(SALT, KEY)
    cipher = ALG.cipher(prk, 4, SALT + bytes([4, ALG.id, log2]) + sealed._aad_block(b""))
    out = SALT + sealed._xor(bytes([4, ALG.id, log2]) + bytes(4), sealed._mask(prk))
    for index, plaintext in enumerate(chunks):
        out += cipher.seal(sealed._chunk_suffix(index, index == len(chunks) - 1), plaintext)
    return out


def test_the_forgers_make_valid_output():
    frame = struct.pack("!BQQ", 0, 1, 2) + b"ok"
    assert yace.decrypt(forge_message(frame), keys=[KEY]) == b"ok"
    meta = struct.pack("!BQ", 0, 1)
    assert yace.decrypt(forge_stream([struct.pack("!I", 11) + meta + b"ok"]), keys=[KEY]) == b"ok"


@pytest.mark.parametrize(
    "frame",
    [
        b"\x00" * 16,  # shorter than the frame header
        struct.pack("!BQQ", 7, 1, 0),  # unknown kind
        struct.pack("!BQQ", 0, 1, 100) + b"short",  # length beyond the frame
    ],
)
def test_malformed_messages(frame):
    with pytest.raises(yace.DecryptionError, match="malformed"):
        yace.decrypt(forge_message(frame), keys=[KEY])


@pytest.mark.parametrize(
    "chunks",
    [
        [struct.pack("!I", 3) + b"abc"],  # first chunk shorter than the metadata
        [struct.pack("!I", 9) + struct.pack("!BQ", 9, 1)],  # unknown kind
        [struct.pack("!I", 99) + struct.pack("!BQ", 0, 1)],  # count beyond the chunk
        [b"\x00\x00"],  # no count at all
    ],
)
def test_malformed_streams(chunks):
    with pytest.raises(yace.DecryptionError, match="malformed"):
        yace.decrypt_stream(io.BytesIO(forge_stream(chunks)), io.BytesIO(), keys=[KEY])


def test_a_short_chunk_in_the_middle_fails_authentication():
    # Chunks are read at their fixed size, so a short one breaks the next tag.
    chunks = [struct.pack("!I", 9) + struct.pack("!BQ", 0, 1), struct.pack("!I", 0)]
    with pytest.raises(yace.DecryptionError):
        yace.decrypt_stream(io.BytesIO(forge_stream(chunks)), io.BytesIO(), keys=[KEY])


def test_stream_too_long_to_encrypt(monkeypatch):
    monkeypatch.setattr(sealed, "_MAX_CHUNK_INDEX", 2)
    with pytest.raises(yace.EncodingError, match="too long"):
        yace.encrypt_stream(io.BytesIO(b"x" * 1000), io.BytesIO(), key=KEY, chunk_size=64)


def test_stream_too_long_to_decrypt(monkeypatch):
    out = io.BytesIO()
    yace.encrypt_stream(io.BytesIO(b"x" * 1000), out, key=KEY, chunk_size=64, output="bytes")
    monkeypatch.setattr(sealed, "_MAX_CHUNK_INDEX", 2)
    with pytest.raises(yace.DecryptionError, match="too long"):
        yace.decrypt_stream(io.BytesIO(out.getvalue()), io.BytesIO(), keys=[KEY])


def test_short_headers():
    for size in (0, 5, 22):
        with pytest.raises(yace.DecodingError):
            yace.decrypt_stream(io.BytesIO(b"\x80" * size), io.BytesIO(), keys=[KEY])

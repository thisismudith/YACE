"""Decrypt the published vectors with an independent implementation of the format.

This uses only the format description (SECURITY.md / the sealed module
docstring), the standard library, and the cryptography package's HKDF and
AEAD classes -- none of yace_codec's own code.
"""

import hashlib
import hmac
import json
import string
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VECTORS = json.loads((Path(__file__).parent / "vectors" / "v3.json").read_text(encoding="utf-8"))["vectors"]
ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase
ALG_IDS = {"yace-hmac-sha256": 1, "aes-256-gcm": 2, "chacha20-poly1305": 3}
BYTES_FOR_CHARS = {2: 1, 3: 2, 5: 3, 6: 4, 7: 5, 9: 6, 10: 7, 11: 8}


def yace62_decode(text: str) -> bytes:
    out = b""
    for i in range(0, len(text), 11):
        group = text[i : i + 11]
        value = 0
        for ch in group:
            value = value * 62 + ALPHABET.index(ch)
        out += value.to_bytes(BYTES_FOR_CHARS[len(group)], "big")
    return out


def hkdf(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)


def keystream_xor(key: bytes, data: bytes, prefix: bytes = b"") -> bytes:
    stream = b"".join(
        hmac.digest(key, prefix + i.to_bytes(8, "big"), "sha256") for i in range(-(-len(data) // 32))
    )
    return bytes(a ^ b for a, b in zip(data, stream))


class Opener:
    def __init__(self, secret: bytes, salt: bytes, version: int, alg_id: int, ad: bytes) -> None:
        info = b"yace3" + bytes([version, alg_id])
        self.alg_id, self.ad = alg_id, ad
        if alg_id == 1:
            self.enc = hkdf(secret, salt, info + b" enc", 32)
            self.mac = hkdf(secret, salt, info + b" mac", 32)
        else:
            cls = AESGCM if alg_id == 2 else ChaCha20Poly1305
            self.aead = cls(hkdf(secret, salt, info + b" key", 32))
            self.nonce = hkdf(secret, salt, info + b" nonce", 12)

    def open(self, suffix: bytes, body: bytes) -> bytes:
        if self.alg_id == 1:
            ciphertext, tag = body[:-32], body[-32:]
            expected = hmac.digest(self.mac, self.ad + suffix + ciphertext, "sha256")
            assert hmac.compare_digest(tag, expected)
            return keystream_xor(self.enc, ciphertext, suffix)
        nonce = self.nonce[: 12 - len(suffix)] + suffix
        return self.aead.decrypt(nonce, body, self.ad)


def secret_for(vector, salt: bytes) -> bytes:
    if "key" in vector:
        return bytes.fromhex(vector["key"])
    params = vector["scrypt"]
    return hashlib.scrypt(
        vector["secret_token"].encode(), salt=salt, n=params["n"], r=params["r"], p=params["p"],
        maxmem=256 * 1024 * 1024, dklen=32,
    )


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: f"v{v['format']}-{v['algorithm']}-{v['salt'][:4]}")
def test_independent_decryption(vector):
    raw = yace62_decode(vector["expected"]) if vector["output"] == "text" else bytes.fromhex(vector["expected"])
    salt = raw[:16]
    secret = secret_for(vector, salt)
    mask = hkdf(secret, salt, b"yace3 header mask", 3)
    version, alg_id = raw[16] ^ mask[0], raw[17] ^ mask[1]
    assert version == vector["format"] and alg_id == ALG_IDS[vector["algorithm"]]
    aad = vector["aad"].encode()
    aad_block = len(aad).to_bytes(8, "big") + aad
    expected = vector["plaintext"].encode() if "plaintext" in vector else bytes.fromhex(vector["plaintext_hex"])

    if version == 3:
        opener = Opener(secret, salt, 3, alg_id, salt + bytes([3, alg_id]) + aad_block)
        frame = opener.open(b"", raw[18:])
        kind, created, length = struct.unpack_from("!BQQ", frame)
        assert (kind == 1) is vector["text"] and created == vector["created"]
        assert frame[17 : 17 + length] == expected
        assert not any(frame[17 + length :])  # zero padding
        return

    log2 = raw[18] ^ mask[2]
    assert 1 << log2 == vector["chunk_size"]
    opener = Opener(secret, salt, 4, alg_id, salt + bytes([4, alg_id, log2]) + aad_block)
    size = (1 << log2) + (32 if alg_id == 1 else 16)
    body = raw[19:]
    chunks = [body[i : i + size] for i in range(0, len(body), size)]
    data = b""
    for index, chunk in enumerate(chunks):
        last = index == len(chunks) - 1
        plaintext = opener.open(index.to_bytes(4, "big") + bytes([last]), chunk)
        (count,) = struct.unpack_from("!I", plaintext)
        data += plaintext[4 : 4 + count]
    kind, created = struct.unpack_from("!BQ", data)
    assert (kind == 1) is vector["text"] and created == vector["created"]
    assert data[9:] == expected

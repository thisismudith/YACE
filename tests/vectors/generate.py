"""Regenerate tests/vectors/v3.json (run from the repository root).

    python tests/vectors/generate.py

The vectors fix every random input (salt, creation time), so each one maps
key or secret token, salt, plaintext, and associated data to one exact token.
Only regenerate them for a deliberate format change: tests/test_vectors.py
checks that the code still produces these exact bytes.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from yace_codec import _algorithms, sealed

KEY = bytes(range(32))
CREATED = 1_760_000_000
ALGORITHMS = ["aes-256-gcm", "chacha20-poly1305", "yace-hmac-sha256"]
MESSAGES = [
    {"plaintext": "", "text": True},
    {"plaintext": "Hello, World!", "text": True},
    {"plaintext": "नमस्ते दुनिया", "text": True, "aad": "row:1"},
    {"plaintext_hex": bytes(range(256)).hex(), "text": False, "aad": "file:42"},
]


def message_vectors() -> list:
    vectors = []
    for alg_index, algorithm in enumerate(ALGORITHMS):
        for msg_index, message in enumerate(MESSAGES):
            salt = bytes([alg_index * 16 + msg_index]) * 16
            data = (
                message["plaintext"].encode() if "plaintext" in message
                else bytes.fromhex(message["plaintext_hex"])
            )
            aad = message.get("aad", "").encode()
            for output in ("text", "bytes"):
                token = sealed.seal(
                    data, text=message["text"], key=KEY, aad=aad, algorithm=algorithm,
                    now=CREATED, salt=salt, output=output,
                )
                vectors.append({
                    "format": 3, "algorithm": algorithm, "key": KEY.hex(), "salt": salt.hex(),
                    "created": CREATED, **message, "aad": aad.decode(), "output": output,
                    **derived(KEY, salt, algorithm, 3),
                    "expected": token if output == "text" else token.hex(),
                })
        salt = bytes([0xA0 + alg_index]) * 16
        token = sealed.seal(
            b"secret token", text=True, secret="correct horse battery staple",
            algorithm=algorithm, now=CREATED, salt=salt,
        )
        vectors.append({
            "format": 3, "algorithm": algorithm, "secret_token": "correct horse battery staple",
            "scrypt": {"n": sealed.SCRYPT_N, "r": sealed.SCRYPT_R, "p": sealed.SCRYPT_P},
            "salt": salt.hex(), "created": CREATED, "plaintext": "secret token", "text": True,
            "aad": "", "output": "text", "expected": token,
        })
    return vectors


def stream_vectors() -> list:
    vectors = []
    data = bytes(range(256)) + b"stream" * 20
    for alg_index, algorithm in enumerate(ALGORITHMS):
        salt = bytes([0xC0 + alg_index]) * 16
        out = io.BytesIO()
        sealed.seal_stream(
            io.BytesIO(data), out, key=KEY, aad=b"stream:1", algorithm=algorithm,
            output="bytes", chunk_size=64, now=CREATED, salt=salt,
        )
        vectors.append({
            "format": 4, "algorithm": algorithm, "key": KEY.hex(), "salt": salt.hex(),
            "created": CREATED, "plaintext_hex": data.hex(), "text": False, "aad": "stream:1",
            "chunk_size": 64, "output": "bytes", **derived(KEY, salt, algorithm, 4),
            "expected": out.getvalue().hex(),
        })
    return vectors


def derived(key: bytes, salt: bytes, algorithm: str, version: int) -> dict:
    """Intermediate values, so other implementations can check each step."""
    prk = sealed._extract(salt, key)
    alg = _algorithms.by_name(algorithm)
    values = {"prk": prk.hex(), "header_mask": sealed._mask(prk).hex()}
    if alg.tag_size == 16:
        values["aead_key"] = _algorithms.hkdf_expand(prk, alg.info(b" key", version)).hex()
        values["nonce"] = _algorithms.hkdf_expand(prk, alg.info(b" nonce", version), 12).hex()
    else:
        values["encryption_key"] = _algorithms.hkdf_expand(prk, alg.info(b" enc", version)).hex()
        values["mac_key"] = _algorithms.hkdf_expand(prk, alg.info(b" mac", version)).hex()
    return values


def main() -> None:
    document = {
        "about": (
            "Test vectors for yace-codec encrypted tokens, format 3 (single message) and 4 "
            "(stream). Every random input is fixed. 'expected' is YACE62 text, or hex for "
            "output 'bytes'. 'nonce' is the derived 12-byte AEAD nonce of a message; stream "
            "chunks replace its last 5 bytes with the chunk index (4 bytes) and final flag."
        ),
        "vectors": message_vectors() + stream_vectors(),
    }
    path = Path(__file__).with_name("v3.json")
    path.write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(document['vectors'])} vectors to {path}")


if __name__ == "__main__":
    main()

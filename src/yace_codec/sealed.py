"""Encrypted YACE tokens ("yace2").

A yace2 token is ``yace2_`` followed by letters and digits. It reveals nothing
about its contents except roughly how long they are: no family name, code
length, key name, creation time, or exact length.

How a token is made:

1. A random 16-byte salt is drawn for every token.
2. A secret is chosen: a 32-byte key from the key store, or a password stretched
   with scrypt (N=2**17, r=8, p=1) and the salt.
3. HKDF-SHA256 (RFC 5869) turns the secret and the salt into two independent
   keys: one to encrypt, one to authenticate. Every token gets its own pair.
4. A frame holds the data type (text or bytes), the creation time, the data
   length, the data, and zero padding to a Padmé length, which hides the exact
   size.
5. The frame is XORed with a keystream of HMAC-SHA256 blocks (counter mode).
6. An HMAC-SHA256 tag covers the prefix, the salt, and the ciphertext
   (encrypt-then-MAC), so a wrong key or any change to the token is detected
   before anything is decrypted.
7. ``salt + ciphertext + tag`` is written in YACE62: 8-byte blocks as 11 letters
   and digits.

Everything uses Python's standard library (``hashlib``, ``hmac``, ``secrets``).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import string
import struct
import time
from typing import Iterable, Optional, Tuple

from ._text import TokenLike, token_text
from .errors import DecodingError, DecryptionError, EncodingError, TokenExpiredError

__all__ = ["KEY_SIZE", "PREFIX", "padme", "seal", "unseal", "yace62_decode", "yace62_encode"]

#: Every encrypted token starts with this.
PREFIX = "yace2_"
#: Size in bytes of the keys stored in a key store.
KEY_SIZE = 32

SALT_SIZE = 16
TAG_SIZE = 32
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
_SCRYPT_MAXMEM = 256 * 1024 * 1024

_FRAME = struct.Struct("!BQQ")  # kind, creation time (Unix seconds), data length
_KIND_BYTES = 0
_KIND_TEXT = 1
_INFO_ENCRYPT = b"yace2 encryption"
_INFO_AUTHENTICATE = b"yace2 authentication"

_ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase
_DIGIT = {ch: i for i, ch in enumerate(_ALPHABET)}
# Characters needed for a final block of 1-8 bytes (62**chars >= 256**bytes).
_CHARS_FOR = {1: 2, 2: 3, 3: 5, 4: 6, 5: 7, 6: 9, 7: 10, 8: 11}
_BYTES_FOR = {chars: size for size, chars in _CHARS_FOR.items()}


def seal(
    data: bytes,
    *,
    text: bool,
    key: Optional[bytes] = None,
    password: Optional[str] = None,
    now: Optional[float] = None,
) -> str:
    """Encrypt ``data`` with a stored ``key`` or a ``password`` and return a token."""
    salt = secrets.token_bytes(SALT_SIZE)
    secret = _secret(salt, key=key, password=password)
    encrypt_key, mac_key = _subkeys(secret, salt)
    created = int(time.time() if now is None else now)
    frame = _FRAME.pack(_KIND_TEXT if text else _KIND_BYTES, created, len(data)) + bytes(data)
    frame += bytes(padme(len(frame)) - len(frame))
    ciphertext = _xor_keystream(encrypt_key, frame)
    tag = _tag(mac_key, salt, ciphertext)
    return PREFIX + yace62_encode(salt + ciphertext + tag)


def unseal(
    token: TokenLike,
    *,
    keys: Iterable[bytes] = (),
    password: Optional[str] = None,
    max_age: Optional[float] = None,
    now: Optional[float] = None,
) -> Tuple[bytes, bool]:
    """Decrypt a token; return ``(data, is_text)``.

    With ``password``, only the password is tried. Otherwise every key in
    ``keys`` is tried, so tokens never need to name their key.
    """
    raw = _token_bytes(token)
    salt, ciphertext, tag = raw[:SALT_SIZE], raw[SALT_SIZE:-TAG_SIZE], raw[-TAG_SIZE:]
    secrets_to_try = (
        [_secret(salt, password=password)] if password is not None else list(keys)
    )
    for secret in secrets_to_try:
        encrypt_key, mac_key = _subkeys(secret, salt)
        if hmac.compare_digest(tag, _tag(mac_key, salt, ciphertext)):
            frame = _xor_keystream(encrypt_key, ciphertext)
            break
    else:
        if password is None and not secrets_to_try:
            raise DecryptionError("the key store holds no keys; pass the password if one was used")
        raise DecryptionError(
            "this token cannot be opened: wrong password or key store, or the token was changed"
        )
    kind, created, length = _FRAME.unpack_from(frame)
    if kind not in (_KIND_BYTES, _KIND_TEXT) or _FRAME.size + length > len(frame):
        raise DecryptionError("the token's contents are malformed")
    if max_age is not None:
        age = (time.time() if now is None else now) - created
        if age > max_age:
            raise TokenExpiredError(f"the token is {int(age)} seconds old (limit {max_age})")
    return frame[_FRAME.size : _FRAME.size + length], kind == _KIND_TEXT


def padme(length: int) -> int:
    """Round ``length`` up to a Padmé length, which leaks at most O(log log n) bits."""
    if length < 2:
        return length
    exponent = length.bit_length() - 1
    last_bits = exponent - exponent.bit_length()
    mask = (1 << last_bits) - 1
    return (length + mask) & ~mask


def yace62_encode(data: bytes) -> str:
    """Write bytes as letters and digits: every 8 bytes become 11 characters."""
    out = []
    for start in range(0, len(data), 8):
        block = data[start : start + 8]
        value = int.from_bytes(block, "big")
        digits = []
        for _ in range(_CHARS_FOR[len(block)]):
            value, digit = divmod(value, 62)
            digits.append(_ALPHABET[digit])
        out.append("".join(reversed(digits)))
    return "".join(out)


def yace62_decode(text: str) -> bytes:
    """Reverse :func:`yace62_encode`; raise DecodingError for invalid input."""
    out = bytearray()
    for start in range(0, len(text), 11):
        group = text[start : start + 11]
        size = _BYTES_FOR.get(len(group))
        if size is None:
            raise DecodingError("the token is truncated or corrupted")
        value = 0
        for ch in group:
            digit = _DIGIT.get(ch)
            if digit is None:
                raise DecodingError(f"the token contains {ch!r}, which is not a letter or digit")
            value = value * 62 + digit
        if value >> (8 * size):
            raise DecodingError("the token is corrupted")
        out += value.to_bytes(size, "big")
    return bytes(out)


def is_sealed(text: str) -> bool:
    """Return whether ``text`` (already stripped) looks like an encrypted token."""
    return text.startswith(PREFIX)


def _token_bytes(token: TokenLike) -> bytes:
    body = "".join(token_text(token).split())  # wrapped lines and CRLF are fine
    if not body.startswith(PREFIX):
        raise DecodingError("not an encrypted yace2 token; use decode() for other tokens")
    raw = yace62_decode(body[len(PREFIX) :])
    if len(raw) < SALT_SIZE + padme(_FRAME.size) + TAG_SIZE:
        raise DecodingError("the token is truncated or corrupted")
    return raw


def _secret(salt: bytes, *, key: Optional[bytes] = None, password: Optional[str] = None) -> bytes:
    if (key is None) == (password is None):
        raise ValueError("pass exactly one of key and password")
    if key is not None:
        if len(key) != KEY_SIZE:
            raise ValueError(f"a key must be {KEY_SIZE} bytes")
        return bytes(key)
    assert password is not None
    if not password:
        raise EncodingError("the password is empty")
    try:
        return hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
            maxmem=_SCRYPT_MAXMEM, dklen=KEY_SIZE,
        )
    except UnicodeEncodeError:
        raise EncodingError("the password contains characters that are not valid text") from None


def _subkeys(secret: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    prk = hmac.digest(salt, secret, "sha256")  # HKDF-Extract
    return _hkdf_expand(prk, _INFO_ENCRYPT), _hkdf_expand(prk, _INFO_AUTHENTICATE)


def _hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    okm, block = b"", b""
    for counter in range(1, -(-length // 32) + 1):
        block = hmac.digest(prk, block + info + bytes([counter]), "sha256")
        okm += block
    return okm[:length]


def _xor_keystream(key: bytes, data: bytes) -> bytes:
    if not data:
        return b""
    stream = b"".join(
        hmac.digest(key, counter.to_bytes(8, "big"), "sha256")
        for counter in range(-(-len(data) // 32))
    )[: len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(len(data), "big")


def _tag(mac_key: bytes, salt: bytes, ciphertext: bytes) -> bytes:
    return hmac.digest(mac_key, PREFIX.encode("ascii") + salt + ciphertext, "sha256")

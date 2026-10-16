"""Encrypted YACE tokens.

An encrypted token is only letters and digits (or raw bytes). It reveals
nothing about its contents except roughly how long they are: no family name,
key name, algorithm, creation time, or exact length.

Format version 3 (a single message)::

    salt (16) || masked(version 0x03 || algorithm id) || ciphertext || tag

1. A random 16-byte salt is drawn for every token.
2. The secret is a 32-byte key, or your own secret token (any text or bytes)
   stretched with scrypt (N=2**17, r=8, p=1) and the salt.
3. ``PRK = HMAC-SHA256(salt, secret)`` (HKDF-Extract). HKDF-Expand derives the
   algorithm's keys, with the version and algorithm id in the ``info``, and a
   3-byte mask for the header. The mask hides the version and algorithm, so
   tokens have no recognisable prefix.
4. A frame holds the data type (text or bytes), the creation time, the data
   length, the data, and zero padding to a Padmé length.
5. The algorithm (see :mod:`yace_codec._algorithms`) encrypts the frame. Its
   tag covers ``salt || version || algorithm id`` (unmasked), the length-
   prefixed associated data, and the ciphertext.
6. Text output is YACE62: 8-byte blocks as 11 letters and digits.

Tokens from versions 0.2.0 (``yace2_`` prefix) and 0.2.1 still decrypt.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import string
import struct
import time
from typing import Iterable, List, Optional, Tuple, Union

from . import _algorithms
from ._algorithms import DEFAULT_ALGORITHM, hkdf_expand
from ._text import TokenLike, token_text
from .errors import DecodingError, DecryptionError, EncodingError, TokenExpiredError

__all__ = [
    "DEFAULT_ALGORITHM",
    "KEY_SIZE",
    "looks_encrypted",
    "padme",
    "seal",
    "unseal",
    "yace62_decode",
    "yace62_encode",
]

#: Tokens made by version 0.2.0 start with this.
LEGACY_PREFIX = "yace2_"
#: Size in bytes of secret keys.
KEY_SIZE = 32
#: Format version of single-message tokens.
VERSION_MESSAGE = 3

SALT_SIZE = 16
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
_SCRYPT_MAXMEM = 256 * 1024 * 1024

#: A secret chosen by the user: any non-empty text or bytes.
Secret = Union[str, bytes, bytearray, memoryview]
#: Associated data: bytes, or text (encoded as UTF-8).
Aad = Union[str, bytes, bytearray, memoryview]

_FRAME = struct.Struct("!BQQ")  # kind, creation time (Unix seconds), data length
_KIND_BYTES = 0
_KIND_TEXT = 1
_MASK_INFO = b"yace3 header mask"
_LEGACY_INFO_ENCRYPT = b"yace2 encryption"
_LEGACY_INFO_AUTHENTICATE = b"yace2 authentication"
_LEGACY_TAG_SIZE = 32

_ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase
_DIGIT = {ch: i for i, ch in enumerate(_ALPHABET)}
# Characters needed for a final block of 1-8 bytes (62**chars >= 256**bytes).
_CHARS_FOR = {1: 2, 2: 3, 3: 5, 4: 6, 5: 7, 6: 9, 7: 10, 8: 11}
_BYTES_FOR = {chars: size for size, chars in _CHARS_FOR.items()}
# The smallest token: salt, header, the smallest padded frame, and a 16-byte tag.
_MIN_BYTES = SALT_SIZE + 2 + 18 + 16


def seal(
    data: bytes,
    *,
    text: bool,
    key: Optional[bytes] = None,
    secret: Optional[Secret] = None,
    aad: Aad = b"",
    algorithm: Optional[str] = None,
    now: Optional[float] = None,
    salt: Optional[bytes] = None,
) -> str:
    """Encrypt ``data`` with a 32-byte ``key`` or your own ``secret``; return a token.

    ``aad`` (associated data) is authenticated but not stored: decryption needs
    the same ``aad``, so a token moved to another context (another record, user,
    or file) does not decrypt there.
    ``algorithm`` defaults to :data:`DEFAULT_ALGORITHM`. ``salt`` and ``now``
    fix the random salt and the creation time, for test vectors only.
    """
    alg = _algorithms.by_name(algorithm)
    aad_block = _aad_block(aad)
    salt = secrets.token_bytes(SALT_SIZE) if salt is None else _check_salt(salt)
    prk = _extract(salt, _secret(salt, key=key, secret=secret))
    created = int(time.time() if now is None else now)
    frame = _FRAME.pack(_KIND_TEXT if text else _KIND_BYTES, created, len(data)) + bytes(data)
    frame += bytes(padme(len(frame)) - len(frame))
    header = salt + bytes([VERSION_MESSAGE, alg.id])
    body = alg.cipher(prk, VERSION_MESSAGE, header + aad_block).seal(b"", frame)
    mask = _mask(prk)
    raw = salt + bytes([VERSION_MESSAGE ^ mask[0], alg.id ^ mask[1]]) + body
    return yace62_encode(raw)


def unseal(
    token: TokenLike,
    *,
    keys: Iterable[bytes] = (),
    secret: Optional[Secret] = None,
    aad: Aad = b"",
    max_age: Optional[float] = None,
    now: Optional[float] = None,
) -> Tuple[bytes, bool]:
    """Decrypt a token; return ``(data, is_text)``.

    With ``secret``, only that secret is tried. Otherwise every key in
    ``keys`` is tried, so tokens never need to name their key. ``aad`` must
    be the associated data given to :func:`seal`.
    """
    aad_block = _aad_block(aad)
    prefix, raw = _token_bytes(token)
    salt = raw[:SALT_SIZE]
    candidates = [_secret(salt, secret=secret)] if secret is not None else [_check_key(k) for k in keys]
    if not candidates:
        raise DecryptionError("no keys to try; pass the secret token if one was used")
    unavailable: List[DecryptionError] = []
    for candidate in candidates:
        prk = _extract(salt, candidate)
        frame = None if prefix else _open_message(prk, raw, aad_block, unavailable)
        if frame is None and len(aad_block) == 8:  # older tokens have no associated data
            frame = _open_legacy(prk, prefix, raw)
        if frame is not None:
            break
    else:
        if unavailable:
            raise unavailable[0]
        raise DecryptionError(
            "this cannot be opened: wrong secret token or key, or the data was changed"
        )
    kind, created, length = _FRAME.unpack_from(frame)
    if kind not in (_KIND_BYTES, _KIND_TEXT) or _FRAME.size + length > len(frame):
        raise DecryptionError("the token's contents are malformed")
    _check_age(created, max_age, now)
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


def looks_encrypted(text: str) -> bool:
    """Return whether ``text`` has the shape of an encrypted token."""
    body = "".join(text.split())
    if body.startswith(LEGACY_PREFIX):
        body = body[len(LEGACY_PREFIX) :]
    groups, rest = divmod(len(body), 11)
    return (
        _DIGIT.keys() >= set(body)
        and (rest == 0 or rest in _BYTES_FOR)
        and 8 * groups + _BYTES_FOR.get(rest, 0) >= _MIN_BYTES
    )


def _token_bytes(token: TokenLike) -> Tuple[str, bytes]:
    body = "".join(token_text(token).split())  # wrapped lines and CRLF are fine
    if not body:
        raise DecodingError("the token is empty")
    prefix = LEGACY_PREFIX if body.startswith(LEGACY_PREFIX) else ""
    body = body[len(prefix) :]
    if not _DIGIT.keys() >= set(body):
        raise DecodingError("this is not an encrypted token; use decode() for encoded tokens")
    raw = yace62_decode(body)
    if len(raw) < _MIN_BYTES:
        raise DecodingError("the token is truncated or corrupted")
    return prefix, raw


def _open_message(
    prk: bytes, raw: bytes, aad_block: bytes, unavailable: List[DecryptionError]
) -> Optional[bytes]:
    mask = _mask(prk)
    if raw[SALT_SIZE] ^ mask[0] != VERSION_MESSAGE:
        return None
    alg = _algorithms.by_id(raw[SALT_SIZE + 1] ^ mask[1])
    if alg is None:
        return None
    if not alg.available:
        unavailable.append(_algorithms.unavailable_error(alg))
        return None
    header = raw[:SALT_SIZE] + bytes([VERSION_MESSAGE, alg.id])
    frame = alg.cipher(prk, VERSION_MESSAGE, header + aad_block).open(b"", raw[SALT_SIZE + 2 :])
    if frame is None or len(frame) < _FRAME.size:
        return None
    return frame


def _open_legacy(prk: bytes, prefix: str, raw: bytes) -> Optional[bytes]:
    """Open a token from version 0.2.0 or 0.2.1 (no header, HMAC-SHA256 only)."""
    if len(raw) < SALT_SIZE + 18 + _LEGACY_TAG_SIZE:
        return None
    salt, ciphertext, tag = raw[:SALT_SIZE], raw[SALT_SIZE:-_LEGACY_TAG_SIZE], raw[-_LEGACY_TAG_SIZE:]
    mac_key = hkdf_expand(prk, _LEGACY_INFO_AUTHENTICATE)
    expected = hmac.digest(mac_key, prefix.encode("ascii") + salt + ciphertext, "sha256")
    if not hmac.compare_digest(tag, expected):
        return None
    return _algorithms.xor_keystream(hkdf_expand(prk, _LEGACY_INFO_ENCRYPT), ciphertext)


def _check_age(created: int, max_age: Optional[float], now: Optional[float]) -> None:
    if max_age is not None:
        age = (time.time() if now is None else now) - created
        if age > max_age:
            raise TokenExpiredError(f"the token is {int(age)} seconds old (limit {max_age})")


def _aad_block(aad: Aad) -> bytes:
    """Length-prefixed associated data, so its boundary is unambiguous."""
    if isinstance(aad, str):
        data = aad.encode("utf-8", "surrogatepass")
    elif isinstance(aad, (bytes, bytearray, memoryview)):
        data = bytes(aad)
    else:
        raise TypeError(f"aad must be bytes or str, not {type(aad).__name__}")
    return len(data).to_bytes(8, "big") + data


def _extract(salt: bytes, secret: bytes) -> bytes:
    return hmac.digest(salt, secret, "sha256")  # HKDF-Extract


def _mask(prk: bytes) -> bytes:
    return hkdf_expand(prk, _MASK_INFO, 3)


def _check_salt(salt: bytes) -> bytes:
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_SIZE:
        raise ValueError(f"salt must be {SALT_SIZE} bytes")
    return bytes(salt)


def _check_key(key: object) -> bytes:
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError(f"a key must be bytes, not {type(key).__name__}")
    key = bytes(key)
    if len(key) != KEY_SIZE:
        raise ValueError(f"a key must be {KEY_SIZE} bytes, not {len(key)}")
    return key


def _secret(salt: bytes, *, key: Optional[bytes] = None, secret: Optional[Secret] = None) -> bytes:
    if (key is None) == (secret is None):
        raise ValueError("pass exactly one of key and secret")
    if key is not None:
        return _check_key(key)
    if isinstance(secret, str):
        try:
            material = secret.encode("utf-8")
        except UnicodeEncodeError:
            raise EncodingError("the secret token contains characters that are not valid text") from None
    elif isinstance(secret, (bytes, bytearray, memoryview)):
        material = bytes(secret)
    else:
        raise TypeError(f"the secret token must be str or bytes, not {type(secret).__name__}")
    if not material:
        raise EncodingError("the secret token is empty")
    return hashlib.scrypt(
        material, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        maxmem=_SCRYPT_MAXMEM, dklen=KEY_SIZE,
    )


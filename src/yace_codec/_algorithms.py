"""Authenticated encryption algorithms for encrypted tokens.

Every algorithm turns a pseudorandom key (``prk``, from HKDF-Extract over the
token's salt) into a :class:`Cipher` bound to one token or stream:

- ``aes-256-gcm`` and ``chacha20-poly1305`` use the audited implementations in
  the ``cryptography`` package. The key and the 12-byte nonce both come from
  HKDF-Expand, and every token has its own salt, so a key never sees the same
  nonce twice.
- ``yace-hmac-sha256`` uses only Python's standard library: a keystream of
  HMAC-SHA256 blocks in counter mode, and an HMAC-SHA256 tag over the
  associated data and the ciphertext (encrypt-then-MAC), truncated to 16 bytes
  so every algorithm has the same tag size and output length.
"""

from __future__ import annotations

import hmac
import struct
from typing import Any, Dict, List, NamedTuple, Optional, Tuple, Type

from .errors import DecryptionError, EncodingError

__all__ = ["DEFAULT_ALGORITHM", "AlgorithmInfo", "Cipher", "algorithms", "by_id", "by_name"]

#: Algorithm used when none is given.
DEFAULT_ALGORITHM = "aes-256-gcm"

_INSTALL_HINT = "it needs the 'cryptography' package (pip install cryptography)"


class AlgorithmInfo(NamedTuple):
    """Description of an encryption algorithm, as listed by :func:`algorithms`."""

    name: str
    id: int
    tag_size: int
    available: bool
    default: bool
    description: str


AlgorithmInfo.__module__ = "yace_codec"


class Cipher:
    """Encrypts and authenticates the parts of one token or stream.

    ``ad`` is authenticated with every part. ``suffix`` tells parts apart (empty
    for a single message; chunk index and final flag for streams).
    """

    tag_size: int

    def seal(self, suffix: bytes, plaintext: bytes) -> bytes:
        raise NotImplementedError

    def open(self, suffix: bytes, body: bytes) -> Optional[bytes]:
        """Return the plaintext, or ``None`` if authentication fails."""
        raise NotImplementedError


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand with SHA-256 (RFC 5869)."""
    okm, block = b"", b""
    for counter in range(1, -(-length // 32) + 1):
        block = hmac.digest(prk, block + info + bytes([counter]), "sha256")
        okm += block
    return okm[:length]


def xor_keystream(key: bytes, data: bytes, prefix: bytes = b"") -> bytes:
    """XOR ``data`` with HMAC-SHA256(key, prefix || u64 counter) blocks.

    Works through ``data`` in 64 KiB pieces, so memory stays proportional to it.
    """
    out = bytearray(len(data))
    counter = 0
    for start in range(0, len(data), _XOR_PIECE):
        piece = data[start : start + _XOR_PIECE]
        blocks = -(-len(piece) // 32)
        stream = b"".join(
            hmac.digest(key, prefix + (counter + i).to_bytes(8, "big"), "sha256") for i in range(blocks)
        )[: len(piece)]
        counter += blocks
        mixed = int.from_bytes(piece, "big") ^ int.from_bytes(stream, "big")
        out[start : start + len(piece)] = mixed.to_bytes(len(piece), "big")
    return bytes(out)


_XOR_PIECE = 64 * 1024  # a multiple of the 32-byte block size


class _HmacCipher(Cipher):
    tag_size = 16

    def __init__(self, encrypt_key: bytes, mac_key: bytes, ad: bytes) -> None:
        self._encrypt_key = encrypt_key
        self._mac = hmac.new(mac_key, ad, "sha256")

    def __repr__(self) -> str:
        return "<yace-hmac-sha256 cipher>"

    def _tag(self, suffix: bytes, ciphertext: bytes) -> bytes:
        mac = self._mac.copy()
        mac.update(suffix)
        mac.update(ciphertext)
        return mac.digest()[: self.tag_size]

    def seal(self, suffix: bytes, plaintext: bytes) -> bytes:
        ciphertext = xor_keystream(self._encrypt_key, plaintext, suffix)
        return ciphertext + self._tag(suffix, ciphertext)

    def open(self, suffix: bytes, body: bytes) -> Optional[bytes]:
        if len(body) < self.tag_size:
            return None
        ciphertext, tag = body[: -self.tag_size], body[-self.tag_size :]
        if not hmac.compare_digest(tag, self._tag(suffix, ciphertext)):
            return None
        return xor_keystream(self._encrypt_key, ciphertext, suffix)


class _AeadCipher(Cipher):
    tag_size = 16

    def __init__(
        self, aead: Any, nonce: bytes, ad: bytes, invalid_tag: Type[BaseException]
    ) -> None:
        self._aead = aead
        self._nonce = nonce
        self._ad = ad
        self._invalid_tag = invalid_tag

    def __repr__(self) -> str:
        return f"<{type(self._aead).__name__} cipher>"

    def _nonce_for(self, suffix: bytes) -> bytes:
        # Messages use the derived nonce; stream chunks replace its last bytes
        # with the chunk index and final flag (the STREAM construction).
        return self._nonce[: len(self._nonce) - len(suffix)] + suffix

    def seal(self, suffix: bytes, plaintext: bytes) -> bytes:
        return bytes(self._aead.encrypt(self._nonce_for(suffix), plaintext, self._ad))

    def open(self, suffix: bytes, body: bytes) -> Optional[bytes]:
        if len(body) < self.tag_size:
            return None
        try:
            return bytes(self._aead.decrypt(self._nonce_for(suffix), body, self._ad))
        except (self._invalid_tag, OverflowError):  # OverflowError: over 2 GiB
            return None


class _Algorithm:
    def __init__(self, name: str, id: int, tag_size: int, description: str) -> None:
        self.name = name
        self.id = id
        self.tag_size = tag_size
        self.description = description

    def __repr__(self) -> str:
        return f"<algorithm {self.name}>"

    def info(self, label: bytes, version: int) -> bytes:
        return b"yace3" + struct.pack("!BB", version, self.id) + label

    @property
    def available(self) -> bool:
        return True

    def cipher(self, prk: bytes, version: int, ad: bytes) -> Cipher:
        raise NotImplementedError


class _Hmac(_Algorithm):
    def cipher(self, prk: bytes, version: int, ad: bytes) -> Cipher:
        return _HmacCipher(
            hkdf_expand(prk, self.info(b" enc", version)),
            hkdf_expand(prk, self.info(b" mac", version)),
            ad,
        )


class _Aead(_Algorithm):
    def __init__(self, name: str, id: int, description: str, class_name: str) -> None:
        super().__init__(name, id, 16, description)
        self._class_name = class_name

    def _load(self) -> Optional[Tuple[Any, Type[BaseException]]]:
        try:
            from cryptography.exceptions import InvalidTag
            from cryptography.hazmat.primitives.ciphers import aead
        except ImportError:
            return None
        return getattr(aead, self._class_name), InvalidTag

    @property
    def available(self) -> bool:
        return self._load() is not None

    def cipher(self, prk: bytes, version: int, ad: bytes) -> Cipher:
        loaded = self._load()
        if loaded is None:
            raise EncodingError(f"{self.name} is not available: {_INSTALL_HINT}")
        aead_class, invalid_tag = loaded
        return _AeadCipher(
            aead_class(hkdf_expand(prk, self.info(b" key", version))),
            hkdf_expand(prk, self.info(b" nonce", version), 12),
            ad,
            invalid_tag,
        )


_ALGORITHMS: List[_Algorithm] = [
    _Aead(
        "aes-256-gcm", 2,
        "AES-256 in GCM mode (needs the cryptography package)",
        "AESGCM",
    ),
    _Aead(
        "chacha20-poly1305", 3,
        "ChaCha20-Poly1305 (fast without AES hardware; needs the cryptography package)",
        "ChaCha20Poly1305",
    ),
    _Hmac(
        "yace-hmac-sha256", 1, 16,
        "HMAC-SHA256 keystream and tag (standard library only; slower, not audited)",
    ),
]
_BY_NAME: Dict[str, _Algorithm] = {alg.name: alg for alg in _ALGORITHMS}
_BY_ID: Dict[int, _Algorithm] = {alg.id: alg for alg in _ALGORITHMS}


def algorithms() -> List[AlgorithmInfo]:
    """List the encryption algorithms, the default first."""
    return [
        AlgorithmInfo(
            alg.name, alg.id, alg.tag_size, alg.available, alg.name == DEFAULT_ALGORITHM,
            alg.description,
        )
        for alg in _ALGORITHMS
    ]


def by_name(name: Optional[str]) -> _Algorithm:
    """Return the algorithm called ``name`` (``None`` for the default)."""
    alg = _BY_NAME.get(DEFAULT_ALGORITHM if name is None else name)
    if alg is None:
        raise EncodingError(
            f"unknown algorithm {name!r}; choose one of {', '.join(_BY_NAME)}"
        )
    if not alg.available:
        raise EncodingError(f"{alg.name} is not available: {_INSTALL_HINT}")
    return alg


def by_id(algorithm_id: int) -> Optional[_Algorithm]:
    """Return the algorithm with ``algorithm_id``, or ``None`` if there is none."""
    return _BY_ID.get(algorithm_id)


def unavailable_error(alg: _Algorithm) -> DecryptionError:
    return DecryptionError(f"this may have been encrypted with {alg.name}, and {_INSTALL_HINT}")

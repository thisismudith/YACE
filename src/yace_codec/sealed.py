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

import codecs
import hashlib
import hmac
import io
import secrets
import string
import struct
import time
from typing import BinaryIO, Callable, Iterable, List, Literal, NamedTuple, Optional, Tuple, Union

from . import _algorithms
from ._algorithms import DEFAULT_ALGORITHM, hkdf_expand
from ._text import TokenLike, token_text
from .errors import DecodingError, DecryptionError, EncodingError, InvalidKeyError, TokenExpiredError

__all__ = [
    "DEFAULT_ALGORITHM",
    "DEFAULT_CHUNK_SIZE",
    "KEY_SIZE",
    "StreamInfo",
    "check_key",
    "looks_encrypted",
    "padme",
    "seal",
    "seal_stream",
    "unseal",
    "unseal_stream",
    "yace62_decode",
    "yace62_encode",
]

#: Tokens made by version 0.2.0 start with this.
LEGACY_PREFIX = "yace2_"
#: Size in bytes of secret keys.
KEY_SIZE = 32
#: Format version of single-message tokens.
VERSION_MESSAGE = 3
#: Format version of streams (chunked).
VERSION_STREAM = 4
#: Default plaintext chunk size of streams.
DEFAULT_CHUNK_SIZE = 64 * 1024

SALT_SIZE = 16
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
_SCRYPT_MAXMEM = 256 * 1024 * 1024

#: A secret chosen by the user: any non-empty text or bytes.
Secret = Union[str, bytes, bytearray, memoryview]
#: Output formats: YACE62 letters and digits, or raw bytes.
Output = Literal["text", "bytes"]
#: Associated data: bytes, or text (encoded as UTF-8).
Aad = Union[str, bytes, bytearray, memoryview]

_FRAME = struct.Struct("!BQQ")  # kind, creation time (Unix seconds), data length
_STREAM_META = struct.Struct("!BQ")  # kind, creation time; starts a stream's data
_COUNT = struct.Struct("!I")  # data bytes in a chunk (the rest is padding)
_STREAM_HEADER_SIZE = SALT_SIZE + 3
_MIN_CHUNK_LOG2 = 6
_MAX_CHUNK_LOG2 = 20
_MAX_CHUNK_INDEX = 2**32 - 1
_IO_SIZE = 64 * 1024
_KIND_BYTES = 0
_KIND_TEXT = 1
_MASK_INFO = b"yace3 header mask"
_LEGACY_INFO_ENCRYPT = b"yace2 encryption"
_LEGACY_INFO_AUTHENTICATE = b"yace2 authentication"
_LEGACY_TAG_SIZE = 32

_ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase
_DIGIT = {ch: i for i, ch in enumerate(_ALPHABET)}
_PAIRS = [a + b for a in _ALPHABET for b in _ALPHABET]  # speeds up encoding
# Characters needed for a final block of 1-8 bytes (62**chars >= 256**bytes).
_CHARS_FOR = {1: 2, 2: 3, 3: 5, 4: 6, 5: 7, 6: 9, 7: 10, 8: 11}
_BYTES_FOR = {chars: size for size, chars in _CHARS_FOR.items()}
# The smallest token: an empty stream (salt, header, one chunk of a 4-byte count
# and 10 bytes of padded metadata, 16-byte tag). Messages are at least 52 bytes.
_MIN_BYTES = SALT_SIZE + 3 + 4 + 10 + 16
_TEXT_BYTES = frozenset((_ALPHABET + "_ " + string.whitespace).encode("ascii"))
_BOMS = (codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE, codecs.BOM_UTF32_BE)
# UTF-32 first: its little-endian BOM starts with the UTF-16 one.
_TEXT_ENCODINGS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


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
    output: str = "text",
) -> Union[str, bytes]:
    """Encrypt ``data`` with a 32-byte ``key`` or your own ``secret``; return a token.

    With ``output="text"`` (the default) the token is YACE62 text; with
    ``output="bytes"`` it is the raw binary token, about 27% smaller.

    ``aad`` (associated data) is authenticated but not stored: decryption needs
    the same ``aad``, so a token moved to another context (another record, user,
    or file) does not decrypt there.
    ``algorithm`` defaults to :data:`DEFAULT_ALGORITHM`. ``salt`` and ``now``
    fix the random salt and the creation time, for test vectors only.
    """
    as_text = _wants_text(output)
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
    return yace62_encode(raw) if as_text else raw


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
    be the associated data given to :func:`seal`. Stream tokens (from
    :func:`seal_stream`) are decrypted in memory.
    """
    aad_block = _aad_block(aad)
    prefix, raw = _token_bytes(token)
    candidates = _candidates(raw[:SALT_SIZE], keys, secret)
    if not prefix:
        streams = _stream_candidates(raw[:_STREAM_HEADER_SIZE], candidates)
        if streams:
            out = io.BytesIO()
            reader = _ByteReader(io.BytesIO(raw[_STREAM_HEADER_SIZE:]).read)
            info = _open_chunks(reader, raw[:SALT_SIZE], streams, out, aad_block, max_age, now)
            if info is not None:
                return out.getvalue(), info.text
    return _open_frame(prefix, raw, candidates, aad_block, max_age, now)


class StreamInfo(NamedTuple):
    """What :func:`unseal_stream` decrypted: ``size`` bytes, which were text if ``text``."""

    size: int
    text: bool


def seal_stream(
    src: BinaryIO,
    dst: BinaryIO,
    *,
    text: bool = False,
    key: Optional[bytes] = None,
    secret: Optional[Secret] = None,
    aad: Aad = b"",
    algorithm: Optional[str] = None,
    output: str = "text",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    now: Optional[float] = None,
    salt: Optional[bytes] = None,
) -> int:
    """Encrypt everything read from ``src`` into ``dst``; return the bytes written.

    Memory use is constant: ``src`` is read in chunks of ``chunk_size`` bytes
    (a power of two from 64 bytes to 1 MiB). Each chunk is encrypted with a
    nonce made from its index and a final-chunk flag, so truncation,
    reordering, and duplication are detected. ``text`` marks the data as text
    for :func:`unseal`. The other arguments work as in :func:`seal`.
    """
    log2 = _chunk_log2(chunk_size)
    writer = _Writer(dst, _wants_text(output))
    alg = _algorithms.by_name(algorithm)
    aad_block = _aad_block(aad)
    salt = secrets.token_bytes(SALT_SIZE) if salt is None else _check_salt(salt)
    prk = _extract(salt, _secret(salt, key=key, secret=secret))
    mask = _mask(prk)
    cipher = alg.cipher(prk, VERSION_STREAM, salt + bytes([VERSION_STREAM, alg.id, log2]) + aad_block)
    writer.write(salt + bytes([VERSION_STREAM ^ mask[0], alg.id ^ mask[1], log2 ^ mask[2]]))
    capacity = (1 << log2) - _COUNT.size
    index = 0

    def emit(real: bytes, zeros: int, last: bool) -> None:
        nonlocal index
        if index > _MAX_CHUNK_INDEX:
            raise EncodingError("the stream is too long")
        writer.write(cipher.seal(_chunk_suffix(index, last), _COUNT.pack(len(real)) + real + bytes(zeros)))
        index += 1

    created = int(time.time() if now is None else now)
    buf = _STREAM_META.pack(_KIND_TEXT if text else _KIND_BYTES, created)
    buf += _read_up_to(src, capacity - len(buf))
    length = len(buf)
    while len(buf) == capacity:
        following = _read_up_to(src, capacity)
        if not following:
            break
        emit(buf, 0, False)
        buf = following
        length += len(buf)
    # Zero padding (not counted as data) brings the total to a Padmé length.
    zeros = padme(length) - length
    while True:
        fill = min(capacity - len(buf), zeros)
        zeros -= fill
        emit(buf, fill, zeros == 0)
        if zeros == 0:
            break
        buf = b""
    writer.close()
    return writer.count


def unseal_stream(
    src: BinaryIO,
    dst: BinaryIO,
    *,
    keys: Iterable[bytes] = (),
    secret: Optional[Secret] = None,
    aad: Aad = b"",
    max_age: Optional[float] = None,
    now: Optional[float] = None,
) -> StreamInfo:
    """Decrypt a token read from ``src`` into ``dst``.

    Stream tokens are decrypted chunk by chunk in constant memory; other
    tokens are read whole. Text and binary input are both accepted. Chunks are
    written as soon as they are verified, so if this raises, ``dst`` may hold
    part of the data: discard it.
    """
    aad_block = _aad_block(aad)
    reader, prefix = _token_reader(src)
    if prefix:
        raw = reader.read_all()
        data, is_text = _open_frame(prefix, raw, _candidates(raw[:SALT_SIZE], keys, secret), aad_block, max_age, now)
        _write_all(dst, data)
        return StreamInfo(len(data), is_text)
    head = reader.read(_STREAM_HEADER_SIZE)
    if len(head) < _STREAM_HEADER_SIZE:
        raise DecodingError("the token is truncated or corrupted")
    candidates = _candidates(head[:SALT_SIZE], keys, secret)
    streams = _stream_candidates(head, candidates)
    if streams:
        info = _open_chunks(reader, head[:SALT_SIZE], streams, dst, aad_block, max_age, now)
        if info is not None:
            return info
    raw = head + reader.read_all()
    if len(raw) < _MIN_BYTES:
        raise DecodingError("the token is truncated or corrupted")
    data, is_text = _open_frame("", raw, candidates, aad_block, max_age, now)
    _write_all(dst, data)
    return StreamInfo(len(data), is_text)


def _open_frame(
    prefix: str,
    raw: bytes,
    candidates: List[bytes],
    aad_block: bytes,
    max_age: Optional[float],
    now: Optional[float],
) -> Tuple[bytes, bool]:
    """Open a single-message token (version 3, or 0.2.x) with the first matching secret."""
    unavailable: List[DecryptionError] = []
    for candidate in candidates:
        prk = _extract(raw[:SALT_SIZE], candidate)
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


_StreamCandidate = Tuple[bytes, "_algorithms._Algorithm", int]


def _stream_candidates(head: bytes, candidates: List[bytes]) -> List[_StreamCandidate]:
    """Secrets whose header mask reveals a valid stream header."""
    found: List[_StreamCandidate] = []
    if len(head) < _STREAM_HEADER_SIZE:
        return found
    for candidate in candidates:
        prk = _extract(head[:SALT_SIZE], candidate)
        mask = _mask(prk)
        if head[SALT_SIZE] ^ mask[0] != VERSION_STREAM:
            continue
        alg = _algorithms.by_id(head[SALT_SIZE + 1] ^ mask[1])
        log2 = head[SALT_SIZE + 2] ^ mask[2]
        if alg is not None and alg.available and _MIN_CHUNK_LOG2 <= log2 <= _MAX_CHUNK_LOG2:
            found.append((prk, alg, log2))
    return found


def _open_chunks(
    reader: _ByteReader,
    salt: bytes,
    streams: List[_StreamCandidate],
    dst: BinaryIO,
    aad_block: bytes,
    max_age: Optional[float],
    now: Optional[float],
) -> Optional[StreamInfo]:
    """Decrypt stream chunks into ``dst``; ``None`` if no candidate opens chunk 0."""
    for prk, alg, log2 in streams:
        cipher = alg.cipher(prk, VERSION_STREAM, salt + bytes([VERSION_STREAM, alg.id, log2]) + aad_block)
        size = (1 << log2) + alg.tag_size
        current = reader.read(size)
        following = reader.read(size)
        plaintext = cipher.open(_chunk_suffix(0, not following), current)
        if plaintext is not None:
            break
        reader.unread(following)
        reader.unread(current)
    else:
        return None
    index = written = 0
    is_text = False
    while True:
        last = not following
        data = _chunk_data(plaintext, last, 1 << log2)
        if index == 0:
            if len(data) < _STREAM_META.size:
                raise DecryptionError("the stream's contents are malformed")
            kind, created = _STREAM_META.unpack_from(data)
            if kind not in (_KIND_BYTES, _KIND_TEXT):
                raise DecryptionError("the stream's contents are malformed")
            _check_age(created, max_age, now)
            is_text = kind == _KIND_TEXT
            data = data[_STREAM_META.size :]
        _write_all(dst, data)
        written += len(data)
        if last:
            return StreamInfo(written, is_text)
        index += 1
        if index > _MAX_CHUNK_INDEX:
            raise DecryptionError("the stream is too long")
        current, following = following, reader.read(size)
        opened = cipher.open(_chunk_suffix(index, not following), current)
        if opened is None:
            raise DecryptionError(
                f"the stream was truncated, reordered, or changed (at chunk {index}); "
                "discard what was written"
            )
        plaintext = opened


def _chunk_data(plaintext: bytes, last: bool, chunk_size: int) -> bytes:
    if len(plaintext) < _COUNT.size or (not last and len(plaintext) != chunk_size):
        raise DecryptionError("the stream's contents are malformed")
    (count,) = _COUNT.unpack_from(plaintext)
    if count > len(plaintext) - _COUNT.size:
        raise DecryptionError("the stream's contents are malformed")
    return plaintext[_COUNT.size : _COUNT.size + count]


def _chunk_suffix(index: int, last: bool) -> bytes:
    return index.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


def _chunk_log2(chunk_size: object) -> int:
    if (
        not isinstance(chunk_size, int)
        or isinstance(chunk_size, bool)
        or chunk_size <= 0
        or chunk_size & (chunk_size - 1)
        or not _MIN_CHUNK_LOG2 <= chunk_size.bit_length() - 1 <= _MAX_CHUNK_LOG2
    ):
        raise ValueError(
            f"chunk_size must be a power of two from {1 << _MIN_CHUNK_LOG2} "
            f"to {1 << _MAX_CHUNK_LOG2}, not {chunk_size!r}"
        )
    return chunk_size.bit_length() - 1


def _candidates(salt: bytes, keys: Iterable[bytes], secret: Optional[Secret]) -> List[bytes]:
    if secret is not None:
        return [_secret(salt, secret=secret)]
    candidates = [check_key(k) for k in keys]
    if not candidates:
        raise DecryptionError("no keys to try; pass the secret token if one was used")
    return candidates


def _read_up_to(src: BinaryIO, size: int) -> bytes:
    """Read ``size`` bytes, or fewer at the end of ``src`` (pipes return short reads)."""
    out = bytearray()
    while len(out) < size:
        piece = src.read(size - len(out))
        if not piece:
            break
        out += piece
    return bytes(out)


def _write_all(dst: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = dst.write(view)
        if written is None:  # a non-blocking raw stream that took nothing
            raise OSError("the output does not accept data")
        view = view[written:]


class _Writer:
    """Writes raw bytes, or YACE62 text (8-byte blocks; the remainder at close)."""

    def __init__(self, dst: BinaryIO, as_text: bool) -> None:
        self._dst = dst
        self._as_text = as_text
        self._pending = b""
        self.count = 0

    def write(self, data: bytes) -> None:
        if self._as_text:
            data = self._pending + data
            cut = len(data) - len(data) % 8
            self._pending = data[cut:]
            data = yace62_encode(data[:cut]).encode("ascii")
        if data:
            _write_all(self._dst, data)
            self.count += len(data)

    def close(self) -> None:
        if self._pending:
            data = yace62_encode(self._pending).encode("ascii")
            self._pending = b""
            _write_all(self._dst, data)
            self.count += len(data)


class _ByteReader:
    """Reads exact sizes (fewer only at the end) and can push data back."""

    def __init__(self, read: Callable[[int], bytes]) -> None:
        self._read = read
        self._back = bytearray()

    def read(self, size: int) -> bytes:
        out = bytearray(self._back[:size])
        del self._back[:size]
        while len(out) < size:
            piece = self._read(size - len(out))
            if not piece:
                break
            out += piece
        return bytes(out)

    def unread(self, data: bytes) -> None:
        self._back[:0] = data

    def read_all(self) -> bytes:
        out = bytearray(self._back)
        self._back.clear()
        while True:
            piece = self._read(_IO_SIZE)
            if not piece:
                return bytes(out)
            out += piece


class _Yace62Source:
    """Decodes YACE62 text (any encoding with a BOM, whitespace ignored) as it is read."""

    def __init__(self, src: BinaryIO, first: bytes) -> None:
        self._src = src
        encoding = next((enc for bom, enc in _TEXT_ENCODINGS if first.startswith(bom)), "utf-8")
        self._decoder = codecs.getincrementaldecoder(encoding)()
        self._chars = ""
        self._bytes = bytearray()
        self._done = False
        self._feed(first)

    def take_prefix(self) -> str:
        """Remove and return a leading ``yace2_`` (0.2.0 tokens), if there is one."""
        while len(self._chars) < len(LEGACY_PREFIX) and not self._done:
            self._pull()
        if self._chars.startswith(LEGACY_PREFIX):
            self._chars = self._chars[len(LEGACY_PREFIX) :]
            return LEGACY_PREFIX
        return ""

    def read(self, size: int) -> bytes:
        while len(self._bytes) < size and not (self._done and not self._chars):
            self._pull()
            usable = len(self._chars) if self._done else len(self._chars) - len(self._chars) % 11
            if usable:
                self._bytes += yace62_decode(self._chars[:usable])
                self._chars = self._chars[usable:]
        out = bytes(self._bytes[:size])
        del self._bytes[:size]
        return out

    def _pull(self) -> None:
        if self._done:
            return
        raw = self._src.read(_IO_SIZE)
        self._feed(raw or b"", final=not raw)

    def _feed(self, raw: bytes, final: bool = False) -> None:
        try:
            text = self._decoder.decode(raw, final)
        except UnicodeDecodeError:
            raise DecodingError("the token is not valid text") from None
        if text.startswith("﻿"):
            text = text[1:]
        self._chars += "".join(text.split())
        self._done = final


def _token_reader(src: BinaryIO) -> Tuple[_ByteReader, str]:
    """Wrap ``src`` so it yields binary token bytes, decoding text tokens on the fly."""
    first = _read_up_to(src, 64)
    if not first:
        raise DecodingError("the token is empty")
    if not is_text_token(first):
        reader = _ByteReader(src.read)
        reader.unread(first)
        return reader, ""
    source = _Yace62Source(src, first)
    prefix = source.take_prefix()
    return _ByteReader(source.read), prefix


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
    out: List[str] = []
    append = out.append
    full = len(data) - len(data) % 8
    for start in range(0, full, 8):
        # 62**11 > 2**64: one leading digit, then five two-character pairs.
        value = int.from_bytes(data[start : start + 8], "big")
        value, p5 = divmod(value, 3844)
        value, p4 = divmod(value, 3844)
        value, p3 = divmod(value, 3844)
        value, p2 = divmod(value, 3844)
        value, p1 = divmod(value, 3844)
        append(_ALPHABET[value] + _PAIRS[p1] + _PAIRS[p2] + _PAIRS[p3] + _PAIRS[p4] + _PAIRS[p5])
    if full < len(data):
        block = data[full:]
        value = int.from_bytes(block, "big")
        digits = []
        for _ in range(_CHARS_FOR[len(block)]):
            value, digit = divmod(value, 62)
            digits.append(_ALPHABET[digit])
        append("".join(reversed(digits)))
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


def _wants_text(output: object) -> bool:
    if output not in ("text", "bytes"):
        raise ValueError(f"output must be 'text' or 'bytes', not {output!r}")
    return output == "text"


def is_text_token(data: bytes) -> bool:
    """Return whether ``data`` holds a text token (YACE62, maybe with a BOM).

    Binary tokens start with a random salt, so the chance that one consists of
    letters, digits, and whitespace only is below 10**-30.
    """
    return data.startswith(_BOMS) or _TEXT_BYTES.issuperset(data)


def _token_bytes(token: TokenLike) -> Tuple[str, bytes]:
    if isinstance(token, (bytes, bytearray, memoryview)):
        data = bytes(token)
        if not is_text_token(data):
            if len(data) < _MIN_BYTES:
                raise DecodingError("the token is truncated or corrupted")
            return "", data
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


def check_key(key: object) -> bytes:
    """Return ``key`` as bytes; raise InvalidKeyError unless it is 32 bytes."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError(f"a key must be bytes, not {type(key).__name__}")
    key = bytes(key)
    if len(key) != KEY_SIZE:
        raise InvalidKeyError(f"a key must be {KEY_SIZE} bytes, not {len(key)}")
    return key


def _secret(salt: bytes, *, key: Optional[bytes] = None, secret: Optional[Secret] = None) -> bytes:
    if (key is None) == (secret is None):
        raise ValueError("pass exactly one of key and secret")
    if key is not None:
        return check_key(key)
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


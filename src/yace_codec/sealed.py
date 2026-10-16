"""Encrypted YACE output (the low-level layer behind ``encrypt`` and ``decrypt``).

Encrypted output is letters and digits (YACE62) or raw bytes. It reveals
nothing about its contents except roughly how long they are: no key name,
algorithm, creation time, or exact length.

Format version 3 (one message, :func:`seal`)::

    salt (16) || masked(u8 3 || u8 algorithm id || 4 zero bytes) || ciphertext || tag (16)

1. A random 16-byte salt is drawn every time.
2. The secret is a 32-byte key, or your own secret token (any text or bytes)
   stretched with scrypt (N=2**17, r=8, p=1) and the salt.
3. ``PRK = HMAC-SHA256(salt, secret)`` (HKDF-Extract). HKDF-Expand derives the
   algorithm's keys, with the version and algorithm id in the ``info``, and a
   7-byte mask for the header. The mask hides the version and algorithm, and
   the four zero bytes let decryption reject a wrong key at once.
4. A frame holds the data type (text or bytes), the creation time, the data
   length, the data, and zero padding to a Padmé length.
5. The algorithm (see :mod:`yace_codec._algorithms`) encrypts the frame. Its
   16-byte tag covers ``salt || version || algorithm id`` (unmasked), the
   length-prefixed associated data, and the ciphertext.

Format version 4 (a stream, :func:`seal_stream`) splits the data into chunks
that are sealed one by one, with the chunk index and a final-chunk flag in each
nonce. SECURITY.md specifies both formats byte by byte.

Output of versions 0.2.0 (``yace2_`` prefix) and 0.2.1 still decrypts.
"""

from __future__ import annotations

import codecs
import hashlib
import hmac
import io
import math
import secrets
import string
import struct
import time
from typing import (
    BinaryIO,
    Callable,
    Iterable,
    List,
    Literal,
    NamedTuple,
    Optional,
    Tuple,
    Union,
    cast,
    overload,
)

from . import _algorithms
from ._algorithms import DEFAULT_ALGORITHM, hkdf_expand
from ._text import BOM, TEXT_ENCODINGS, TokenLike, bom_encoding, token_text
from .errors import (
    DecodingError,
    DecryptionError,
    EncodingError,
    InvalidKeyError,
    TokenExpiredError,
)

__all__ = [
    "DEFAULT_ALGORITHM",
    "DEFAULT_CHUNK_SIZE",
    "KEY_SIZE",
    "MAX_MESSAGE_SIZE",
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

#: Output of version 0.2.0 starts with this.
LEGACY_PREFIX = "yace2_"
#: Size in bytes of secret keys.
KEY_SIZE = 32
#: Format version of single messages.
VERSION_MESSAGE = 3
#: Format version of streams (chunked).
VERSION_STREAM = 4
#: Default plaintext chunk size of streams.
DEFAULT_CHUNK_SIZE = 64 * 1024
#: Largest padded frame one message can hold (AES-GCM and ChaCha20-Poly1305 in
#: the cryptography package accept up to 2**31 - 1 bytes per call). Larger data
#: needs :func:`seal_stream`.
MAX_MESSAGE_SIZE = 2**31 - 1

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
BytesLike = Union[bytes, bytearray, memoryview]

_FRAME = struct.Struct("!BQQ")  # kind, creation time (Unix seconds), data length
_STREAM_META = struct.Struct("!BQ")  # kind, creation time; starts a stream's data
_COUNT = struct.Struct("!I")  # data bytes in a chunk (the rest is padding)
_CHECK = bytes(4)  # four zero bytes after the version and algorithm id (and log2)
_MESSAGE_HEADER_SIZE = SALT_SIZE + 2 + len(_CHECK)
_STREAM_HEADER_SIZE = SALT_SIZE + 3 + len(_CHECK)
_TAG_SIZE = 16
_MIN_CHUNK_LOG2 = 6
_MAX_CHUNK_LOG2 = 20
_MAX_CHUNK_INDEX = 2**32 - 1
_IO_SIZE = 64 * 1024
#: decrypt_stream() reads at most this much when only 0.2.x output (made in
#: memory, with no header) is left to try.
LEGACY_STREAM_LIMIT = 256 * 1024 * 1024
_CANNOT_OPEN = "this cannot be opened: wrong secret token, key, or aad, or the data was changed"
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
# The smallest output: an empty stream (header, one chunk of a 4-byte count and
# 10 bytes of padded metadata, and a tag). Messages are at least 56 bytes.
_MIN_BYTES = _STREAM_HEADER_SIZE + 4 + 10 + _TAG_SIZE
_WHITESPACE = " \t\n\r\x0b\x0c"  # only ASCII whitespace is ignored in text output
_DELETE_WHITESPACE = str.maketrans("", "", _WHITESPACE)
_TEXT_CHARS = frozenset(_ALPHABET + "_" + _WHITESPACE)
_TEXT_BYTES = frozenset((_ALPHABET + "_" + _WHITESPACE).encode("ascii"))
_BOMS = tuple(bom for bom, _encoding in TEXT_ENCODINGS)
_ENCODE_PIECE = 64 * 1024  # bytes of input per joined piece of YACE62 text


class StreamInfo(NamedTuple):
    """What :func:`unseal_stream` decrypted: ``size`` bytes, which were text if ``text``."""

    size: int
    text: bool


StreamInfo.__module__ = "yace_codec"

# --- public functions -----------------------------------------------------------


@overload
def seal(
    data: BytesLike, *, text: bool, key: Optional[bytes] = ..., secret: Optional[Secret] = ...,
    aad: Aad = ..., algorithm: Optional[str] = ..., now: Optional[float] = ...,
    salt: Optional[bytes] = ..., output: Literal["text"] = ...,
) -> str: ...
@overload
def seal(
    data: BytesLike, *, text: bool, key: Optional[bytes] = ..., secret: Optional[Secret] = ...,
    aad: Aad = ..., algorithm: Optional[str] = ..., now: Optional[float] = ...,
    salt: Optional[bytes] = ..., output: Literal["bytes"],
) -> bytes: ...
@overload
def seal(
    data: BytesLike, *, text: bool, key: Optional[bytes] = ..., secret: Optional[Secret] = ...,
    aad: Aad = ..., algorithm: Optional[str] = ..., now: Optional[float] = ...,
    salt: Optional[bytes] = ..., output: Output,
) -> Union[str, bytes]: ...
def seal(
    data: BytesLike,
    *,
    text: bool,
    key: Optional[bytes] = None,
    secret: Optional[Secret] = None,
    aad: Aad = b"",
    algorithm: Optional[str] = None,
    now: Optional[float] = None,
    salt: Optional[bytes] = None,
    output: Output = "text",
) -> Union[str, bytes]:
    """Encrypt ``data`` with a 32-byte ``key`` or your own ``secret``.

    Returns YACE62 text (``output="text"``) or raw bytes (``output="bytes"``).
    ``text=True`` marks ``data`` as UTF-8 text, which :func:`unseal` reports.
    ``aad`` (associated data) is authenticated but not stored: decryption needs
    the same ``aad``. ``algorithm`` defaults to :data:`DEFAULT_ALGORITHM`.

    ``salt`` and ``now`` fix the random salt and the creation time, for test
    vectors only: reusing a salt with the same key reuses the nonce, which
    breaks AES-GCM and ChaCha20-Poly1305.
    """
    as_text = _wants_text(output)
    data = _plain_bytes(data, text)
    alg = _algorithms.by_name(algorithm)
    aad_block = _aad_block(aad)
    created = _creation_time(now)
    frame = _FRAME.pack(_KIND_TEXT if text else _KIND_BYTES, created, len(data)) + data
    frame += bytes(padme(len(frame)) - len(frame))
    if len(frame) > MAX_MESSAGE_SIZE:
        raise EncodingError("the data is too large for one message (2 GiB); use encrypt_stream()")
    salt = _new_salt() if salt is None else _check_salt(salt)
    prk = _extract(salt, _secret(salt, key=key, secret=secret))
    ad = salt + bytes([VERSION_MESSAGE, alg.id]) + aad_block
    body = alg.cipher(prk, VERSION_MESSAGE, ad).seal(b"", frame)
    raw = salt + _xor(bytes([VERSION_MESSAGE, alg.id]) + _CHECK, _mask(prk)) + body
    return yace62_encode(raw) if as_text else raw


def unseal(
    token: TokenLike,
    *,
    keys: Iterable[BytesLike] = (),
    secret: Optional[Secret] = None,
    aad: Aad = b"",
    max_age: Optional[float] = None,
    now: Optional[float] = None,
) -> Tuple[bytes, bool]:
    """Decrypt output of :func:`seal` or :func:`seal_stream` in memory.

    Returns ``(data, is_text)``. With ``secret``, only that secret is tried;
    otherwise every key in ``keys`` is tried, so output never needs to name its
    key. ``aad`` must be the associated data used to encrypt.
    """
    _check_max_age(max_age)
    aad_block = _aad_block(aad)
    prefix, raw = _token_bytes(token)
    out = io.BytesIO()
    reader = _ByteReader(io.BytesIO(raw).read)
    info = _decrypt(reader, prefix, out, keys, secret, aad_block, max_age, now, legacy_limit=None)
    return out.getvalue(), info.text


def seal_stream(
    src: BinaryIO,
    dst: BinaryIO,
    *,
    text: bool = False,
    key: Optional[bytes] = None,
    secret: Optional[Secret] = None,
    aad: Aad = b"",
    algorithm: Optional[str] = None,
    output: Output = "text",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    now: Optional[float] = None,
    salt: Optional[bytes] = None,
) -> int:
    """Encrypt everything read from binary ``src`` into binary ``dst``; return bytes written.

    Memory use is constant: ``src`` is read in chunks of ``chunk_size`` bytes
    (a power of two from 64 bytes to 1 MiB). Each chunk is encrypted with a
    nonce made from its index and a final-chunk flag, so truncation,
    reordering, and duplication are detected. ``text=True`` requires UTF-8
    data and makes :func:`unseal` report it as text. The other arguments work
    as in :func:`seal`.
    """
    log2 = _chunk_log2(chunk_size)
    writer = _Writer(dst, _wants_text(output))
    alg = _algorithms.by_name(algorithm)
    aad_block = _aad_block(aad)
    created = _creation_time(now)
    salt = _new_salt() if salt is None else _check_salt(salt)
    prk = _extract(salt, _secret(salt, key=key, secret=secret))
    cipher = alg.cipher(prk, VERSION_STREAM, salt + bytes([VERSION_STREAM, alg.id, log2]) + aad_block)
    writer.write(salt + _xor(bytes([VERSION_STREAM, alg.id, log2]) + _CHECK, _mask(prk)))
    capacity = (1 << log2) - _COUNT.size
    index = 0

    def emit(real: bytes, zeros: int, last: bool) -> None:
        nonlocal index
        if index > _MAX_CHUNK_INDEX:
            raise EncodingError("the stream is too long")
        writer.write(cipher.seal(_chunk_suffix(index, last), _COUNT.pack(len(real)) + real + bytes(zeros)))
        index += 1

    source: BinaryIO = cast(BinaryIO, _Utf8Checked(src)) if text else src
    buf = _STREAM_META.pack(_KIND_TEXT if text else _KIND_BYTES, created)
    buf += _read_up_to(source, capacity - len(buf))
    length = len(buf)
    while len(buf) == capacity:
        following = _read_up_to(source, capacity)
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
    keys: Iterable[BytesLike] = (),
    secret: Optional[Secret] = None,
    aad: Aad = b"",
    max_age: Optional[float] = None,
    now: Optional[float] = None,
) -> StreamInfo:
    """Decrypt output read from binary ``src`` (text or bytes, any format) into ``dst``.

    Streams are decrypted chunk by chunk in constant memory; single messages
    are read whole. Chunks are written as soon as they are verified, so if this
    raises, ``dst`` may hold part of the data: discard it. Output of 0.2.x is
    read only up to :data:`LEGACY_STREAM_LIMIT`.
    """
    _check_max_age(max_age)
    aad_block = _aad_block(aad)
    reader, prefix = _token_reader(src)
    return _decrypt(reader, prefix, dst, keys, secret, aad_block, max_age, now, legacy_limit=LEGACY_STREAM_LIMIT)


def check_key(key: object) -> bytes:
    """Return ``key`` as bytes; raise InvalidKeyError unless it is 32 bytes."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError(f"a key must be bytes, not {type(key).__name__}")
    key = bytes(key)
    if len(key) != KEY_SIZE:
        raise InvalidKeyError(f"a key must be {KEY_SIZE} bytes, not {len(key)}")
    return key


def padme(length: int) -> int:
    """Round ``length`` up to a Padmé length, which leaks at most O(log log n) bits."""
    if length < 2:
        return length
    exponent = length.bit_length() - 1
    last_bits = exponent - exponent.bit_length()
    mask = (1 << last_bits) - 1
    return (length + mask) & ~mask


def yace62_encode(data: BytesLike) -> str:
    """Write bytes as letters and digits: every 8 bytes become 11 characters."""
    data = bytes(data)
    pieces = []
    full = len(data) - len(data) % 8
    for piece_start in range(0, full, _ENCODE_PIECE):
        out: List[str] = []
        append = out.append
        for start in range(piece_start, min(piece_start + _ENCODE_PIECE, full), 8):
            # 62**11 > 2**64: one leading digit, then five two-character pairs.
            value = int.from_bytes(data[start : start + 8], "big")
            value, p5 = divmod(value, 3844)
            value, p4 = divmod(value, 3844)
            value, p3 = divmod(value, 3844)
            value, p2 = divmod(value, 3844)
            value, p1 = divmod(value, 3844)
            append(_ALPHABET[value] + _PAIRS[p1] + _PAIRS[p2] + _PAIRS[p3] + _PAIRS[p4] + _PAIRS[p5])
        pieces.append("".join(out))
    if full < len(data):
        value = int.from_bytes(data[full:], "big")
        digits = []
        for _ in range(_CHARS_FOR[len(data) - full]):
            value, digit = divmod(value, 62)
            digits.append(_ALPHABET[digit])
        pieces.append("".join(reversed(digits)))
    return "".join(pieces)


def yace62_decode(text: str) -> bytes:
    """Reverse :func:`yace62_encode`; raise DecodingError for invalid input."""
    out = bytearray()
    digit_of = _DIGIT
    for start in range(0, len(text), 11):
        group = text[start : start + 11]
        size = _BYTES_FOR.get(len(group))
        if size is None:
            raise DecodingError("the encrypted data is truncated or corrupted")
        value = 0
        try:
            for ch in group:
                value = value * 62 + digit_of[ch]
        except KeyError as exc:
            raise DecodingError(
                f"the encrypted data contains {exc.args[0]!r}, which is not a letter or digit"
            ) from None
        if value >> (8 * size):
            raise DecodingError("the encrypted data is corrupted")
        out += value.to_bytes(size, "big")
    return bytes(out)


def looks_encrypted(text: str) -> bool:
    """Return whether ``text`` has the shape of encrypted output."""
    body = text.translate(_DELETE_WHITESPACE)
    if body.startswith(LEGACY_PREFIX):
        body = body[len(LEGACY_PREFIX) :]
    groups, rest = divmod(len(body), 11)
    return (
        _DIGIT.keys() >= set(body)
        and (rest == 0 or rest in _BYTES_FOR)
        and 8 * groups + _BYTES_FOR.get(rest, 0) >= _MIN_BYTES
    )


def is_text_token(data: bytes, *, complete: bool = True) -> bool:
    """Return whether ``data`` holds YACE62 text (maybe with a BOM), not binary output.

    Binary output starts with a random salt that never starts like a byte order
    mark, and 50 or more random bytes are all letters, digits, and whitespace
    with probability below 10**-28. With ``complete=False``, ``data`` is only
    the start of the input.
    """
    encoding = bom_encoding(data)
    if encoding is None:
        return _TEXT_BYTES.issuperset(data)
    try:
        text = codecs.getincrementaldecoder(encoding)().decode(data, complete)
    except UnicodeDecodeError:
        return False
    return _TEXT_CHARS.issuperset(text.lstrip(BOM))


# --- decryption -----------------------------------------------------------------


class _Header(NamedTuple):
    prk: bytes
    version: int
    alg: "_algorithms._Algorithm"
    log2: int  # streams only


def _decrypt(
    reader: _ByteReader,
    prefix: str,
    dst: BinaryIO,
    keys: Iterable[BytesLike],
    secret: Optional[Secret],
    aad_block: bytes,
    max_age: Optional[float],
    now: Optional[float],
    *,
    legacy_limit: Optional[int],
) -> StreamInfo:
    """Decrypt any format from ``reader`` into ``dst``.

    Order: a stream (version 4) or message (version 3) whose header matches a
    candidate secret, then 0.2.x output (no header), which only decrypts with
    empty associated data.
    """
    legacy_allowed = len(aad_block) == 8
    if prefix:  # "yace2_": only 0.2.0 output starts like this
        if not legacy_allowed:
            raise DecryptionError(_CANNOT_OPEN)
        whole = reader.read_all(limit=legacy_limit)
        data, is_text = _open_legacy_frame(prefix, whole, _candidates(whole[:SALT_SIZE], keys, secret), max_age, now)
        _write_all(dst, data)
        return StreamInfo(len(data), is_text)

    head = reader.read(_STREAM_HEADER_SIZE)
    if len(head) < _STREAM_HEADER_SIZE:
        raise DecodingError("the encrypted data is truncated or corrupted")
    candidates = _candidates(head[:SALT_SIZE], keys, secret)
    headers: List[_Header] = []
    unavailable: List[DecryptionError] = []
    for candidate in candidates:
        header = _read_header(_extract(head[:SALT_SIZE], candidate), head)
        if header is None:
            continue
        if not header.alg.available:
            unavailable.append(_algorithms.unavailable_error(header.alg))
            continue
        headers.append(header)

    streams = [h for h in headers if h.version == VERSION_STREAM]
    if streams:
        info = _open_chunks(reader, head[:SALT_SIZE], streams, dst, aad_block, max_age, now)
        if info is not None:
            return info
    raw: Optional[bytes] = None
    messages = [h for h in headers if h.version == VERSION_MESSAGE]
    if messages:
        raw = head + reader.read_all()
        frame = _open_message(raw, messages, aad_block)
        if frame is not None:
            data, is_text = _parse_frame(frame, max_age, now)
            _write_all(dst, data)
            return StreamInfo(len(data), is_text)
    if legacy_allowed:
        if raw is None:
            raw = head + reader.read_all(limit=legacy_limit)
        if len(raw) >= SALT_SIZE + 18 + _LEGACY_TAG_SIZE:
            data, is_text = _open_legacy_frame("", raw, candidates, max_age, now)
            _write_all(dst, data)
            return StreamInfo(len(data), is_text)
    if unavailable:
        raise unavailable[0]
    raise DecryptionError(_CANNOT_OPEN)


def _read_header(prk: bytes, head: bytes) -> Optional[_Header]:
    """The version, algorithm, and chunk size hidden in ``head``, if ``prk`` is right."""
    mask = _mask(prk)
    version = head[SALT_SIZE] ^ mask[0]
    if version == VERSION_MESSAGE:
        fields = _xor(head[SALT_SIZE:_MESSAGE_HEADER_SIZE], mask)
        log2 = 0
    elif version == VERSION_STREAM:
        fields = _xor(head[SALT_SIZE:_STREAM_HEADER_SIZE], mask)
        log2 = fields[2]
        if not _MIN_CHUNK_LOG2 <= log2 <= _MAX_CHUNK_LOG2:
            return None
    else:
        return None
    if fields[-len(_CHECK) :] != _CHECK:
        return None
    alg = _algorithms.by_id(fields[1])
    return None if alg is None else _Header(prk, version, alg, log2)


def _open_message(raw: bytes, messages: List[_Header], aad_block: bytes) -> Optional[bytes]:
    for header in messages:
        ad = raw[:SALT_SIZE] + bytes([VERSION_MESSAGE, header.alg.id]) + aad_block
        frame = header.alg.cipher(header.prk, VERSION_MESSAGE, ad).open(b"", raw[_MESSAGE_HEADER_SIZE:])
        if frame is not None:
            return frame
    return None


def _parse_frame(frame: bytes, max_age: Optional[float], now: Optional[float]) -> Tuple[bytes, bool]:
    if len(frame) < _FRAME.size:
        raise DecryptionError("the encrypted contents are malformed")
    kind, created, length = _FRAME.unpack_from(frame)
    if kind not in (_KIND_BYTES, _KIND_TEXT) or _FRAME.size + length > len(frame):
        raise DecryptionError("the encrypted contents are malformed")
    _check_age(created, max_age, now)
    return frame[_FRAME.size : _FRAME.size + length], kind == _KIND_TEXT


def _open_legacy_frame(
    prefix: str, raw: bytes, candidates: List[bytes], max_age: Optional[float], now: Optional[float]
) -> Tuple[bytes, bool]:
    """Open output of 0.2.0 or 0.2.1: ``salt || ciphertext || HMAC tag`` (no header)."""
    if len(raw) < SALT_SIZE + 18 + _LEGACY_TAG_SIZE:
        raise DecodingError("the encrypted data is truncated or corrupted")
    salt, ciphertext, tag = raw[:SALT_SIZE], raw[SALT_SIZE:-_LEGACY_TAG_SIZE], raw[-_LEGACY_TAG_SIZE:]
    for candidate in candidates:
        prk = _extract(salt, candidate)
        expected = hmac.digest(
            hkdf_expand(prk, _LEGACY_INFO_AUTHENTICATE), prefix.encode("ascii") + salt + ciphertext, "sha256"
        )
        if hmac.compare_digest(tag, expected):
            frame = _algorithms.xor_keystream(hkdf_expand(prk, _LEGACY_INFO_ENCRYPT), ciphertext)
            return _parse_frame(frame, max_age, now)
    raise DecryptionError(_CANNOT_OPEN)


def _open_chunks(
    reader: _ByteReader,
    salt: bytes,
    streams: List[_Header],
    dst: BinaryIO,
    aad_block: bytes,
    max_age: Optional[float],
    now: Optional[float],
) -> Optional[StreamInfo]:
    """Decrypt stream chunks into ``dst``; ``None`` if no candidate opens chunk 0."""
    for header in streams:
        cipher = header.alg.cipher(
            header.prk, VERSION_STREAM, salt + bytes([VERSION_STREAM, header.alg.id, header.log2]) + aad_block
        )
        size = (1 << header.log2) + header.alg.tag_size
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
        data = _chunk_data(plaintext, last, 1 << header.log2)
        if index == 0:
            # Encoders put the 9 metadata bytes at the start of chunk 0.
            if len(data) < _STREAM_META.size:
                raise DecryptionError("the encrypted contents are malformed")
            kind, created = _STREAM_META.unpack_from(data)
            if kind not in (_KIND_BYTES, _KIND_TEXT):
                raise DecryptionError("the encrypted contents are malformed")
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
        raise DecryptionError("the encrypted contents are malformed")
    (count,) = _COUNT.unpack_from(plaintext)
    if count > len(plaintext) - _COUNT.size:
        raise DecryptionError("the encrypted contents are malformed")
    return plaintext[_COUNT.size : _COUNT.size + count]


def _chunk_suffix(index: int, last: bool) -> bytes:
    return index.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


def _candidates(salt: bytes, keys: Iterable[BytesLike], secret: Optional[Secret]) -> List[bytes]:
    if secret is not None:
        try:
            return [_secret(salt, secret=secret)]
        except EncodingError as exc:  # e.g. an empty secret token
            raise DecryptionError(str(exc)) from None
    candidates = [check_key(k) for k in keys]
    if not candidates:
        raise DecryptionError("no keys to try; pass the secret token if one was used")
    return candidates


# --- input and output -------------------------------------------------------------


def _read_piece(src: BinaryIO, size: int) -> bytes:
    piece = src.read(size)
    if piece is None:
        raise OSError("the input would block; non-blocking streams are not supported")
    if not isinstance(piece, (bytes, bytearray)):
        raise TypeError("read the input in binary mode (open(path, 'rb'))")
    return piece


def _read_up_to(src: BinaryIO, size: int) -> bytes:
    """Read ``size`` bytes, or fewer at the end of ``src`` (pipes return short reads)."""
    out = bytearray()
    while len(out) < size:
        piece = _read_piece(src, size - len(out))
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


class _Utf8Checked:
    """Passes reads through, raising EncodingError unless the data is valid UTF-8."""

    def __init__(self, src: BinaryIO) -> None:
        self._src = src
        self._decoder = codecs.getincrementaldecoder("utf-8")()

    def read(self, size: int) -> bytes:
        piece = _read_piece(self._src, size)
        try:
            self._decoder.decode(piece, not piece)
        except UnicodeDecodeError:
            raise EncodingError("the data is not valid UTF-8 text; use text=False for bytes") from None
        return piece


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

    def read_all(self, limit: Optional[int] = None) -> bytes:
        out = bytearray(self._back)
        self._back.clear()
        while True:
            piece = self._read(_IO_SIZE)
            if not piece:
                return bytes(out)
            out += piece
            if limit is not None and len(out) > limit:
                raise DecryptionError(_CANNOT_OPEN)


class _Yace62Source:
    """Decodes YACE62 text (any encoding with a BOM; ASCII whitespace ignored) as it is read."""

    def __init__(self, src: BinaryIO, first: bytes) -> None:
        self._src = src
        self._decoder = codecs.getincrementaldecoder(bom_encoding(first) or "utf-8")()
        self._chars = ""
        self._bytes = bytearray()
        self._done = False
        self._feed(first)

    def take_prefix(self) -> str:
        """Remove and return a leading ``yace2_`` (0.2.0 output), if there is one."""
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
        if not self._done:
            raw = _read_piece(self._src, _IO_SIZE)
            self._feed(raw, final=not raw)

    def _feed(self, raw: bytes, final: bool = False) -> None:
        try:
            text = self._decoder.decode(raw, final)
        except UnicodeDecodeError:
            raise DecodingError("the encrypted data is not valid text") from None
        self._chars += text.translate(_DELETE_WHITESPACE)
        self._done = final


def _token_reader(src: BinaryIO) -> Tuple[_ByteReader, str]:
    """Wrap ``src`` so it yields binary output bytes, decoding YACE62 text on the fly.

    Returns the reader and the 0.2.0 prefix (if any).
    """
    first = _read_up_to(src, 64)
    if not first:
        raise DecodingError("the encrypted data is empty")
    if not is_text_token(first, complete=len(first) < 64):
        reader = _ByteReader(lambda size: _read_piece(src, size))
        reader.unread(first)
        return reader, ""
    source = _Yace62Source(src, first)
    prefix = source.take_prefix()
    return _ByteReader(source.read), prefix


def _token_bytes(token: TokenLike) -> Tuple[str, bytes]:
    """The 0.2.0 prefix (if any) and the binary form of ``token``."""
    if isinstance(token, (bytes, bytearray, memoryview)):
        data = bytes(token)
        if not is_text_token(data):
            if len(data) < _MIN_BYTES:
                raise DecodingError("the encrypted data is truncated or corrupted")
            return "", data
    body = token_text(token).translate(_DELETE_WHITESPACE)  # wrapped lines and CRLF are fine
    if not body:
        raise DecodingError("the encrypted data is empty")
    prefix = LEGACY_PREFIX if body.startswith(LEGACY_PREFIX) else ""
    body = body[len(prefix) :]
    if not _DIGIT.keys() >= set(body):
        raise DecodingError("this is not encrypted output; use decode() for encoded tokens")
    raw = yace62_decode(body)
    if len(raw) < _MIN_BYTES:
        raise DecodingError("the encrypted data is truncated or corrupted")
    return prefix, raw


# --- small helpers ------------------------------------------------------------------


def _wants_text(output: object) -> bool:
    if output not in ("text", "bytes"):
        raise EncodingError(f"output must be 'text' or 'bytes', not {output!r}")
    return output == "text"


def _plain_bytes(data: BytesLike, text: bool) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"data must be bytes-like, not {type(data).__name__}")
    data = bytes(data)  # a memoryview of other item sizes becomes its bytes
    if text:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise EncodingError("the data is not valid UTF-8 text; use text=False for bytes") from None
    return data


def _chunk_log2(chunk_size: object) -> int:
    if (
        not isinstance(chunk_size, int)
        or isinstance(chunk_size, bool)
        or chunk_size <= 0
        or chunk_size & (chunk_size - 1)
        or not _MIN_CHUNK_LOG2 <= chunk_size.bit_length() - 1 <= _MAX_CHUNK_LOG2
    ):
        raise EncodingError(
            f"chunk_size must be a power of two from {1 << _MIN_CHUNK_LOG2} "
            f"to {1 << _MAX_CHUNK_LOG2}, not {chunk_size!r}"
        )
    return chunk_size.bit_length() - 1


def _creation_time(now: Optional[float]) -> int:
    moment = time.time() if now is None else now
    if isinstance(moment, bool) or not isinstance(moment, (int, float)):
        raise TypeError("now must be a number of seconds")
    if not math.isfinite(moment) or not 0 <= moment < 2**64:
        raise EncodingError("now must be a finite, non-negative Unix time")
    return int(moment)


def _check_max_age(max_age: Optional[float]) -> None:
    if max_age is None:
        return
    if isinstance(max_age, bool) or not isinstance(max_age, (int, float)):
        raise TypeError("max_age must be a number of seconds")
    if math.isnan(max_age):
        raise DecodingError("max_age must be a number of seconds, not NaN")


def _check_age(created: int, max_age: Optional[float], now: Optional[float]) -> None:
    if max_age is None:
        return
    moment = time.time() if now is None else now
    if not math.isfinite(moment):
        raise DecodingError("now must be a finite Unix time")
    age = moment - created
    if age > max_age:
        raise TokenExpiredError(f"the data was encrypted {int(age)} seconds ago (limit {max_age})")


def _aad_block(aad: Aad) -> bytes:
    """Length-prefixed associated data, so its boundary is unambiguous."""
    if isinstance(aad, str):
        try:
            data = aad.encode("utf-8")
        except UnicodeEncodeError:
            raise EncodingError("aad contains characters that are not valid text") from None
    elif isinstance(aad, (bytes, bytearray, memoryview)):
        data = bytes(aad)
    else:
        raise TypeError(f"aad must be bytes or str, not {type(aad).__name__}")
    if len(data) > MAX_MESSAGE_SIZE // 2:
        raise EncodingError("aad is too large (over 1 GiB)")
    return len(data).to_bytes(8, "big") + data


def _extract(salt: bytes, secret: bytes) -> bytes:
    return hmac.digest(salt, secret, "sha256")  # HKDF-Extract


def _mask(prk: bytes) -> bytes:
    return hkdf_expand(prk, _MASK_INFO, 7)


def _xor(data: bytes, mask: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, mask))


def _new_salt() -> bytes:
    """A random salt that does not start like a byte order mark (see is_text_token)."""
    while True:
        salt = secrets.token_bytes(SALT_SIZE)
        if not salt.startswith(_BOMS):
            return salt


def _check_salt(salt: bytes) -> bytes:
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_SIZE:
        raise EncodingError(f"salt must be {SALT_SIZE} bytes")
    return bytes(salt)


def _secret(salt: bytes, *, key: Optional[bytes] = None, secret: Optional[Secret] = None) -> bytes:
    if (key is None) == (secret is None):
        raise TypeError("pass exactly one of key and secret")
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

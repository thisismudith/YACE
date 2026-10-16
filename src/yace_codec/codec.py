"""The YACE encoding pipeline.

Encoding ``text`` with family ``name``, code length ``L`` and ``I`` iterations:

1. Layer ``k`` (``k = 1..I``) replaces every character with its code from table
   ``name-L:k``. Each space gets one of several space codes at random. Codes
   consist of letters and digits, so every layer's output is valid input for
   the next layer.
2. ``ceil(chunks / 4)`` bin (noise) codes from the last table are inserted at
   random chunk positions, where a chunk is one ``L``-character code.
3. Chunk ``x - 1`` is swapped with chunk ``n - x`` for ``x = L, 2L, 3L, ...``.
   No two swaps overlap, so applying the step twice restores the order.
4. The token is the header ``name-L:I``, a newline, and the chunks.

Decoding undoes the steps in reverse order with the same tables. This is the
format of the original YACE scripts, so their tokens and ``encodings.json``
files keep working.

:meth:`Codec.encrypt` and :meth:`Codec.decrypt` make encrypted tokens instead;
see :mod:`yace_codec.sealed`.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import os
import secrets
from random import Random
from typing import (
    Any,
    BinaryIO,
    Dict,
    Iterable,
    Iterator,
    List,
    Literal,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Union,
    overload,
)

from . import _algorithms, sealed
from ._files import Access, atomic_output
from ._text import TokenLike, token_text
from .errors import DecodingError, DecryptionError, EncodingError, UnsupportedCharacterError
from .keybackends import BACKENDS, KeyBackend, open_key_backend
from .keystore import KeyStore
from .tables import (
    CODE_ALPHABET,
    MAX_LENGTH,
    MIN_LENGTH,
    SPACE_KEY,
    SUPPORTED_CHARACTERS,
    Table,
    parse_table_name,
    table_name,
    validate_family,
)

__all__ = [
    "DEFAULT_FAMILY",
    "DEFAULT_ITERATIONS",
    "DEFAULT_KEY",
    "DEFAULT_LENGTH",
    "MAX_ENCODED_CHARS",
    "MAX_ITERATIONS",
    "Codec",
    "Header",
    "decode",
    "decode_bytes",
    "decrypt",
    "decrypt_stream",
    "encode",
    "encode_bytes",
    "encrypt",
    "encrypt_stream",
    "generate_key",
    "parse_header",
]

#: Family used when no name is given.
DEFAULT_FAMILY = "default"
#: Secret key used by :meth:`Codec.encrypt` when no key or password is given.
DEFAULT_KEY = "default"
#: Default code length (``hash_length`` in the original scripts).
DEFAULT_LENGTH = 2
#: Default number of encoding layers (``final_hash_iteration`` in the original scripts).
DEFAULT_ITERATIONS = 3
#: Upper limit for ``iterations``.
MAX_ITERATIONS = 32
#: Encoding is refused when ``len(text) * length ** iterations`` exceeds this.
#: Encoding and decoding need roughly 25-40 bytes of memory per token character.
MAX_ENCODED_CHARS = 2**25

_CODE_CHARS = frozenset(CODE_ALPHABET)
# The longest token body: every character encoded, plus 25% bins (rounded up).
_MAX_TOKEN_CHARS = MAX_ENCODED_CHARS + (MAX_ENCODED_CHARS // MIN_LENGTH // 4 + 1) * MAX_LENGTH
_SYSTEM_RANDOM = secrets.SystemRandom()

KeyStoreLike = Union[KeyStore, str, "os.PathLike[str]", None]
PathLike = Union[str, "os.PathLike[str]"]
KeyBackendLike = Union[KeyBackend, str, None]
BytesLike = Union[bytes, bytearray, memoryview]


class Header(NamedTuple):
    """The first line of a token: ``<family>-<length>:<iterations>``."""

    family: str
    length: int
    iterations: int

    @property
    def table_names(self) -> Tuple[str, ...]:
        """Names of the tables needed to decode the token, innermost first."""
        return tuple(table_name(self.family, self.length, k) for k in range(1, self.iterations + 1))

    def __str__(self) -> str:
        return table_name(self.family, self.length, self.iterations)


class Codec:
    """Encode and decode with the tables of one key store.

    ``keystore`` may be a :class:`~yace_codec.keystore.KeyStore`, a path to a
    key store file, or ``None`` for the default key store
    (:func:`~yace_codec.keystore.default_keystore_path`).

    ``key_backend`` keeps the secret keys for :meth:`encrypt` elsewhere: a
    :class:`~yace_codec.keybackends.KeyBackend`, or the name ``"json"`` (the
    key store, the default), ``"dpapi"``, or ``"keyring"``.

    ``rng`` replaces the operating system's random source for new tables and
    for the per-token randomness. Pass a seeded :class:`random.Random` only to
    get reproducible output in tests.
    """

    def __init__(
        self,
        keystore: KeyStoreLike = None,
        *,
        rng: Optional[Random] = None,
        key_backend: KeyBackendLike = None,
    ) -> None:
        self.keystore = _as_keystore(keystore)
        #: Where secret keys for encrypt()/decrypt() live (default: the key store).
        self.key_backend: KeyBackend = _as_key_backend(key_backend, self.keystore)
        self._rng = rng

    def __repr__(self) -> str:
        if self.key_backend is self.keystore:
            return f"Codec({self.keystore!r})"
        return f"Codec({self.keystore!r}, key_backend={self.key_backend!r})"

    def encode(
        self,
        text: str,
        name: str = DEFAULT_FAMILY,
        *,
        length: int = DEFAULT_LENGTH,
        iterations: int = DEFAULT_ITERATIONS,
    ) -> str:
        """Encode ``text`` with the table family ``name`` and return the token.

        Missing tables ``name-length:1`` to ``name-length:iterations`` are
        generated and saved to the key store; existing ones are reused.

        Raises :class:`~yace_codec.errors.UnsupportedCharacterError` if ``text``
        contains characters the table cannot encode (new tables cover
        :data:`string.printable`; use :meth:`encode_bytes` for anything else),
        :class:`~yace_codec.errors.InvalidNameError` for an invalid ``name``, and
        :class:`~yace_codec.errors.EncodingError` for invalid settings.
        """
        if not isinstance(text, str):
            raise TypeError(
                f"text must be str, not {type(text).__name__}; use encode_bytes() for bytes"
            )
        validate_family(name)
        _check_settings(length, iterations)
        if len(text) * length**iterations > MAX_ENCODED_CHARS:
            raise EncodingError(
                f"the token would exceed {MAX_ENCODED_CHARS} data characters "
                f"({len(text)} characters x {length}**{iterations}); "
                "lower the length or the number of iterations"
            )
        used = frozenset(text)
        first = table_name(name, length, 1)
        existing = self.keystore.find(first)
        # Check before generating tables, so invalid input leaves the store unchanged.
        _check_characters(used, existing.characters if existing else SUPPORTED_CHARACTERS, first)
        tables = self.keystore.ensure_tables(name, length, iterations, rng=self._rng)
        _check_characters(used, tables[0].characters, first)
        last = tables[-1]
        if last.bin_codes and not last.usable_bin_codes:
            # Only possible with hand-made or legacy tables.
            raise EncodingError(
                f"every bin code of table {last.name!r} is also a character or space code, "
                "so it cannot produce an unambiguous token"
            )

        rng = self._rng or _SYSTEM_RANDOM
        try:
            data = text
            for table in tables:
                data = _substitute(data, table, rng)
            noisy = _insert_bins(data.encode("ascii"), length, last.usable_bin_codes, rng)
            body = _swap_chunks(noisy, length).decode("ascii")
        except MemoryError:
            raise EncodingError(
                "not enough memory for this token; lower the length or the number of iterations"
            ) from None
        return f"{table_name(name, length, iterations)}\n{body}"

    def decode(self, token: TokenLike) -> str:
        """Decode a token produced by :meth:`encode` (or by the original scripts).

        Whitespace inside the token is ignored, so wrapped or CRLF tokens work.

        Raises :class:`~yace_codec.errors.TableNotFoundError` if the key store
        lacks a required table and :class:`~yace_codec.errors.DecodingError` if
        the token is malformed or was encoded with different tables.
        """
        header, body = _split_token(token)
        tables = [self.keystore.get(name) for name in header.table_names]
        length = header.length
        data = body
        for layer in range(header.iterations, 0, -1):
            if len(data) % length:
                raise DecodingError(
                    f"layer {layer} has {len(data)} characters, which is not a multiple of "
                    f"the code length {length}; the token is truncated or corrupted"
                )
            outermost = layer == header.iterations
            if outermost:
                data = _swap_chunks(data.encode("ascii"), length).decode("ascii")
            table = tables[layer - 1]
            mapping = table.reverse_map(plaintext=layer == 1, outermost=outermost)
            chunks = [data[i : i + length] for i in range(0, len(data), length)]
            data = _restore(chunks, mapping, table, outermost=outermost)
        return data

    def encode_bytes(
        self,
        data: Union[bytes, bytearray, memoryview],
        name: str = DEFAULT_FAMILY,
        *,
        length: int = DEFAULT_LENGTH,
        iterations: int = DEFAULT_ITERATIONS,
    ) -> str:
        """Encode arbitrary bytes (base64 first, then :meth:`encode`).

        Use this for binary files and for text outside :data:`string.printable`,
        e.g. ``codec.encode_bytes("café".encode("utf-8"))``. Decode the token
        with :meth:`decode_bytes`.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f"data must be bytes-like, not {type(data).__name__}")
        text = base64.b64encode(bytes(data)).decode("ascii")
        return self.encode(text, name, length=length, iterations=iterations)

    def decode_bytes(self, token: TokenLike) -> bytes:
        """Decode a token produced by :meth:`encode_bytes`."""
        text = self.decode(token)
        try:
            return base64.b64decode(text.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError) as exc:
            raise DecodingError(
                "the decoded text is not base64; was the token made with encode_bytes()?"
            ) from exc

    @overload
    def encrypt(
        self,
        data: Union[str, BytesLike],
        key: Union[str, BytesLike, None] = None,
        *,
        token: Optional[sealed.Secret] = None,
        password: Optional[sealed.Secret] = None,
        aad: sealed.Aad = b"",
        algorithm: Optional[str] = None,
        output: Literal["text"] = "text",
    ) -> str: ...

    @overload
    def encrypt(
        self,
        data: Union[str, BytesLike],
        key: Union[str, BytesLike, None] = None,
        *,
        token: Optional[sealed.Secret] = None,
        password: Optional[sealed.Secret] = None,
        aad: sealed.Aad = b"",
        algorithm: Optional[str] = None,
        output: Literal["bytes"],
    ) -> bytes: ...

    @overload
    def encrypt(
        self,
        data: Union[str, BytesLike],
        key: Union[str, BytesLike, None] = None,
        *,
        token: Optional[sealed.Secret] = None,
        password: Optional[sealed.Secret] = None,
        aad: sealed.Aad = b"",
        algorithm: Optional[str] = None,
        output: sealed.Output,
    ) -> Union[str, bytes]: ...

    def encrypt(
        self,
        data: Union[str, BytesLike],
        key: Union[str, BytesLike, None] = None,
        *,
        token: Optional[sealed.Secret] = None,
        password: Optional[sealed.Secret] = None,
        aad: sealed.Aad = b"",
        algorithm: Optional[str] = None,
        output: sealed.Output = "text",
    ) -> Union[str, bytes]:
        """Encrypt ``data`` (any text or bytes).

        Choose the secret with one of:

        - ``token``: your own secret, any non-empty text or bytes (stretched with
          scrypt). Nothing is generated or stored. ``password`` is another name
          for it.
        - ``key`` as 32 bytes: a raw key (see :func:`~yace_codec.generate_key`),
          used as is. No key backend is used.
        - ``key`` as a name (default ``"default"``): a stored key from the key
          backend, generated and saved on first use. Key names are 1-64 ASCII
          letters or underscores.

        ``aad`` (associated data, bytes or text) is authenticated but not
        stored; :meth:`decrypt` needs the same value. ``algorithm`` is one of
        :func:`~yace_codec.algorithms` (default
        :data:`~yace_codec.DEFAULT_ALGORITHM`, ``"aes-256-gcm"``).
        ``output="text"`` (the default) returns letters and digits;
        ``output="bytes"`` returns raw bytes, with no expansion. The result does
        not reveal the key, the algorithm, the exact length, or anything else
        about the data. Every argument is checked before a key is created.
        """
        raw, is_text = _plaintext(data)
        _check_encryption_options(aad, algorithm, output)
        secrets_ = self._encryption_secret(key, token, password)
        return sealed.seal(raw, text=is_text, aad=aad, algorithm=algorithm, output=output, **secrets_)

    def decrypt(
        self,
        encrypted: TokenLike,
        *,
        token: Optional[sealed.Secret] = None,
        password: Optional[sealed.Secret] = None,
        keys: Optional[Iterable[BytesLike]] = None,
        aad: sealed.Aad = b"",
        max_age: Optional[float] = None,
    ) -> Union[str, bytes]:
        """Decrypt the output of :meth:`encrypt` or :meth:`encrypt_stream`.

        Returns ``str`` for text and ``bytes`` for bytes, as they were encrypted.
        Pass the same ``token`` (your secret) and ``aad`` that encrypted it.
        With ``keys`` (raw 32-byte keys), only those keys are tried. Otherwise
        every current and retired key of the key backend is tried. With
        ``max_age`` (seconds), older output raises
        :class:`~yace_codec.errors.TokenExpiredError`.

        Every failure raises :class:`~yace_codec.errors.DecodingError`: a wrong
        secret or ``aad``, or changed data, raises its subclass
        :class:`~yace_codec.errors.DecryptionError`.
        """
        data, is_text = sealed.unseal(
            encrypted, aad=aad, max_age=max_age, **self._decryption_secrets(token, password, keys)
        )
        if not is_text:
            return data
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise DecryptionError("the decrypted text is not valid UTF-8") from None

    def encrypt_stream(
        self,
        src: Union[BinaryIO, PathLike],
        dst: Union[BinaryIO, PathLike],
        key: Union[str, BytesLike, None] = None,
        *,
        token: Optional[sealed.Secret] = None,
        password: Optional[sealed.Secret] = None,
        aad: sealed.Aad = b"",
        algorithm: Optional[str] = None,
        output: sealed.Output = "text",
        text: bool = False,
        chunk_size: int = sealed.DEFAULT_CHUNK_SIZE,
    ) -> int:
        """Encrypt a file or binary stream in constant memory; return the bytes written.

        ``src`` and ``dst`` are binary file objects or paths. A ``dst`` path is
        written to a temporary file first and only replaces ``dst`` when
        encryption succeeds. The secret, ``aad``, ``algorithm``, and ``output``
        work as in :meth:`encrypt` (use ``output="bytes"`` for large files).
        ``text=True`` requires UTF-8 data and makes :meth:`decrypt` return ``str``.
        """
        _check_encryption_options(aad, algorithm, output, chunk_size)
        secrets_ = self._encryption_secret(key, token, password)
        # The output is entered first and replaced last, after the input is closed,
        # so src and dst may be the same path (Windows cannot replace an open file).
        with _written(dst, "normal") as writer, _opened(src) as reader:
            return sealed.seal_stream(
                reader, writer, text=text, aad=aad, algorithm=algorithm, output=output,
                chunk_size=chunk_size, **secrets_,
            )

    def decrypt_stream(
        self,
        src: Union[BinaryIO, PathLike],
        dst: Union[BinaryIO, PathLike],
        *,
        token: Optional[sealed.Secret] = None,
        password: Optional[sealed.Secret] = None,
        keys: Optional[Iterable[BytesLike]] = None,
        aad: sealed.Aad = b"",
        max_age: Optional[float] = None,
    ) -> sealed.StreamInfo:
        """Decrypt a file or binary stream (any format, text or bytes) into ``dst``.

        Streams are decrypted in constant memory. Every chunk is verified before
        it is written, but a truncated or changed stream is only detected when
        the damaged chunk is reached: if this raises, discard what was written
        to a file object. A ``dst`` path is written to a temporary file that only
        replaces ``dst`` (readable only by you, if it is new) on success.
        """
        secrets_ = self._decryption_secrets(token, password, keys)
        with _written(dst, "private") as writer, _opened(src) as reader:
            return sealed.unseal_stream(reader, writer, aad=aad, max_age=max_age, **secrets_)

    def _encryption_secret(
        self,
        key: Union[str, BytesLike, None],
        token: Optional[sealed.Secret],
        password: Optional[sealed.Secret],
    ) -> Dict[str, Any]:
        secret = _choose_secret(token, password)
        if key is not None and secret is not None:
            raise TypeError("pass either key or token, not both")
        if secret is not None:
            return {"secret": secret}
        if isinstance(key, (bytes, bytearray, memoryview)):
            return {"key": sealed.check_key(key)}
        if key is not None and not isinstance(key, str):
            raise TypeError(f"key must be a key name (str) or 32 bytes, not {type(key).__name__}")
        return {"key": self.key_backend.ensure_key(DEFAULT_KEY if key is None else key, rng=self._rng)}

    def _decryption_secrets(
        self,
        token: Optional[sealed.Secret],
        password: Optional[sealed.Secret],
        keys: Optional[Iterable[BytesLike]],
    ) -> Dict[str, Any]:
        secret = _choose_secret(token, password)
        if secret is not None:
            if keys is not None:
                raise TypeError("pass either keys or token, not both")
            return {"secret": secret}
        if keys is not None:
            if isinstance(keys, (str, bytes, bytearray, memoryview)):
                raise TypeError("keys must be a list of 32-byte keys, not a single value")
            return {"keys": [sealed.check_key(k) for k in keys]}
        return {"keys": self.key_backend.decryption_keys()}


@overload
def encrypt(
    data: Union[str, BytesLike],
    key: Union[str, BytesLike, None] = None,
    *,
    token: Optional[sealed.Secret] = None,
    password: Optional[sealed.Secret] = None,
    keystore: KeyStoreLike = None,
    key_backend: KeyBackendLike = None,
    aad: sealed.Aad = b"",
    algorithm: Optional[str] = None,
    output: Literal["text"] = "text",
) -> str: ...


@overload
def encrypt(
    data: Union[str, BytesLike],
    key: Union[str, BytesLike, None] = None,
    *,
    token: Optional[sealed.Secret] = None,
    password: Optional[sealed.Secret] = None,
    keystore: KeyStoreLike = None,
    key_backend: KeyBackendLike = None,
    aad: sealed.Aad = b"",
    algorithm: Optional[str] = None,
    output: Literal["bytes"],
) -> bytes: ...


@overload
def encrypt(
    data: Union[str, BytesLike],
    key: Union[str, BytesLike, None] = None,
    *,
    token: Optional[sealed.Secret] = None,
    password: Optional[sealed.Secret] = None,
    keystore: KeyStoreLike = None,
    key_backend: KeyBackendLike = None,
    aad: sealed.Aad = b"",
    algorithm: Optional[str] = None,
    output: sealed.Output,
) -> Union[str, bytes]: ...


def encrypt(
    data: Union[str, BytesLike],
    key: Union[str, BytesLike, None] = None,
    *,
    token: Optional[sealed.Secret] = None,
    password: Optional[sealed.Secret] = None,
    keystore: KeyStoreLike = None,
    key_backend: KeyBackendLike = None,
    aad: sealed.Aad = b"",
    algorithm: Optional[str] = None,
    output: sealed.Output = "text",
) -> Union[str, bytes]:
    """Encrypt ``data``; shortcut for ``Codec(keystore).encrypt(...)``.

    With a ``token`` (your own secret) or a raw 32-byte ``key``, no key store
    or key backend is used at all.
    """
    return _codec_for(keystore, key_backend, _key_free(key, token, password)).encrypt(
        data, key, token=token, password=password, aad=aad, algorithm=algorithm, output=output
    )


def decrypt(
    encrypted: TokenLike,
    *,
    token: Optional[sealed.Secret] = None,
    password: Optional[sealed.Secret] = None,
    keys: Optional[Iterable[BytesLike]] = None,
    aad: sealed.Aad = b"",
    max_age: Optional[float] = None,
    keystore: KeyStoreLike = None,
    key_backend: KeyBackendLike = None,
) -> Union[str, bytes]:
    """Decrypt; shortcut for ``Codec(keystore).decrypt(...)``.

    With a ``token`` or ``keys``, no key store or key backend is used at all.
    """
    key_free = token is not None or password is not None or keys is not None
    return _codec_for(keystore, key_backend, key_free).decrypt(
        encrypted, token=token, password=password, keys=keys, aad=aad, max_age=max_age
    )


def encrypt_stream(
    src: Union[BinaryIO, PathLike],
    dst: Union[BinaryIO, PathLike],
    key: Union[str, BytesLike, None] = None,
    *,
    token: Optional[sealed.Secret] = None,
    password: Optional[sealed.Secret] = None,
    keystore: KeyStoreLike = None,
    key_backend: KeyBackendLike = None,
    aad: sealed.Aad = b"",
    algorithm: Optional[str] = None,
    output: sealed.Output = "text",
    text: bool = False,
    chunk_size: int = sealed.DEFAULT_CHUNK_SIZE,
) -> int:
    """Encrypt a stream; shortcut for ``Codec(keystore).encrypt_stream(...)``."""
    return _codec_for(keystore, key_backend, _key_free(key, token, password)).encrypt_stream(
        src, dst, key, token=token, password=password, aad=aad, algorithm=algorithm,
        output=output, text=text, chunk_size=chunk_size,
    )


def decrypt_stream(
    src: Union[BinaryIO, PathLike],
    dst: Union[BinaryIO, PathLike],
    *,
    token: Optional[sealed.Secret] = None,
    password: Optional[sealed.Secret] = None,
    keys: Optional[Iterable[BytesLike]] = None,
    aad: sealed.Aad = b"",
    max_age: Optional[float] = None,
    keystore: KeyStoreLike = None,
    key_backend: KeyBackendLike = None,
) -> sealed.StreamInfo:
    """Decrypt a stream; shortcut for ``Codec(keystore).decrypt_stream(...)``."""
    key_free = token is not None or password is not None or keys is not None
    return _codec_for(keystore, key_backend, key_free).decrypt_stream(
        src, dst, token=token, password=password, keys=keys, aad=aad, max_age=max_age
    )


def generate_key() -> bytes:
    """Return a new random 32-byte key for ``encrypt(data, key=...)``."""
    return secrets.token_bytes(sealed.KEY_SIZE)


def _codec_for(keystore: KeyStoreLike, key_backend: KeyBackendLike, key_free: bool) -> Codec:
    """A Codec for the module functions; key-free calls never open the default store."""
    if key_free and keystore is None and key_backend is None:
        return Codec(KeyStore.in_memory())
    return Codec(keystore, key_backend=key_backend)


def _key_free(
    key: Union[str, BytesLike, None], token: Optional[sealed.Secret], password: Optional[sealed.Secret]
) -> bool:
    if isinstance(key, (bytes, bytearray, memoryview)):
        return True
    return key is None and (token is not None or password is not None)


def _check_encryption_options(
    aad: sealed.Aad, algorithm: Optional[str], output: object, chunk_size: Optional[int] = None
) -> None:
    """Raise for bad options before anything (such as a new key) is saved."""
    sealed._wants_text(output)
    _algorithms.by_name(algorithm)
    sealed._aad_block(aad)
    if chunk_size is not None:
        sealed._chunk_log2(chunk_size)


@contextlib.contextmanager
def _opened(source: Union[BinaryIO, PathLike]) -> Iterator[BinaryIO]:
    """Yield ``source`` itself, or the file at that path opened for binary reading."""
    if isinstance(source, (str, os.PathLike)):
        with open(source, "rb") as fh:
            yield fh
    else:
        yield source


@contextlib.contextmanager
def _written(target: Union[BinaryIO, PathLike], access: Access) -> Iterator[BinaryIO]:
    """Yield ``target`` itself, or a file that replaces that path only on success."""
    if isinstance(target, (str, os.PathLike)):
        with atomic_output(target, access) as fh:
            yield fh
    else:
        yield target


def _as_key_backend(key_backend: KeyBackendLike, keystore: KeyStore) -> KeyBackend:
    if key_backend is None or key_backend == "json":
        return keystore
    if isinstance(key_backend, str):
        return open_key_backend(key_backend)
    if not isinstance(key_backend, KeyBackend):
        raise TypeError(
            f"key_backend must be a KeyBackend or one of {', '.join(BACKENDS)}, "
            f"not {type(key_backend).__name__}"
        )
    return key_backend


def _plaintext(data: Union[str, BytesLike]) -> Tuple[bytes, bool]:
    if isinstance(data, str):
        try:
            return data.encode("utf-8"), True
        except UnicodeEncodeError:
            raise EncodingError("the text contains characters that are not valid Unicode") from None
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data), False
    raise TypeError(f"data must be str or bytes-like, not {type(data).__name__}")


def _choose_secret(
    token: Optional[sealed.Secret], password: Optional[sealed.Secret]
) -> Optional[sealed.Secret]:
    if token is not None and password is not None:
        raise TypeError("pass either token or password, not both (they are the same thing)")
    return token if token is not None else password


def encode(
    text: str,
    name: str = DEFAULT_FAMILY,
    *,
    length: int = DEFAULT_LENGTH,
    iterations: int = DEFAULT_ITERATIONS,
    keystore: KeyStoreLike = None,
) -> str:
    """Encode ``text``; shortcut for ``Codec(keystore).encode(...)``."""
    return Codec(keystore).encode(text, name, length=length, iterations=iterations)


def decode(token: TokenLike, *, keystore: KeyStoreLike = None) -> str:
    """Decode ``token``; shortcut for ``Codec(keystore).decode(token)``."""
    return Codec(keystore).decode(token)


def encode_bytes(
    data: Union[bytes, bytearray, memoryview],
    name: str = DEFAULT_FAMILY,
    *,
    length: int = DEFAULT_LENGTH,
    iterations: int = DEFAULT_ITERATIONS,
    keystore: KeyStoreLike = None,
) -> str:
    """Encode bytes; shortcut for ``Codec(keystore).encode_bytes(...)``."""
    return Codec(keystore).encode_bytes(data, name, length=length, iterations=iterations)


def decode_bytes(token: TokenLike, *, keystore: KeyStoreLike = None) -> bytes:
    """Decode a bytes token; shortcut for ``Codec(keystore).decode_bytes(token)``."""
    return Codec(keystore).decode_bytes(token)


def parse_header(token: TokenLike) -> Header:
    """Return the :class:`Header` of ``token`` without decoding it.

    ``parse_header(token).table_names`` lists the tables a key store needs to
    decode the token.
    """
    return _split_token(token)[0]


def _as_keystore(keystore: KeyStoreLike) -> KeyStore:
    if keystore is None:
        return KeyStore.default()
    if isinstance(keystore, KeyStore):
        return keystore
    if isinstance(keystore, (str, os.PathLike)):
        return KeyStore(keystore)
    raise TypeError(f"keystore must be a KeyStore, a path, or None, not {type(keystore).__name__}")


def _check_settings(length: object, iterations: object) -> None:
    if not _is_int(length) or not MIN_LENGTH <= length <= MAX_LENGTH:  # type: ignore[operator]
        raise EncodingError(
            f"length must be an integer from {MIN_LENGTH} to {MAX_LENGTH}, got {length!r}"
        )
    if not _is_int(iterations) or not 1 <= iterations <= MAX_ITERATIONS:  # type: ignore[operator]
        raise EncodingError(
            f"iterations must be an integer from 1 to {MAX_ITERATIONS}, got {iterations!r}"
        )


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_characters(used: Iterable[str], supported: Iterable[str], name: str) -> None:
    unsupported = sorted(set(used).difference(supported))
    if unsupported:
        shown = ", ".join(repr(ch) for ch in unsupported[:10])
        if len(unsupported) > 10:
            shown += f" and {len(unsupported) - 10} more"
        raise UnsupportedCharacterError(
            f"table {name!r} cannot encode {shown}; use encode_bytes() for "
            "arbitrary text or binary data",
            tuple(unsupported),
            name,
        )


def _substitute(text: str, table: Table, rng: Random) -> str:
    if SPACE_KEY not in text:
        return table.translate(text)
    parts = text.split(SPACE_KEY)
    spaces = rng.choices(table.usable_space_codes, k=len(parts) - 1)
    spaces.append("")
    return "".join([piece for part, space in zip(parts, spaces) for piece in (table.translate(part), space)])


def _insert_bins(data: bytes, length: int, bins: Sequence[str], rng: Random) -> bytes:
    """Insert ``ceil(chunks / 4)`` random bin codes at random chunk positions."""
    chunks = len(data) // length
    count = -(-chunks // 4)
    if not count or not bins:
        return data
    slots = sorted(rng.sample(range(chunks + count), count))
    codes = rng.choices([code.encode("ascii") for code in bins], k=count)
    # The i-th bin (in slot order) lands after slots[i] - i data chunks.
    cuts = [(slot - i) * length for i, slot in enumerate(slots)]
    segments = [data[start:cut] for start, cut in zip([0, *cuts], cuts)]
    pieces = [piece for pair in zip(segments, codes) for piece in pair]
    pieces.append(data[cuts[-1] :])
    return b"".join(pieces)


def _swap_chunks(data: bytes, length: int) -> bytes:
    """Swap chunk ``x - 1`` with chunk ``n - x`` for ``x = length, 2*length, ... < n``.

    This is the original "misordering" step. The swapped pairs never overlap,
    so the function is its own inverse.

    Chunks ``x - 1`` sit every ``length`` chunks from chunk ``length - 1``, and
    their partners ``n - x`` sit every ``length`` chunks up to chunk ``n - length``.
    Strided slices move byte ``offset`` of all those chunks at once; reversing
    one side pairs the first chunk of one group with the last of the other.
    """
    n = len(data) // length
    pairs = len(range(length, n, length))
    if not pairs:
        return bytes(data)
    out = bytearray(data)
    step = length * length
    for offset in range(length):
        first = (length - 1) * length + offset
        last = (n - pairs * length) * length + offset
        lower = slice(first, first + pairs * step, step)
        upper = slice(last, last + pairs * step, step)
        out[lower] = data[upper][::-1]
        out[upper] = data[lower][::-1]
    return bytes(out)


def _restore(
    chunks: List[str], mapping: Dict[str, Optional[str]], table: Table, *, outermost: bool
) -> str:
    """Map one layer's chunks back to characters and drop the bins.

    On the outermost layer, the number of bins must match the token length
    (see :func:`_bins_inserted`). Otherwise chunks were lost or added.
    """
    if not outermost:
        return "".join(_lookup(chunks, mapping, table))
    if any(mapping.get(code) is not None for code in table.bin_codes):
        decoded = _lookup(chunks, mapping, table)
        _drop_shared_bins(decoded, chunks, mapping, table.bin_codes)
        bins = decoded.count(None)
        text = "".join([ch for ch in decoded if ch is not None])
    else:
        fast = {code: ("" if ch is None else ch) for code, ch in mapping.items()}
        text = "".join(_lookup(chunks, fast, table))
        bins = len(chunks) - len(text)
    expected = _bins_inserted(len(chunks))
    if table.bin_codes and bins != expected:
        implied = "no valid count" if expected is None else str(expected)
        raise DecodingError(
            f"the token holds {bins} noise chunks, but its length implies {implied}; "
            "it is truncated, extended, or corrupted"
        )
    return text


def _lookup(chunks: List[str], mapping: Dict[str, Any], table: Table) -> List[Any]:
    try:
        return list(map(mapping.__getitem__, chunks))
    except KeyError:
        index = next(i for i, chunk in enumerate(chunks) if chunk not in mapping)
        raise DecodingError(
            f"{chunks[index]!r} at offset {index * table.length} is not a valid code of "
            f"table {table.name!r}; the token is corrupted or was encoded with different tables"
        ) from None


def _bins_inserted(chunks: int) -> Optional[int]:
    """Return how many bins a token of ``chunks`` chunks holds, or ``None``.

    The encoder adds ``ceil(m / 4)`` bins to ``m`` data chunks. That total grows
    strictly with ``m``, so the chunk count determines the bin count.
    """
    guess = 4 * chunks // 5
    for m in (guess - 1, guess, guess + 1):
        if m >= 0 and m - (-m // 4) == chunks:
            return chunks - m
    return None


def _drop_shared_bins(
    decoded: List[Optional[str]],
    chunks: List[str],
    mapping: Dict[str, Optional[str]],
    bin_codes: Sequence[str],
) -> None:
    """Resolve bins whose code a legacy table also uses for a character or space.

    Such chunks first decode as the character or space. The token length tells
    how many bins the encoder inserted (see :func:`_bins_inserted`), so if fewer
    chunks decoded as bins, some shared-code chunks are bins. Like the original
    decoder, drop the first occurrence of each shared code when that gives the
    right count; otherwise drop the earliest shared-code chunks. Tables
    generated by this package never share codes, so this is a no-op for them.
    """
    shared = {code for code in bin_codes if mapping.get(code) is not None}
    expected = _bins_inserted(len(decoded)) if shared else None
    if expected is None:
        return
    missing = expected - decoded.count(None)
    if missing <= 0:
        return
    positions = [i for i, chunk in enumerate(chunks) if chunk in shared]
    first_of_each = {chunks[i]: i for i in reversed(positions)}
    if len(first_of_each) == missing:
        chosen = list(first_of_each.values())
    elif missing <= len(positions):
        chosen = positions[:missing]
    else:
        return
    for i in chosen:
        decoded[i] = None


def _split_token(token: TokenLike) -> Tuple[Header, str]:
    stripped = token_text(token).strip()
    if not stripped:
        raise DecodingError("the token is empty")
    # The header is the first line. The original scripts allowed spaces in family
    # names, so try the whole line first, then "header body" on a single line.
    first_line, _, body = stripped.partition("\n")
    head = first_line.strip()
    parsed = parse_table_name(head)
    if parsed is None:
        parts = stripped.split(None, 1)
        head, body = parts[0], (parts[1] if len(parts) > 1 else "")
        parsed = parse_table_name(head)
    if parsed is None:
        if sealed.looks_encrypted(stripped):
            raise DecodingError("this is an encrypted token; use decrypt()")
        raise DecodingError(
            f"invalid header {head[:40]!r}; expected '<name>-<length>:<iterations>'"
        )
    family, length, iterations = parsed
    if not MIN_LENGTH <= length <= MAX_LENGTH or iterations < 1:
        raise DecodingError(f"invalid header {head!r}: unsupported length or iteration count")
    body = "".join(body.split())
    if len(body) > _MAX_TOKEN_CHARS:
        raise DecodingError("the token is longer than any token the encoder makes")
    if not _CODE_CHARS.issuperset(body):
        bad = sorted(set(body) - _CODE_CHARS)[:5]
        raise DecodingError(
            f"the token contains characters the encoder never produces: {bad!r}"
        )
    return Header(family, length, iterations), body

"""YACE (Yet Another Custom Encoder): a reversible text encoder built on random
substitution tables.

>>> import yace_codec as yace
>>> codec = yace.Codec(yace.KeyStore.in_memory())
>>> token = codec.encode("Hello, World!")
>>> codec.decode(token)
'Hello, World!'

YACE obfuscates text. It is not encryption: do not use it to protect secrets.
"""

from .codec import (
    DEFAULT_FAMILY,
    DEFAULT_ITERATIONS,
    DEFAULT_LENGTH,
    MAX_ENCODED_CHARS,
    MAX_ITERATIONS,
    Codec,
    Header,
    decode,
    decode_bytes,
    encode,
    encode_bytes,
    parse_header,
)
from .errors import (
    DecodingError,
    EncodingError,
    InvalidNameError,
    KeyStoreError,
    TableNotFoundError,
    UnsupportedCharacterError,
    YaceError,
)
from .keystore import ENV_VAR, Family, ImportResult, KeyStore, default_keystore_path
from .tables import MAX_LENGTH, MIN_LENGTH, SUPPORTED_CHARACTERS, Table

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_FAMILY",
    "DEFAULT_ITERATIONS",
    "DEFAULT_LENGTH",
    "ENV_VAR",
    "MAX_ENCODED_CHARS",
    "MAX_ITERATIONS",
    "MAX_LENGTH",
    "MIN_LENGTH",
    "SUPPORTED_CHARACTERS",
    "Codec",
    "DecodingError",
    "EncodingError",
    "Family",
    "Header",
    "ImportResult",
    "InvalidNameError",
    "KeyStore",
    "KeyStoreError",
    "Table",
    "TableNotFoundError",
    "UnsupportedCharacterError",
    "YaceError",
    "__version__",
    "decode",
    "decode_bytes",
    "default_keystore_path",
    "encode",
    "encode_bytes",
    "parse_header",
]

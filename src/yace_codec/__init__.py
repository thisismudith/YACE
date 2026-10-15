"""YACE (Yet Another Custom Encoder): a reversible text encoder built on random
substitution tables.

>>> import yace_codec as yace
>>> codec = yace.Codec(yace.KeyStore.in_memory())
>>> token = codec.encode("Hello, World!")
>>> codec.decode(token)
'Hello, World!'

encode()/decode() only obfuscate text. For secrets, use encrypt()/decrypt(),
which encrypt with your own secret token or a stored key.
"""

from .codec import (
    DEFAULT_FAMILY,
    DEFAULT_ITERATIONS,
    DEFAULT_KEY,
    DEFAULT_LENGTH,
    MAX_ENCODED_CHARS,
    MAX_ITERATIONS,
    Codec,
    Header,
    decode,
    decode_bytes,
    decrypt,
    encode,
    encode_bytes,
    encrypt,
    parse_header,
)
from .errors import (
    DecodingError,
    DecryptionError,
    EncodingError,
    InvalidNameError,
    KeyStoreError,
    TableNotFoundError,
    TokenExpiredError,
    UnsupportedCharacterError,
    YaceError,
)
from .keystore import ENV_VAR, Family, ImportResult, KeyStore, default_keystore_path
from .tables import MAX_LENGTH, MIN_LENGTH, SUPPORTED_CHARACTERS, Table

__version__ = "0.2.1"

__all__ = [
    "DEFAULT_FAMILY",
    "DEFAULT_ITERATIONS",
    "DEFAULT_KEY",
    "DEFAULT_LENGTH",
    "ENV_VAR",
    "MAX_ENCODED_CHARS",
    "MAX_ITERATIONS",
    "MAX_LENGTH",
    "MIN_LENGTH",
    "SUPPORTED_CHARACTERS",
    "Codec",
    "DecodingError",
    "DecryptionError",
    "EncodingError",
    "Family",
    "Header",
    "ImportResult",
    "InvalidNameError",
    "KeyStore",
    "KeyStoreError",
    "Table",
    "TableNotFoundError",
    "TokenExpiredError",
    "UnsupportedCharacterError",
    "YaceError",
    "__version__",
    "decode",
    "decode_bytes",
    "decrypt",
    "default_keystore_path",
    "encode",
    "encode_bytes",
    "encrypt",
    "parse_header",
]

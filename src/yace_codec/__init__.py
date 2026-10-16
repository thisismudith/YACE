"""YACE (Yet Another Custom Encoder): a reversible text encoder built on random
substitution tables.

>>> import yace_codec as yace
>>> codec = yace.Codec(yace.KeyStore.in_memory())
>>> token = codec.encode("Hello, World!")
>>> codec.decode(token)
'Hello, World!'

encode()/decode() only obfuscate text. For secrets, use encrypt()/decrypt(),
which encrypt with AES-256-GCM (by default) using your own secret token, a raw
key, or a stored key.
"""

from ._algorithms import DEFAULT_ALGORITHM, AlgorithmInfo, algorithms
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
    decrypt_stream,
    encode,
    encode_bytes,
    encrypt,
    encrypt_stream,
    generate_key,
    parse_header,
)
from .errors import (
    DecodingError,
    DecryptionError,
    EncodingError,
    InvalidKeyError,
    InvalidNameError,
    KeyNotFoundError,
    KeyStoreError,
    TableNotFoundError,
    TokenExpiredError,
    UnsupportedCharacterError,
    YaceError,
)
from .sealed import DEFAULT_CHUNK_SIZE, KEY_SIZE, MAX_MESSAGE_SIZE, StreamInfo
from .keybackends import DpapiKeyStore, KeyBackend, KeyringKeyStore, open_key_backend
from .keystore import ENV_VAR, Family, ImportResult, KeyStore, default_keystore_path
from .tables import MAX_LENGTH, MIN_LENGTH, SUPPORTED_CHARACTERS, Table

__version__ = "0.3.0"

__all__ = [
    "DEFAULT_ALGORITHM",
    "DEFAULT_CHUNK_SIZE",
    "DEFAULT_FAMILY",
    "DEFAULT_ITERATIONS",
    "DEFAULT_KEY",
    "DEFAULT_LENGTH",
    "ENV_VAR",
    "KEY_SIZE",
    "MAX_ENCODED_CHARS",
    "MAX_ITERATIONS",
    "MAX_LENGTH",
    "MAX_MESSAGE_SIZE",
    "MIN_LENGTH",
    "SUPPORTED_CHARACTERS",
    "AlgorithmInfo",
    "Codec",
    "DecodingError",
    "DecryptionError",
    "DpapiKeyStore",
    "EncodingError",
    "Family",
    "Header",
    "ImportResult",
    "InvalidKeyError",
    "InvalidNameError",
    "KeyBackend",
    "KeyNotFoundError",
    "KeyStore",
    "KeyStoreError",
    "KeyringKeyStore",
    "StreamInfo",
    "Table",
    "TableNotFoundError",
    "TokenExpiredError",
    "UnsupportedCharacterError",
    "YaceError",
    "__version__",
    "algorithms",
    "decode",
    "decode_bytes",
    "decrypt",
    "decrypt_stream",
    "default_keystore_path",
    "encode",
    "encode_bytes",
    "encrypt",
    "encrypt_stream",
    "generate_key",
    "open_key_backend",
    "parse_header",
]

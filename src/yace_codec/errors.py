"""Exceptions raised by yace_codec.

Every exception derives from :class:`YaceError`, so ``except YaceError`` catches
all of them. Errors about bad input also derive from :class:`ValueError`.
"""

from __future__ import annotations

from typing import Tuple

__all__ = [
    "DecodingError",
    "DecryptionError",
    "EncodingError",
    "InvalidNameError",
    "KeyStoreError",
    "TableNotFoundError",
    "TokenExpiredError",
    "UnsupportedCharacterError",
    "YaceError",
]


class YaceError(Exception):
    """Base class for all yace_codec errors."""


class InvalidNameError(YaceError, ValueError):
    """A table family name is not allowed."""


class EncodingError(YaceError, ValueError):
    """The input cannot be encoded with the requested settings."""


class UnsupportedCharacterError(EncodingError):
    """The text contains characters that the substitution table cannot encode.

    ``characters`` holds the offending characters and ``table_name`` names the
    table that was checked.
    """

    def __init__(
        self, message: str, characters: Tuple[str, ...] = (), table_name: str = ""
    ) -> None:
        super().__init__(message)
        self.characters = characters
        self.table_name = table_name


class DecodingError(YaceError, ValueError):
    """The token is malformed, corrupted, or does not match the key store's tables."""


class DecryptionError(DecodingError):
    """Encrypted data cannot be opened: wrong key or secret token, or it was changed."""


class TokenExpiredError(DecryptionError):
    """An encrypted token is older than the ``max_age`` given to ``decrypt``."""


class TableNotFoundError(YaceError, LookupError):
    """A table needed for decoding or export is not in the key store.

    ``table_name`` names the missing table (or family).
    """

    def __init__(self, message: str, table_name: str = "") -> None:
        super().__init__(message)
        self.table_name = table_name


class KeyStoreError(YaceError):
    """The key store cannot be read, parsed, validated, or written."""

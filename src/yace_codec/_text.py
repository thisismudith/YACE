"""Turn token input (``str`` or ``bytes``, possibly with a byte order mark) into text."""

from __future__ import annotations

import codecs
from typing import Optional, Tuple, Union

from .errors import DecodingError

TokenLike = Union[str, bytes, bytearray, memoryview]

#: Byte order marks and the codec that reads text starting with each. UTF-32
#: comes first: its little-endian BOM starts with the UTF-16 one.
TEXT_ENCODINGS: Tuple[Tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)
BOM = "﻿"


def bom_encoding(data: bytes) -> Optional[str]:
    """The codec for text that starts with a byte order mark, or ``None``."""
    return next((encoding for bom, encoding in TEXT_ENCODINGS if data.startswith(bom)), None)


def token_text(token: TokenLike) -> str:
    """Return ``token`` as text without a leading byte order mark.

    Bytes are read as UTF-8, or as UTF-16/UTF-32 when they start with a byte
    order mark, because Windows tools often add one (PowerShell 5.1 writes UTF-16).
    """
    if isinstance(token, (bytes, bytearray, memoryview)):
        raw = bytes(token)
        try:
            token = raw.decode(bom_encoding(raw) or "utf-8")
        except UnicodeDecodeError:
            raise DecodingError(
                "a token must be text: UTF-8, or UTF-16/UTF-32 with a byte order mark"
            ) from None
    elif not isinstance(token, str):
        raise TypeError(f"token must be str or bytes, not {type(token).__name__}")
    return token[1:] if token.startswith(BOM) else token

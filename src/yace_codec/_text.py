"""Turn token input (``str`` or ``bytes``, possibly with a byte order mark) into text."""

from __future__ import annotations

import codecs
from typing import Union

from .errors import DecodingError

TokenLike = Union[str, bytes, bytearray]

# UTF-32 first: its little-endian BOM starts with the UTF-16 one.
_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def token_text(token: TokenLike) -> str:
    """Return ``token`` as text without a leading byte order mark.

    Bytes are read as UTF-8, or as UTF-16/UTF-32 when they start with a byte
    order mark, because Windows tools often add one (PowerShell 5.1 writes UTF-16).
    """
    if isinstance(token, (bytes, bytearray)):
        raw = bytes(token)
        encoding = next((enc for bom, enc in _BOMS if raw.startswith(bom)), "utf-8")
        try:
            token = raw.decode(encoding)
        except UnicodeDecodeError:
            raise DecodingError(
                "a token must be text: UTF-8, or UTF-16/UTF-32 with a byte order mark"
            ) from None
    elif not isinstance(token, str):
        raise TypeError(f"token must be str or bytes, not {type(token).__name__}")
    return token[1:] if token.startswith("﻿") else token

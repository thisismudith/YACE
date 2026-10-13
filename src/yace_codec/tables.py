"""Substitution tables: generation, validation, and JSON (de)serialisation.

A *table* (the original YACE scripts called it a "hash") maps every supported
character to a random code of ``length`` characters drawn from
:data:`CODE_ALPHABET`. The space character gets several interchangeable codes,
and every table also carries *bin* codes: noise chunks that the encoder inserts
and the decoder drops.

Tables are stored under names of the form ``<family>-<length>:<layer>``, using
the JSON layout of the original ``encodings.json``::

    {"demo-3:1": {"a": "xQ9", "b": "7Lp", ..., " ": ["..."], "bin": ["..."]}}
"""

from __future__ import annotations

import itertools
import re
import string
from random import Random
from types import MappingProxyType
from typing import Any, Callable, Dict, FrozenSet, Iterable, Mapping, Optional, Set, Tuple

from .errors import InvalidNameError, KeyStoreError

__all__ = [
    "BIN_KEY",
    "CODE_ALPHABET",
    "MAX_LENGTH",
    "MIN_LENGTH",
    "SPACE_KEY",
    "SUPPORTED_CHARACTERS",
    "TABLE_CHARACTERS",
    "Table",
    "parse_table_name",
    "table_name",
    "validate_family",
]

#: Characters that codes are built from (the alphabet of the original scripts).
CODE_ALPHABET = string.ascii_letters + string.digits

#: Characters that get their own code in a newly generated table. The original
#: scripts covered punctuation, letters, digits, and newline; tab, carriage
#: return, vertical tab, and form feed were added so that new tables cover all
#: of :data:`string.printable`.
TABLE_CHARACTERS = (
    string.punctuation + string.ascii_letters + string.digits + "\n\t\r\x0b\x0c"
)

#: Every character a newly generated table can encode (equal to ``string.printable``).
SUPPORTED_CHARACTERS: FrozenSet[str] = frozenset(TABLE_CHARACTERS + " ")

#: JSON key holding the space codes.
SPACE_KEY = " "
#: JSON key holding the bin (noise) codes.
BIN_KEY = "bin"

#: Number of space and bin codes in a generated table (the original defaults).
SPACE_CODES = 10
BIN_CODES = 26

#: Allowed code lengths. A length of 1 cannot give 100 distinct codes, and codes
#: never repeat a character, so the length cannot exceed the alphabet size.
MIN_LENGTH = 2
MAX_LENGTH = len(CODE_ALPHABET)

_CODE_CHARS = frozenset(CODE_ALPHABET)
_FAMILY_RE = re.compile(r"[A-Za-z_]{1,64}")
_MAX_DIGITS = 4
#: Longest table name (or token header) that is accepted.
MAX_NAME_LENGTH = 128
#: Most space or bin codes a table may hold (the original scripts used 10 and 26).
MAX_SPECIAL_CODES = 1000
#: Most characters a table may cover.
MAX_TABLE_CHARACTERS = 10_000


def table_name(family: str, length: int, layer: int) -> str:
    """Return a table's key-store name, e.g. ``table_name("demo", 3, 1) == "demo-3:1"``."""
    return f"{family}-{length}:{layer}"


def parse_table_name(name: str) -> Optional[Tuple[str, int, int]]:
    """Split ``"<family>-<length>:<layer>"`` into its parts, or return ``None``.

    Names longer than :data:`MAX_NAME_LENGTH` characters, or containing
    non-printable characters (control characters, tabs, line breaks), are
    rejected. Spaces are allowed: the original scripts accepted them in
    family names.
    """
    if len(name) > MAX_NAME_LENGTH or not name.isprintable():
        return None
    family, dash, rest = name.rpartition("-")
    length, colon, layer = rest.partition(":")
    if not (family and dash and colon and _is_number(length) and _is_number(layer)):
        return None
    return family, int(length), int(layer)


def validate_family(name: object) -> str:
    """Return ``name`` if it is a valid family name for new tables.

    Valid names have 1-64 ASCII letters or underscores. Digits, ``-`` and ``:``
    are excluded because they delimit the length and layer in table names.
    """
    if not isinstance(name, str) or not _FAMILY_RE.fullmatch(name):
        raise InvalidNameError(
            f"invalid table family name {name!r}: use 1-64 ASCII letters or "
            "underscores (no digits, '-' or ':')"
        )
    return name


def _is_number(text: str) -> bool:
    return 0 < len(text) <= _MAX_DIGITS and text.isascii() and text.isdigit()


class Table:
    """A validated, immutable substitution table.

    Create tables with :meth:`generate` or :meth:`from_dict`. The constructor
    validates its arguments and raises :class:`~yace_codec.errors.KeyStoreError`
    for an invalid table.
    """

    __slots__ = (
        "name",
        "length",
        "codes",
        "space_codes",
        "bin_codes",
        "usable_space_codes",
        "usable_bin_codes",
        "_code_of",
    )

    name: str
    length: int
    codes: Mapping[str, str]
    space_codes: Tuple[str, ...]
    bin_codes: Tuple[str, ...]
    usable_space_codes: Tuple[str, ...]
    usable_bin_codes: Tuple[str, ...]
    _code_of: Callable[[str], str]

    def __init__(
        self,
        name: str,
        length: int,
        codes: Mapping[str, str],
        space_codes: Iterable[str],
        bin_codes: Iterable[str],
    ) -> None:
        lookup = dict(codes)
        spaces, bins = tuple(space_codes), tuple(bin_codes)
        _validate(name, length, lookup, spaces, bins)
        set_ = object.__setattr__
        set_(self, "name", name)
        set_(self, "length", length)
        set_(self, "codes", MappingProxyType(lookup))
        set_(self, "_code_of", lookup.__getitem__)
        set_(self, "space_codes", spaces)
        set_(self, "bin_codes", bins)
        # Tables made by the original scripts can share a code between a
        # character, a space, and a bin. The encoder never emits a shared space
        # or bin code, so new tokens stay unambiguous for every decoder.
        char_codes = set(lookup.values())
        space_set, bin_set = set(spaces), set(bins)
        set_(
            self,
            "usable_space_codes",
            tuple(dict.fromkeys(c for c in spaces if c not in char_codes and c not in bin_set)),
        )
        set_(
            self,
            "usable_bin_codes",
            tuple(dict.fromkeys(c for c in bins if c not in char_codes and c not in space_set)),
        )

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("Table objects are read-only")

    def __repr__(self) -> str:
        return f"Table(name={self.name!r}, length={self.length}, characters={len(self.characters)})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Table):
            return NotImplemented
        return self.to_dict() == other.to_dict() and self.name == other.name

    __hash__ = None  # type: ignore[assignment]

    @property
    def characters(self) -> FrozenSet[str]:
        """The characters this table can encode."""
        if self.usable_space_codes:
            return frozenset(self.codes).union(SPACE_KEY)
        return frozenset(self.codes)

    def translate(self, text: str) -> str:
        """Replace every character of ``text`` with its code.

        Raises :class:`KeyError` for a character without a single code,
        including the space (it has several codes; see ``usable_space_codes``).
        """
        return "".join(map(self._code_of, text))

    def reverse_map(self, *, plaintext: bool, outermost: bool) -> Dict[str, Optional[str]]:
        """Map codes back to characters for one decoding layer.

        ``None`` marks a bin code (dropped while decoding). Bins only occur on
        the outermost layer. Inner layers can only decode to letters and digits,
        because their output is a string of codes from the layer below. When a
        legacy table shares a code, characters take priority over spaces and
        spaces over bins, as in the original decoder.
        """
        mapping: Dict[str, Optional[str]] = {}
        if outermost:
            mapping.update(dict.fromkeys(self.bin_codes))
        if plaintext:
            mapping.update(dict.fromkeys(self.space_codes, SPACE_KEY))
        for ch, code in self.codes.items():
            if plaintext or ch in _CODE_CHARS:
                mapping[code] = ch
        return mapping

    def to_dict(self) -> Dict[str, Any]:
        """Return the table in key-store JSON layout."""
        data: Dict[str, Any] = dict(self.codes)
        data[SPACE_KEY] = list(self.space_codes)
        data[BIN_KEY] = list(self.bin_codes)
        return data

    @classmethod
    def from_dict(cls, name: str, data: Any) -> Table:
        """Validate key-store JSON for table ``name`` and build a :class:`Table`.

        Raises :class:`~yace_codec.errors.KeyStoreError` if the data is not a
        usable table.
        """
        length = _length_of(name)
        if not isinstance(data, dict):
            raise KeyStoreError(f"table {name!r} is invalid: expected a JSON object")
        spaces, bins = data.get(SPACE_KEY), data.get(BIN_KEY)
        if not isinstance(spaces, list) or not isinstance(bins, list):
            raise KeyStoreError(
                f"table {name!r} is invalid: {SPACE_KEY!r} and {BIN_KEY!r} must be lists of codes"
            )
        codes = {k: v for k, v in data.items() if k not in (SPACE_KEY, BIN_KEY)}
        return cls(name, length, codes, spaces, bins)

    @classmethod
    def generate(cls, name: str, rng: Random) -> Table:
        """Generate a random table for ``name`` (``"<family>-<length>:<layer>"``).

        Every code is unique within the table, so decoding is never ambiguous.
        Codes never repeat a character, as in the original generator.
        """
        parsed = parse_table_name(name)
        if parsed is None:
            raise ValueError(f"invalid table name {name!r}: expected '<family>-<length>:<layer>'")
        length = parsed[1]
        if not MIN_LENGTH <= length <= MAX_LENGTH:
            raise ValueError(f"code length must be {MIN_LENGTH}-{MAX_LENGTH}, got {length}")
        used: Set[str] = set()

        def fresh() -> str:
            while True:
                code = "".join(rng.sample(CODE_ALPHABET, length))
                if code not in used:
                    used.add(code)
                    return code

        codes = {ch: fresh() for ch in TABLE_CHARACTERS}
        spaces = [fresh() for _ in range(SPACE_CODES)]
        bins = [fresh() for _ in range(BIN_CODES)]
        return cls(name, length, codes, spaces, bins)


def _length_of(name: object) -> int:
    """Return the code length in table ``name``, or raise KeyStoreError."""
    parsed = parse_table_name(name) if isinstance(name, str) else None
    if parsed is None:
        raise KeyStoreError(f"invalid table name {name!r}: expected '<family>-<length>:<layer>'")
    if not MIN_LENGTH <= parsed[1] <= MAX_LENGTH:
        raise KeyStoreError(f"table {name!r} is invalid: code length must be {MIN_LENGTH}-{MAX_LENGTH}")
    return parsed[1]


def _validate(
    name: object,
    length: object,
    codes: Dict[Any, Any],
    spaces: Tuple[Any, ...],
    bins: Tuple[Any, ...],
) -> None:
    def invalid(reason: str) -> KeyStoreError:
        return KeyStoreError(f"table {name!r} is invalid: {reason}")

    if length != _length_of(name):
        raise invalid(f"its name does not match code length {length!r}")
    if len(codes) > MAX_TABLE_CHARACTERS:
        raise invalid(f"more than {MAX_TABLE_CHARACTERS} characters")
    if len(spaces) > MAX_SPECIAL_CODES or len(bins) > MAX_SPECIAL_CODES:
        raise invalid(f"more than {MAX_SPECIAL_CODES} space or bin codes")
    for key in codes:
        if not isinstance(key, str) or len(key) != 1:
            raise invalid(f"key {key!r} is not a single character")
    if SPACE_KEY in codes:
        raise invalid("the space must use the list of space codes")
    for code in itertools.chain(codes.values(), spaces, bins):
        if not (isinstance(code, str) and len(code) == length and _CODE_CHARS.issuperset(code)):
            raise invalid(f"code {code!r} is not {length} ASCII letters or digits")
    if len(set(codes.values())) != len(codes):
        raise invalid("two characters share the same code")
    missing = _CODE_CHARS.difference(codes)
    if missing:
        raise invalid(f"no code for {''.join(sorted(missing))!r}")

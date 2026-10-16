"""Where secret keys for ``encrypt()`` and ``decrypt()`` are kept.

Every backend implements :class:`KeyBackend`:

- :class:`~yace_codec.keystore.KeyStore` (``"json"``, the default): a JSON
  file. Keys are stored **in plain text** (base64); anyone who can read the
  file can decrypt. New files are readable only by their owner (mode 0600 on
  POSIX, an owner-only ACL on Windows).
- :class:`DpapiKeyStore` (``"dpapi"``, Windows only): a JSON file whose keys
  are encrypted with DPAPI for the current Windows user, so a copy of the file
  is useless on another account or computer.
- :class:`KeyringKeyStore` (``"keyring"``): the operating system's credential
  store (Windows Credential Manager, macOS Keychain, Secret Service) through
  the optional ``keyring`` package (``pip install yace-codec[keyring]``).
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import threading
from pathlib import Path
from random import Random
from typing import Any, Dict, List, Mapping, Optional, Protocol, Tuple, runtime_checkable

from . import _winsec
from .errors import KeyStoreError, TableNotFoundError
from .keystore import (
    _KEY_PREFIX,
    ImportResult,
    KeyStore,
    PathLike,
    _key_entry,
    _decode_secret,
    _KeyRecord,
    _new_key,
    _parse_key_record,
    _plan_import,
    default_keystore_path,
    parse_key_entries,
)
from .sealed import KEY_SIZE
from .tables import validate_family

__all__ = [
    "BACKENDS",
    "DpapiKeyStore",
    "KeyBackend",
    "KeyringKeyStore",
    "default_dpapi_path",
    "open_key_backend",
]

#: Names accepted by :func:`open_key_backend` (and ``--key-backend``).
BACKENDS = ("json", "dpapi", "keyring")


@runtime_checkable
class KeyBackend(Protocol):
    """Storage for named 32-byte secret keys."""

    def key_names(self) -> List[str]:
        """Names of the stored keys, sorted."""

    def find_key(self, name: str) -> Optional[bytes]:
        """The current key ``name``, or ``None``."""

    def get_key(self, name: str) -> bytes:
        """The current key ``name``; raise TableNotFoundError if it is missing."""

    def ensure_key(self, name: str, *, rng: Optional[Random] = None) -> bytes:
        """The current key ``name``, generated and saved if missing."""

    def rotate_key(self, name: str, *, rng: Optional[Random] = None) -> bytes:
        """Replace key ``name`` with a new one, keeping the old one for decryption."""

    def delete_key(self, name: str) -> None:
        """Remove key ``name`` and its retired keys."""

    def decryption_keys(self) -> List[bytes]:
        """Every current and retired key, for decryption."""

    def export_key(self, name: str) -> Dict[str, Dict[str, Any]]:
        """Key ``name`` (with retired keys) as portable JSON data."""

    def import_keys(
        self, keys: Mapping[str, Any], *, overwrite: bool = False, name: Optional[str] = None
    ) -> ImportResult:
        """Add keys from :meth:`export_key` data."""


def default_dpapi_path() -> Path:
    """``keys-dpapi.json`` next to the default key store."""
    return default_keystore_path().with_name("keys-dpapi.json")


class DpapiKeyStore(KeyStore):
    """Secret keys encrypted with Windows DPAPI for the current user.

    Entries are ``"key:<name>": {"dpapi": <base64>, "retired": [...]}``.
    :meth:`export_key` still returns portable, unprotected keys. Use this store
    for keys only; tables are not protected.
    """

    def __init__(self, path: Optional[PathLike] = None) -> None:
        super().__init__(default_dpapi_path() if path is None else path)

    def __repr__(self) -> str:
        if self.path is None:
            return "DpapiKeyStore.in_memory()"
        return f"DpapiKeyStore({str(self.path)!r})"

    def _encode_record(self, record: _KeyRecord) -> Dict[str, Any]:
        entry: Dict[str, Any] = {"dpapi": _b64(_winsec.protect(record.current))}
        if record.retired:
            entry["retired"] = [_b64(_winsec.protect(key)) for key in record.retired]
        return entry

    def _decode_record(self, entry: str, raw: Any) -> _KeyRecord:
        if not isinstance(raw, dict) or not isinstance(raw.get("dpapi"), str):
            raise KeyStoreError(f"{entry!r} is invalid: expected a DPAPI-protected key ('dpapi')")
        retired = raw.get("retired", [])
        if not isinstance(retired, list):
            raise KeyStoreError(f"{entry!r} is invalid: 'retired' must be a list")
        return _KeyRecord(
            self._unprotect(entry, raw["dpapi"]),
            tuple(self._unprotect(entry, value) for value in retired),
        )

    @staticmethod
    def _unprotect(entry: str, value: Any) -> bytes:
        try:
            blob = base64.b64decode(value, validate=True) if isinstance(value, str) else b""
        except (binascii.Error, ValueError):
            blob = b""
        if not blob:
            raise KeyStoreError(f"{entry!r} is invalid: expected base64 DPAPI data")
        key = _winsec.unprotect(blob)
        if len(key) != KEY_SIZE:
            raise KeyStoreError(f"{entry!r} is invalid: the protected key is not {KEY_SIZE} bytes")
        return key


class KeyringKeyStore:
    """Secret keys in the system keyring (needs ``pip install yace-codec[keyring]``).

    Each key is a small credential under ``service``: user ``key:<name>`` holds
    ``{"secret": <base64>, "retired": <count>}``, and each retired key has its own
    credential (``key:<name>:retired:<n>``, oldest first), so no credential grows
    past keyring size limits. Keyrings cannot list their entries, so another
    credential lists the names; it is repaired when an unlisted key is found.
    """

    _INDEX = "__yace_codec_key_names__"

    def __init__(self, service: str = "yace-codec") -> None:
        try:
            import keyring
            import keyring.errors
        except ImportError:
            raise KeyStoreError(
                "the keyring backend needs the 'keyring' package: pip install yace-codec[keyring]"
            ) from None
        self.service = service
        self._keyring = keyring
        self._lock = threading.RLock()

    def __repr__(self) -> str:
        return f"KeyringKeyStore(service={self.service!r})"

    def key_names(self) -> List[str]:
        with self._lock:
            raw = self._get(self._INDEX)
            try:
                names = json.loads(raw) if raw else []
            except ValueError:
                raise KeyStoreError(f"the keyring's key index for {self.service!r} is corrupted") from None
            return sorted({name for name in names if isinstance(name, str)})

    def find_key(self, name: str) -> Optional[bytes]:
        record = self._record(name)
        return None if record is None else record.current

    def get_key(self, name: str) -> bytes:
        key = self.find_key(name)
        if key is None:
            raise TableNotFoundError(f"key {name!r} is not in the keyring service {self.service!r}", name)
        return key

    def decryption_keys(self) -> List[bytes]:
        records = [record for record in map(self._record, self.key_names()) if record is not None]
        return [record.current for record in records] + [key for record in records for key in record.retired]

    def ensure_key(self, name: str, *, rng: Optional[Random] = None) -> bytes:
        validate_family(name)
        with self._lock:
            record = self._record(name)
            if record is None:
                record = _KeyRecord(_new_key(rng), ())
                self._store(name, record)
            else:
                self._index_add(name)
            return record.current

    def rotate_key(self, name: str, *, rng: Optional[Random] = None) -> bytes:
        validate_family(name)
        with self._lock:
            key = _new_key(rng)
            old = self._main(name)
            if old is None:
                self._store(name, _KeyRecord(key, ()))
                return key
            current, count = old
            # Append the old key as the newest retired one, then switch.
            self._set(self._retired_user(name, count), _b64(current))
            self._set(_KEY_PREFIX + name, json.dumps({"secret": _b64(key), "retired": count + 1}))
            self._index_add(name)
            return key

    def delete_key(self, name: str) -> None:
        with self._lock:
            main = self._main(name)
            listed = name in self.key_names()
            if main is None and not listed:
                raise TableNotFoundError(f"key {name!r} is not in the keyring service {self.service!r}", name)
            if main is not None:
                for index in range(main[1]):
                    self._delete(self._retired_user(name, index))
                self._delete(_KEY_PREFIX + name)
            self._set(self._INDEX, json.dumps([n for n in self.key_names() if n != name]))

    def export_key(self, name: str) -> Dict[str, Dict[str, Any]]:
        record = self._record(name)
        if record is None:
            raise TableNotFoundError(f"key {name!r} is not in the keyring service {self.service!r}", name)
        return {_KEY_PREFIX + name: _key_entry(record)}

    def import_keys(
        self, keys: Mapping[str, Any], *, overwrite: bool = False, name: Optional[str] = None
    ) -> ImportResult:
        incoming = parse_key_entries(keys, name)
        with self._lock:
            # Look every incoming key up directly: the index may have missed one.
            current = {
                entry: _key_entry(record)
                for entry in incoming
                if (record := self._record(entry[len(_KEY_PREFIX) :])) is not None
            }
            result = _plan_import(current, incoming, overwrite, lambda _entry, raw: raw, "key")
            for entry in result.added + result.replaced:
                self._store(entry[len(_KEY_PREFIX) :], _parse_key_record(entry, incoming[entry]))
            for entry in result.unchanged:
                self._index_add(entry[len(_KEY_PREFIX) :])
        return result

    @staticmethod
    def _retired_user(name: str, index: int) -> str:
        return f"{_KEY_PREFIX}{name}:retired:{index}"

    def _main(self, name: str) -> Optional[Tuple[bytes, int]]:
        """The current key and the number of retired keys, or ``None``."""
        raw = self._get(_KEY_PREFIX + name)
        if raw is None:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        if not isinstance(data, dict) or not isinstance(data.get("retired", 0), int):
            raise KeyStoreError(f"key {name!r} in the keyring is corrupted")
        return _decode_secret(_KEY_PREFIX + name, data.get("secret")), max(0, data.get("retired", 0))

    def _record(self, name: str) -> Optional[_KeyRecord]:
        main = self._main(name)
        if main is None:
            return None
        current, count = main
        retired = []
        for index in range(count):
            value = self._get(self._retired_user(name, index))
            if value is None:
                raise KeyStoreError(f"retired key {index} of {name!r} is missing from the keyring")
            retired.append(_decode_secret(_KEY_PREFIX + name, value))
        return _KeyRecord(current, tuple(reversed(retired)))  # newest first

    def _store(self, name: str, record: _KeyRecord) -> None:
        old = self._main(name)
        retired = list(reversed(record.retired))  # oldest first
        for index, key in enumerate(retired):
            self._set(self._retired_user(name, index), _b64(key))
        self._set(_KEY_PREFIX + name, json.dumps({"secret": _b64(record.current), "retired": len(retired)}))
        if old is not None:
            for index in range(len(retired), old[1]):
                self._delete(self._retired_user(name, index))
        self._index_add(name)

    def _index_add(self, name: str) -> None:
        names = self.key_names()
        if name not in names:
            self._set(self._INDEX, json.dumps(sorted(names + [name])))

    def _get(self, user: str) -> Optional[str]:
        value = self._call("read", self._keyring.get_password, self.service, user)
        return value if isinstance(value, str) else None

    def _set(self, user: str, value: str) -> None:
        self._call("write", self._keyring.set_password, self.service, user, value)

    def _delete(self, user: str) -> None:
        with contextlib.suppress(KeyStoreError):  # already gone
            self._call("delete from", self._keyring.delete_password, self.service, user)

    @staticmethod
    def _call(what: str, function: Any, *args: Any) -> Any:
        try:
            return function(*args)
        except Exception as exc:  # keyring backends raise their own exception types
            raise KeyStoreError(f"cannot {what} the keyring: {type(exc).__name__}: {exc}") from None


def open_key_backend(
    kind: str, *, path: Optional[PathLike] = None, service: str = "yace-codec"
) -> KeyBackend:
    """Open a key backend by name: ``"json"``, ``"dpapi"``, or ``"keyring"``."""
    if kind == "json":
        return KeyStore.default() if path is None else KeyStore(path)
    if kind == "dpapi":
        return DpapiKeyStore(path)
    if kind == "keyring":
        return KeyringKeyStore(service)
    raise ValueError(f"unknown key backend {kind!r}; choose one of {', '.join(BACKENDS)}")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

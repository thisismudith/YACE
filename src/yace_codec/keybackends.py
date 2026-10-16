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
  the optional ``keyring`` package (``pip install "yace-codec[keyring]"``).
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import sys
import threading
from pathlib import Path
from random import Random
from typing import Any, Dict, Iterator, List, Mapping, Optional, Protocol, Tuple, Type, runtime_checkable

from . import _winsec
from .errors import KeyNotFoundError, KeyStoreError
from .keystore import (
    _KEY_PREFIX,
    ImportResult,
    KeyStore,
    PathLike,
    _decode_secret,
    _file_lock,
    _key_entry,
    _KeyRecord,
    _new_key,
    _parse_key_record,
    _plan_import,
    _usable_keys,
    default_keystore_path,
    parse_key_entries,
    validate_key_name,
)
from .sealed import KEY_SIZE

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
        """The current key ``name``; raise KeyNotFoundError if it is missing."""

    def ensure_key(self, name: str, *, rng: Optional[Random] = None) -> bytes:
        """The current key ``name``, generated and saved if missing."""

    def rotate_key(self, name: str, *, rng: Optional[Random] = None) -> bytes:
        """Give ``name`` a new key, keeping the old one for decryption; create it if missing."""

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
    """Secret keys encrypted with Windows DPAPI for the current user (Windows only).

    Entries are ``"key:<name>": {"dpapi": <base64>, "retired": [...]}``.
    :meth:`export_key` still returns portable, unprotected keys. The file holds
    keys only; keep tables in a :class:`~yace_codec.keystore.KeyStore`.
    """

    def __init__(self, path: Optional[PathLike] = None) -> None:
        if sys.platform != "win32":
            raise KeyStoreError("DPAPI key stores are only available on Windows")
        super().__init__(default_dpapi_path() if path is None else path)

    def _setup(self, path: Optional[Path]) -> None:
        super()._setup(path)
        self._unprotected: Dict[str, bytes] = {}  # base64 blob -> key, to skip repeat DPAPI calls

    def __repr__(self) -> str:
        if self.path is None:
            return "DpapiKeyStore.in_memory()"
        return f"DpapiKeyStore({str(self.path)!r})"

    def ensure_tables(self, *args: Any, **kwargs: Any) -> Any:
        raise KeyStoreError("a DPAPI key store holds keys only; keep tables in a KeyStore")

    def import_tables(self, *args: Any, **kwargs: Any) -> Any:
        raise KeyStoreError("a DPAPI key store holds keys only; keep tables in a KeyStore")

    def _encode_record(self, record: _KeyRecord) -> Dict[str, Any]:
        entry: Dict[str, Any] = {"dpapi": _b64(_winsec.protect(record.current))}
        if record.retired:
            entry["retired"] = [_b64(_winsec.protect(key)) for key in record.retired]
        return entry

    def _decode_record(self, entry: str, raw: Any) -> _KeyRecord:
        if isinstance(raw, dict) and "secret" in raw and "dpapi" not in raw:
            raise KeyStoreError(
                f"{entry!r} is a plain-text key, not a DPAPI-protected one: open this file "
                "with KeyStore (CLI: --key-backend json)"
            )
        if not isinstance(raw, dict) or not isinstance(raw.get("dpapi"), str):
            raise KeyStoreError(f"{entry!r} is invalid: expected a DPAPI-protected key ('dpapi')")
        retired = raw.get("retired", [])
        if not isinstance(retired, list):
            raise KeyStoreError(f"{entry!r} is invalid: 'retired' must be a list")
        return _KeyRecord(
            self._unprotect(entry, raw["dpapi"]),
            tuple(self._unprotect(entry, value) for value in retired),
        )

    def _unprotect(self, entry: str, value: Any) -> bytes:
        if isinstance(value, str) and value in self._unprotected:
            return self._unprotected[value]
        try:
            blob = base64.b64decode(value, validate=True) if isinstance(value, str) else b""
        except (binascii.Error, ValueError):
            blob = b""
        if not blob:
            raise KeyStoreError(f"{entry!r} is invalid: expected base64 DPAPI data")
        key = _winsec.unprotect(blob)
        if len(key) != KEY_SIZE:
            raise KeyStoreError(f"{entry!r} is invalid: the protected key is not {KEY_SIZE} bytes")
        self._unprotected[value] = key
        return key


class KeyringKeyStore:
    """Secret keys in the system keyring (needs ``pip install "yace-codec[keyring]"``).

    Credentials under ``service`` (user names):

    - ``key:<name>``: ``{"secret": <base64>, "retired": [first, next]}``; the
      retired keys are in ``key:<name>:retired:<n>`` for ``first <= n < next``
      (oldest first), so no credential grows with rotation.
    - ``__yace_codec_key_names__:<n>``: the list of key names, in parts small
      enough for every keyring (keyrings cannot list their entries).

    Changes are serialised across processes with a lock file next to the
    default key store, and written so that a failure part way never loses a
    key that was already stored.
    """

    _INDEX = "__yace_codec_key_names__"
    _INDEX_PART_CHARS = 900  # Windows Credential Manager stores up to 1280 characters
    _MAX_PARTS = 1000
    _MAX_RETIRED = 100_000

    def __init__(self, service: str = "yace-codec") -> None:
        try:
            import keyring
            import keyring.errors
        except ImportError:
            raise KeyStoreError(
                'the keyring backend needs the "keyring" package: pip install "yace-codec[keyring]"'
            ) from None
        if not isinstance(service, str) or not service:
            raise KeyStoreError("the keyring service name must be a non-empty string")
        self.service = service
        self._keyring = keyring
        self._delete_error: Type[BaseException] = keyring.errors.PasswordDeleteError
        self._thread_lock = threading.RLock()
        tag = hashlib.sha256(service.encode("utf-8")).hexdigest()[:16]
        self._lock_path = default_keystore_path().with_name(f"keyring-{tag}")

    def __repr__(self) -> str:
        return f"KeyringKeyStore(service={self.service!r})"

    def __str__(self) -> str:
        return f"the system keyring (service {self.service!r})"

    # --- KeyBackend -----------------------------------------------------------------

    def key_names(self) -> List[str]:
        names: List[str] = []
        for part in range(self._MAX_PARTS):
            raw = self._get(f"{self._INDEX}:{part}")
            if raw is None:
                break
            try:
                listed = json.loads(raw)
            except ValueError:
                listed = None
            if not isinstance(listed, list):
                raise KeyStoreError(f"the keyring's key index for {self.service!r} is corrupted")
            names.extend(name for name in listed if isinstance(name, str))
        return sorted(set(names))

    def find_key(self, name: str) -> Optional[bytes]:
        record = self._record(name)
        return None if record is None else record.current

    def get_key(self, name: str) -> bytes:
        key = self.find_key(name)
        if key is None:
            raise KeyNotFoundError(f"key {name!r} is not in {self}", name)
        return key

    def decryption_keys(self) -> List[bytes]:
        entries = [(_KEY_PREFIX + name, name) for name in self.key_names()]

        def decode(_entry: str, name: Any) -> _KeyRecord:
            record = self._record(name)
            if record is None:
                raise KeyStoreError(f"key {name!r} is listed but missing from {self}")
            return record

        return _usable_keys(entries, decode)

    def ensure_key(self, name: str, *, rng: Optional[Random] = None) -> bytes:
        validate_key_name(name)
        with self._locked():
            record = self._record(name)
            if record is None:
                self._write_record(name, _KeyRecord(_new_key(rng), ()))
                record = self._record(name)
                assert record is not None
            self._index_add(name)
            return record.current

    def rotate_key(self, name: str, *, rng: Optional[Random] = None) -> bytes:
        validate_key_name(name)
        with self._locked():
            key = _new_key(rng)
            main = self._main(name)
            if main is None:
                self._write_record(name, _KeyRecord(key, ()))
            else:
                current, first, following = main
                # Store the old key in a new slot first, then switch: a failure
                # in between leaves the old key current, so nothing is lost.
                self._set(self._retired_user(name, following), _b64(current))
                self._set_main(name, key, first, following + 1)
            self._index_add(name)
            return key

    def delete_key(self, name: str) -> None:
        with self._locked():
            main = self._main(name)
            if main is None and name not in self.key_names():
                raise KeyNotFoundError(f"key {name!r} is not in {self}", name)
            if main is not None:
                # The main entry goes first: without it, the slots are unreachable.
                self._delete(_KEY_PREFIX + name)
                for index in range(main[1], main[2]):
                    self._delete(self._retired_user(name, index))
            self._write_index([n for n in self.key_names() if n != name])

    def export_key(self, name: str) -> Dict[str, Dict[str, Any]]:
        record = self._record(name)
        if record is None:
            raise KeyNotFoundError(f"key {name!r} is not in {self}", name)
        return {_KEY_PREFIX + name: _key_entry(record)}

    def import_keys(
        self, keys: Mapping[str, Any], *, overwrite: bool = False, name: Optional[str] = None
    ) -> ImportResult:
        incoming = parse_key_entries(keys, name)
        with self._locked():
            # Look every incoming key up directly: the index may have missed one.
            current = {
                entry: _key_entry(record)
                for entry in incoming
                if (record := self._record(entry[len(_KEY_PREFIX) :])) is not None
            }
            result = _plan_import(current, incoming, overwrite, lambda _entry, raw: raw, "key")
            for entry in result.added + result.replaced:
                self._write_record(entry[len(_KEY_PREFIX) :], _parse_key_record(entry, incoming[entry]))
            for entry in result.added + result.unchanged + result.replaced:
                self._index_add(entry[len(_KEY_PREFIX) :])
        return result

    # --- storage --------------------------------------------------------------------

    @staticmethod
    def _retired_user(name: str, index: int) -> str:
        return f"{_KEY_PREFIX}{name}:retired:{index}"

    def _main(self, name: str) -> Optional[Tuple[bytes, int, int]]:
        """The current key and the retired slot range ``[first, next)``, or ``None``."""
        raw = self._get(_KEY_PREFIX + name)
        if raw is None:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        span = data.get("retired") if isinstance(data, dict) else None
        if (
            not isinstance(span, list)
            or len(span) != 2
            or not all(isinstance(n, int) and not isinstance(n, bool) for n in span)
            or not 0 <= span[0] <= span[1] <= span[0] + self._MAX_RETIRED
        ):
            raise KeyStoreError(f"key {name!r} in {self} is corrupted")
        assert isinstance(data, dict)
        return _decode_secret(_KEY_PREFIX + name, data.get("secret")), span[0], span[1]

    def _record(self, name: str) -> Optional[_KeyRecord]:
        main = self._main(name)
        if main is None:
            return None
        current, first, following = main
        retired = []
        for index in range(first, following):
            value = self._get(self._retired_user(name, index))
            if value is None:
                raise KeyStoreError(f"a retired key of {name!r} is missing from {self}")
            retired.append(_decode_secret(_KEY_PREFIX + name, value))
        return _KeyRecord(current, tuple(reversed(retired)))  # newest first

    def _write_record(self, name: str, record: _KeyRecord) -> None:
        """Store ``record`` in fresh slots, switch the main entry, then drop old slots."""
        old = self._main(name)
        first = 0 if old is None else old[2]
        retired = list(reversed(record.retired))  # oldest first
        for offset, key in enumerate(retired):
            self._set(self._retired_user(name, first + offset), _b64(key))
        self._set_main(name, record.current, first, first + len(retired))
        if old is not None:
            for index in range(old[1], old[2]):
                self._delete(self._retired_user(name, index))

    def _set_main(self, name: str, key: bytes, first: int, following: int) -> None:
        self._set(_KEY_PREFIX + name, json.dumps({"secret": _b64(key), "retired": [first, following]}))

    def _index_add(self, name: str) -> None:
        names = self.key_names()
        if name not in names:
            self._write_index(names + [name])

    def _write_index(self, names: List[str]) -> None:
        parts: List[List[str]] = [[]]
        for name in sorted(set(names)):
            if parts[-1] and len(json.dumps(parts[-1] + [name])) > self._INDEX_PART_CHARS:
                parts.append([])
            parts[-1].append(name)
        for index, part in enumerate(parts):
            self._set(f"{self._INDEX}:{index}", json.dumps(part))
        index = len(parts)
        while index < self._MAX_PARTS and self._get(f"{self._INDEX}:{index}") is not None:
            self._delete(f"{self._INDEX}:{index}")
            index += 1

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialise changes across threads and processes."""
        with self._thread_lock, _file_lock(self._lock_path):
            yield

    def _get(self, user: str) -> Optional[str]:
        value = self._call("read", self._keyring.get_password, self.service, user)
        return value if isinstance(value, str) else None

    def _set(self, user: str, value: str) -> None:
        self._call("write", self._keyring.set_password, self.service, user, value)

    def _delete(self, user: str) -> None:
        try:
            self._keyring.delete_password(self.service, user)
        except self._delete_error:
            pass  # already gone
        except Exception as exc:
            raise KeyStoreError(f"cannot delete from {self}: {type(exc).__name__}: {exc}") from None

    def _call(self, what: str, function: Any, *args: Any) -> Any:
        try:
            return function(*args)
        except Exception as exc:  # keyring backends raise their own exception types
            raise KeyStoreError(f"cannot {what} {self}: {type(exc).__name__}: {exc}") from None


def open_key_backend(
    kind: str, *, path: Optional[PathLike] = None, service: Optional[str] = None
) -> KeyBackend:
    """Open a key backend by name.

    - ``"json"``: the key store file ``path`` (default: the default key store);
    - ``"dpapi"``: the DPAPI key file ``path`` (default: ``keys-dpapi.json`` next
      to the default key store), Windows only;
    - ``"keyring"``: the system keyring, with the credentials under ``service``
      (default ``"yace-codec"``).
    """
    if kind in ("json", "dpapi"):
        if service is not None:
            raise TypeError(f"the {kind} backend takes a path, not a service")
        if kind == "json":
            return KeyStore.default() if path is None else KeyStore(path)
        return DpapiKeyStore(path)
    if kind == "keyring":
        if path is not None:
            raise TypeError("the keyring backend takes a service, not a path")
        return KeyringKeyStore("yace-codec" if service is None else service)
    raise KeyStoreError(f"unknown key backend {kind!r}; choose one of {', '.join(BACKENDS)}")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

"""Persistent storage for substitution tables.

A key store is a JSON file in the format of the original ``encodings.json``.
Every token depends on the tables in it, so treat the file like a key: back it
up, and share it (or a single family, see :meth:`KeyStore.export_family`) only
with people who should be able to decode your tokens.

Writes are atomic (temporary file, then rename) and serialised through a
``<keystore>.lock`` file, so concurrent processes never lose each other's tables.
"""

from __future__ import annotations

import contextlib
import itertools
import json
import os
import secrets
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path
from random import Random
from typing import Any, Dict, Iterator, List, Mapping, NamedTuple, Optional, Tuple, Union

from .errors import KeyStoreError, TableNotFoundError
from .tables import Table, parse_table_name, table_name, validate_family

__all__ = ["ENV_VAR", "Family", "ImportResult", "KeyStore", "default_keystore_path"]

#: Environment variable that overrides the default key store location.
ENV_VAR = "YACE_CODEC_KEYSTORE"

_APP_DIR = "yace-codec"
_FILE_NAME = "keystore.json"
_LOCK_TIMEOUT = 30.0
_RETRY_DELAY = 0.05
_RETRIES = 40  # Windows briefly denies access while a file is being replaced.

_SYSTEM_RANDOM = secrets.SystemRandom()

PathLike = Union[str, "os.PathLike[str]"]


def default_keystore_path() -> Path:
    """Return the key store location used when none is given, as an absolute path.

    ``$YACE_CODEC_KEYSTORE`` takes priority. Otherwise the per-user data
    directory is used: ``%APPDATA%\\yace-codec\\keystore.json`` on Windows,
    ``~/Library/Application Support/yace-codec/keystore.json`` on macOS, and
    ``$XDG_DATA_HOME/yace-codec/keystore.json`` (``~/.local/share`` by default)
    elsewhere.
    """
    override = os.environ.get(ENV_VAR)
    if override:
        return _absolute(override)
    try:
        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA")
            root = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
        elif sys.platform == "darwin":
            root = Path.home() / "Library" / "Application Support"
        else:
            xdg = os.environ.get("XDG_DATA_HOME", "")
            root = Path(xdg) if os.path.isabs(xdg) else Path.home() / ".local" / "share"
    except RuntimeError as exc:  # no home directory
        raise KeyStoreError(f"cannot find the default key store location: {exc}") from exc
    return _absolute(root / _APP_DIR / _FILE_NAME)


def _absolute(path: PathLike) -> Path:
    """Expand ``~`` and anchor ``path`` to the current directory once."""
    try:
        return Path(os.fspath(path)).expanduser().absolute()
    except RuntimeError as exc:  # e.g. "~nosuchuser/keystore.json"
        raise KeyStoreError(f"cannot expand key store path {os.fspath(path)!r}: {exc}") from exc


class Family(NamedTuple):
    """The layers of one family and code length that a key store holds."""

    name: str
    length: int
    layers: Tuple[int, ...]


class ImportResult(NamedTuple):
    """Table names affected by :meth:`KeyStore.import_tables`."""

    added: Tuple[str, ...]
    unchanged: Tuple[str, ...]
    replaced: Tuple[str, ...]


class KeyStore:
    """Substitution tables kept in a JSON file, or in memory (:meth:`in_memory`).

    A relative ``path`` is resolved against the current directory when the
    store is created. The file is created on the first write and re-read
    whenever it changes on disk, so tables added by other processes become
    visible.
    """

    def __init__(self, path: PathLike) -> None:
        self._setup(_absolute(path))

    @classmethod
    def default(cls) -> KeyStore:
        """Open the key store at :func:`default_keystore_path`."""
        return cls(default_keystore_path())

    @classmethod
    def in_memory(cls) -> KeyStore:
        """Create an empty store that is never written to disk."""
        store = cls.__new__(cls)
        store._setup(None)
        return store

    def _setup(self, path: Optional[Path]) -> None:
        self._path = path
        self._data: Optional[Dict[str, Any]] = None if path is not None else {}
        self._signature: Optional[Tuple[int, int, int]] = None
        self._cache: Dict[str, Table] = {}
        self._lock = threading.RLock()

    @property
    def path(self) -> Optional[Path]:
        """The backing file (absolute), or ``None`` for an in-memory store."""
        return self._path

    def __repr__(self) -> str:
        if self._path is None:
            return "KeyStore.in_memory()"
        return f"KeyStore({str(self._path)!r})"

    def __contains__(self, name: object) -> bool:
        with self._lock:
            return name in self._loaded()

    def __len__(self) -> int:
        with self._lock:
            return len(self._loaded())

    def table_names(self) -> List[str]:
        """Return the names of all stored tables, sorted."""
        with self._lock:
            return sorted(self._loaded())

    def families(self) -> List[Family]:
        """Group the stored tables by family name and code length."""
        groups: Dict[Tuple[str, int], List[int]] = {}
        for name in self.table_names():
            parsed = parse_table_name(name)
            if parsed is not None:
                family, length, layer = parsed
                groups.setdefault((family, length), []).append(layer)
        return [
            Family(family, length, tuple(sorted(layers)))
            for (family, length), layers in sorted(groups.items())
        ]

    def find(self, name: str) -> Optional[Table]:
        """Return table ``name``, or ``None`` if the store does not have it.

        Raises :class:`~yace_codec.errors.KeyStoreError` if the stored table is
        malformed.
        """
        with self._lock:
            data = self._loaded()
            table = self._cache.get(name)
            if table is None:
                if name not in data:
                    return None
                table = self._cache[name] = Table.from_dict(name, data[name])
            return table

    def get(self, name: str) -> Table:
        """Return table ``name``.

        Raises :class:`~yace_codec.errors.TableNotFoundError` if it is missing.
        """
        table = self.find(name)
        if table is None:
            raise TableNotFoundError(
                f"table {name!r} is not in {self._describe()}. Decode with the key store "
                "that encoded the token, or import the tables first "
                "(yace-codec tables import).",
                name,
            )
        return table

    def ensure_tables(
        self, family: str, length: int, iterations: int, *, rng: Optional[Random] = None
    ) -> List[Table]:
        """Return the tables ``<family>-<length>:1`` to ``:<iterations>``.

        Missing tables are generated with ``rng`` (default: the operating
        system's cryptographic random source) and saved. Existing tables are
        never changed.
        """
        validate_family(family)
        names = [table_name(family, length, layer) for layer in range(1, iterations + 1)]
        with self._lock:
            loaded = self._loaded()
            if any(name not in loaded for name in names):
                with self._editing() as data:
                    for name in names:
                        if name not in data:
                            data[name] = Table.generate(name, rng or _SYSTEM_RANDOM).to_dict()
            return [self.get(name) for name in names]

    def export_family(self, family: str) -> Dict[str, Dict[str, Any]]:
        """Return every table of ``family`` (all code lengths) as key-store JSON.

        The result can be saved with :func:`json.dump` and loaded elsewhere with
        :meth:`import_tables`.
        """
        with self._lock:
            names = [name for name in self.table_names() if family_of(name) == family]
            if not names:
                raise TableNotFoundError(f"no tables for family {family!r} in {self._describe()}", family)
            return {name: self.get(name).to_dict() for name in names}

    def import_tables(
        self,
        tables: Mapping[str, Any],
        *,
        overwrite: bool = False,
        family: Optional[str] = None,
    ) -> ImportResult:
        """Add tables (e.g. the output of :meth:`export_family`) to this store.

        With ``family``, only that family's tables are imported and any others
        in ``tables`` are ignored. Use it for files from other people: a file
        could otherwise add tables for families you use, such as ``default``,
        so that its sender can decode your future tokens.

        All tables are validated first, and nothing is written unless every
        table can be imported. A table that already exists with different codes
        is a conflict: replacing it makes tokens encoded with the old table
        undecodable, so it is only replaced when ``overwrite`` is true. If
        nothing would change, the file is not touched.
        """
        if not isinstance(tables, Mapping):
            raise KeyStoreError("expected a JSON object that maps table names to tables")
        if family is not None:
            tables = {name: raw for name, raw in tables.items() if family_of(name) == family}
            if not tables:
                raise KeyStoreError(f"no tables for family {family!r} to import")
        incoming = {name: Table.from_dict(name, raw).to_dict() for name, raw in tables.items()}
        with self._lock:
            result = _plan_import(self._loaded(), incoming, overwrite)
            if result.added or result.replaced:
                with self._editing() as data:
                    # Plan again under the file lock, against the latest file.
                    result = _plan_import(data, incoming, overwrite)
                    for name in result.added + result.replaced:
                        data[name] = incoming[name]
        return result

    def reload(self) -> None:
        """Forget cached tables and re-read the file on next use."""
        with self._lock:
            if self._path is not None:
                self._data = None
                self._cache.clear()

    def _describe(self) -> str:
        return "the in-memory key store" if self._path is None else f"key store '{self._path}'"

    def _loaded(self) -> Dict[str, Any]:
        if self._path is not None:
            signature = _signature(self._path)
            if self._data is None or signature != self._signature:
                self._data = _read_json(self._path)
                self._signature = signature
                self._cache.clear()
        assert self._data is not None
        return self._data

    @contextlib.contextmanager
    def _editing(self) -> Iterator[Dict[str, Any]]:
        """Yield the current tables for changes, then save them.

        For file stores the data is re-read under the lock, so tables written
        by other processes in the meantime are kept. If the block raises,
        nothing is saved.
        """
        if self._path is None:
            data = dict(self._loaded())
            yield data
        else:
            # Lock and write the real file, so a symbolic link stays a link.
            target = Path(os.path.realpath(self._path))
            with _file_lock(target):
                data = _read_json(target)
                before = dict(data)
                yield data
                if data != before:
                    _write_json(target, data)
                self._signature = _signature(self._path)
        self._data = data
        self._cache.clear()


def family_of(name: object) -> Optional[str]:
    """Return the family part of table name ``name``, or ``None`` if it is not one."""
    parsed = parse_table_name(name) if isinstance(name, str) else None
    return parsed[0] if parsed else None


def _plan_import(
    current: Mapping[str, Any], incoming: Mapping[str, Dict[str, Any]], overwrite: bool
) -> ImportResult:
    """Sort incoming tables into added/unchanged/replaced, or raise on conflicts."""
    added: List[str] = []
    unchanged: List[str] = []
    replaced: List[str] = []
    conflicts: List[str] = []
    for name, table in incoming.items():
        if name not in current:
            added.append(name)
        elif _normalised(name, current[name]) == table:
            unchanged.append(name)
        elif overwrite:
            replaced.append(name)
        else:
            conflicts.append(name)
    if conflicts:
        raise KeyStoreError(
            f"{len(conflicts)} table(s) already exist with different codes: "
            f"{', '.join(sorted(conflicts))}. Replacing them makes tokens encoded "
            "with the old tables undecodable; use overwrite=True (CLI: --overwrite) "
            "to replace them anyway."
        )
    return ImportResult(tuple(added), tuple(unchanged), tuple(replaced))


def _normalised(name: str, raw: Any) -> Optional[Dict[str, Any]]:
    try:
        return Table.from_dict(name, raw).to_dict()
    except KeyStoreError:
        return None


def _signature(path: Path) -> Optional[Tuple[int, int, int]]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_ino, st.st_size, st.st_mtime_ns)


def _read_json(path: Path) -> Dict[str, Any]:
    if path.is_dir():
        raise KeyStoreError(f"key store '{path}' is a directory")
    for attempt in itertools.count():
        try:
            raw = path.read_bytes()
            break
        except FileNotFoundError:
            return {}
        except PermissionError as exc:
            if sys.platform != "win32" or attempt >= _RETRIES:
                raise KeyStoreError(f"cannot read key store '{path}': {exc}") from exc
            time.sleep(_RETRY_DELAY)
        except OSError as exc:
            raise KeyStoreError(f"cannot read key store '{path}': {exc}") from exc
    if not raw.strip():
        return {}
    try:
        # json.loads detects UTF-8 (with or without a BOM), UTF-16, and UTF-32.
        data = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise KeyStoreError(
            f"key store '{path}' is not valid JSON ({exc}); it was left unchanged"
        ) from exc
    if not isinstance(data, dict):
        raise KeyStoreError(f"key store '{path}' must contain a JSON object")
    return data


def _write_json(path: Path, data: Mapping[str, Any]) -> None:
    payload = json.dumps(data, ensure_ascii=True).encode("ascii")
    try:
        links = os.stat(path).st_nlink
    except FileNotFoundError:
        links = 1
    except OSError as exc:
        raise KeyStoreError(f"cannot write key store '{path}': {exc}") from exc
    if links > 1:
        raise KeyStoreError(
            f"key store '{path}' has {links} hard links, and saving it would separate "
            "this copy from the others; use a symbolic link instead"
        )
    try:
        fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    except OSError as exc:
        raise KeyStoreError(f"cannot write key store '{path}': {exc}") from exc
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        for attempt in itertools.count():
            try:
                _swap_in(tmp, path)
                break
            except PermissionError:
                if sys.platform != "win32" or attempt >= _RETRIES:
                    raise
                time.sleep(_RETRY_DELAY)
    except BaseException as exc:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        if isinstance(exc, OSError):
            raise KeyStoreError(f"cannot write key store '{path}': {exc}") from exc
        raise


@contextlib.contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    """Hold an exclusive lock on ``<path>.lock``.

    A separate lock file is used because the key store itself is replaced on
    every write. The lock file is left in place.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = _open_lock(path)
    except OSError as exc:
        raise KeyStoreError(f"cannot lock key store '{path}': {exc}") from exc
    try:
        _lock_fd(fd, path)
        try:
            yield
        finally:
            _unlock_fd(fd)
    finally:
        os.close(fd)


def _open_lock(path: Path) -> int:
    lock = f"{path}.lock"
    if sys.platform == "win32":
        return os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    except PermissionError:
        # Another user's lock file in a shared directory: flock also works on
        # a read-only descriptor.
        return os.open(lock, os.O_RDONLY)
    try:
        st = os.stat(path)
    except OSError:
        return fd
    # Give the lock the key store's permissions and group, so everyone who may
    # write a group-shared key store can also take its lock.
    with contextlib.suppress(OSError):
        os.fchmod(fd, stat.S_IMODE(st.st_mode) & 0o666)
    with contextlib.suppress(OSError):
        os.fchown(fd, -1, st.st_gid)
    return fd


if sys.platform == "win32":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ReplaceFileW = _kernel32.ReplaceFileW
    _ReplaceFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
    )
    _ReplaceFileW.restype = wintypes.BOOL
    _ERROR_UNABLE_TO_MOVE_REPLACEMENT = 1176

    def _swap_in(tmp: str, path: Path) -> None:
        """Move ``tmp`` over ``path``, keeping the existing file's ACL and attributes.

        ``os.replace`` would give the file the folder's inherited permissions
        instead, undoing any hardening of the key store's ACL.
        """
        if not path.exists():
            os.replace(tmp, path)
            return
        if _ReplaceFileW(str(path), tmp, None, 0, None, None):
            return
        error = ctypes.get_last_error()
        if error == _ERROR_UNABLE_TO_MOVE_REPLACEMENT and not path.exists():
            # The old file is gone but the new one kept its temporary name.
            os.replace(tmp, path)
            return
        exc = ctypes.WinError(error)
        if isinstance(exc, PermissionError):  # sharing violation: the caller retries
            raise exc
        # Some file systems do not support ReplaceFileW; a plain replace still
        # keeps the data safe.
        os.replace(tmp, path)

    def _lock_fd(fd: int, path: Path) -> None:
        deadline = time.monotonic() + _LOCK_TIMEOUT
        while True:
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise KeyStoreError(f"timed out waiting for the lock on key store '{path}'") from None
                time.sleep(_RETRY_DELAY)

    def _unlock_fd(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _swap_in(tmp: str, path: Path) -> None:
        """Move ``tmp`` over ``path``, keeping the existing file's mode and owner.

        New files keep the 0600 mode that :func:`tempfile.mkstemp` gives them.
        """
        try:
            st = os.stat(path)
        except FileNotFoundError:
            st = None
        if st is not None:
            os.chmod(tmp, stat.S_IMODE(st.st_mode))
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except OSError:
                # Only root can give a file away; members of the group can still
                # keep the group, so a group-shared key store stays shared.
                with contextlib.suppress(OSError):
                    os.chown(tmp, -1, st.st_gid)
        os.replace(tmp, path)

    def _lock_fd(fd: int, path: Path) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError as exc:
            raise KeyStoreError(f"cannot lock key store '{path}': {exc}") from exc

    def _unlock_fd(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

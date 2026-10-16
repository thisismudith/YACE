"""Writing output files safely: complete or not at all, with the right permissions."""

from __future__ import annotations

import contextlib
import errno
import os
import stat
import sys
import tempfile
import time
from typing import BinaryIO, Iterator, Literal, Optional, Union

from ._winsec import restrict_to_owner

PathLike = Union[str, "os.PathLike[str]"]
#: Who may read a written file:
#: - "normal" (encrypted output, tokens): an existing file's mode, else the default
#:   for new files;
#: - "private" (decrypted data): an existing file's mode, else only you;
#: - "secret" (exported keys and tables): always only you.
#: "Only you" is mode 0600 on POSIX and an owner-only ACL on Windows. On Windows
#: a "normal" file gets its folder's inherited permissions.
Access = Literal["normal", "private", "secret"]


def _read_umask() -> int:
    """The process umask, read once at import (setting it is not thread-safe)."""
    if sys.platform == "win32":
        return 0o022
    umask = os.umask(0o022)
    os.umask(umask)
    return umask


_UMASK = _read_umask()
_REPLACE_RETRIES = 40  # Windows briefly denies access while another program reads the file
_RETRY_DELAY = 0.05


@contextlib.contextmanager
def atomic_output(target: PathLike, access: Access = "normal") -> Iterator[BinaryIO]:
    """Yield a binary file that replaces ``target`` only if the block succeeds.

    Data goes to a temporary file in the same folder, which is renamed over
    ``target`` at the end, so ``target`` never holds partial output. A symbolic
    link is followed (the file it points to is replaced). Targets that are not
    regular files, such as ``os.devnull``, are written directly. Errors name
    ``target``, not the temporary file.
    """
    name = os.fspath(target)
    try:
        existing: Optional[os.stat_result] = os.stat(name)  # follows links, e.g. /dev/stdout
    except OSError:
        existing = None
    if existing is not None and stat.S_ISDIR(existing.st_mode):
        raise IsADirectoryError(errno.EISDIR, "is a directory", name)
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        # A pipe, terminal, or device (such as os.devnull): write to it directly.
        with open(name, "wb") as fh:
            yield fh
        return
    path = os.path.realpath(name)
    directory, base = os.path.split(path)
    try:
        fd, tmp = tempfile.mkstemp(prefix=f".{base}.", suffix=".part", dir=directory)
    except OSError as exc:
        reason = "the folder does not exist" if isinstance(exc, FileNotFoundError) else exc.strerror
        raise OSError(exc.errno, reason, name) from None
    try:
        fh = os.fdopen(fd, "wb")
    except BaseException:
        os.close(fd)
        _remove(tmp)
        raise
    try:
        with fh:
            if access != "normal":
                _restrict(tmp)
            yield fh
        if sys.platform != "win32":
            os.chmod(tmp, _mode(access, existing))
        _replace(tmp, path, name)
    except BaseException:
        _remove(tmp)
        raise


def _restrict(tmp: str) -> None:
    """Owner-only ACL on Windows; file systems without ACLs (FAT, some shares) keep theirs."""
    with contextlib.suppress(OSError):
        restrict_to_owner(tmp)


def _remove(tmp: str) -> None:
    with contextlib.suppress(OSError):
        os.unlink(tmp)


def _mode(access: Access, existing: Optional[os.stat_result]) -> int:
    if access == "secret":
        return 0o600
    if existing is not None:
        return stat.S_IMODE(existing.st_mode)
    if access == "private":
        return 0o600
    return 0o666 & ~_UMASK  # like a normally created file


def _replace(tmp: str, path: str, name: str) -> None:
    for attempt in range(_REPLACE_RETRIES + 1):
        try:
            os.replace(tmp, path)
            return
        except PermissionError as exc:
            if sys.platform != "win32" or attempt == _REPLACE_RETRIES:
                raise PermissionError(exc.errno, exc.strerror, name) from None
            time.sleep(_RETRY_DELAY)
        except OSError as exc:
            raise OSError(exc.errno, exc.strerror, name) from None

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
    path = os.path.realpath(name)
    if os.path.isdir(path):
        raise IsADirectoryError(errno.EISDIR, "is a directory", name)
    try:
        existing: Optional[os.stat_result] = os.stat(path)
    except OSError:
        existing = None
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        with open(path, "wb") as fh:
            yield fh
        return
    directory, base = os.path.split(path)
    try:
        fd, tmp = tempfile.mkstemp(prefix=f".{base}.", suffix=".part", dir=directory)
    except OSError as exc:
        reason = "the folder does not exist" if isinstance(exc, FileNotFoundError) else exc.strerror
        raise OSError(exc.errno, reason, name) from None
    try:
        if access != "normal":
            restrict_to_owner(tmp)  # Windows; mkstemp already gives 0600 on POSIX
        with os.fdopen(fd, "wb") as fh:
            yield fh
        if sys.platform != "win32":
            os.chmod(tmp, _mode(access, existing))
        _replace(tmp, path, name)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _mode(access: Access, existing: Optional[os.stat_result]) -> int:
    if access == "secret":
        return 0o600
    if existing is not None:
        return stat.S_IMODE(existing.st_mode)
    if access == "private":
        return 0o600
    umask = os.umask(0)
    os.umask(umask)
    return 0o666 & ~umask  # like a normally created file


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

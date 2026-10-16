"""Command-line interface: ``yace-codec`` (or ``python -m yace_codec``)."""

from __future__ import annotations

import argparse
import contextlib
import errno
import getpass
import io
import json
import os
import stat
import sys
import tempfile
import warnings
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, Iterator, List, Optional, Sequence, Union, cast

from . import __version__
from ._algorithms import DEFAULT_ALGORITHM, algorithms
from .codec import DEFAULT_FAMILY, DEFAULT_ITERATIONS, DEFAULT_LENGTH, Codec
from .errors import EncodingError, KeyStoreError, UnsupportedCharacterError, YaceError
from .keybackends import BACKENDS, KeyBackend, open_key_backend
from ._winsec import restrict_to_owner
from .keystore import ENV_VAR, KeyStore, family_of

PROG = "yace-codec"
#: Deprecated environment variables that supply the secret token for --token.
#: The first one that is set wins; YACE_CODEC_PASSWORD is the 0.2.0 name.
TOKEN_ENV_VAR = "YACE_CODEC_TOKEN"
PASSWORD_ENV_VAR = "YACE_CODEC_PASSWORD"


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the command line and return the exit status."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "text", None) is not None and args.input != "-":
        parser.error("give either INPUT or --text, not both")
    handler: Callable[[argparse.Namespace], int] = args.handler
    try:
        return handler(args)
    except UnsupportedCharacterError as exc:
        shown = ", ".join(f"{ascii(ch)} (U+{ord(ch):04X})" for ch in exc.characters[:10])
        if len(exc.characters) > 10:
            shown += f" and {len(exc.characters) - 10} more"
        return _fail(f"table {exc.table_name!r} cannot encode {shown}; re-run with --binary")
    except UnicodeDecodeError:
        return _fail("input is not valid UTF-8 text; re-run with --binary")
    except YaceError as exc:
        return _fail(str(exc))
    except OSError as exc:
        if isinstance(exc, BrokenPipeError):
            _silence_stdout()
            return 1
        target = f"{exc.filename}: " if exc.filename else ""
        return _fail(f"{target}{exc.strerror or exc}")
    except MemoryError:
        return _fail("not enough memory")
    except KeyboardInterrupt:
        return 130


def _build_parser() -> argparse.ArgumentParser:
    store = argparse.ArgumentParser(add_help=False)
    store.add_argument(
        "-k",
        "--keystore",
        metavar="PATH",
        help=f"key store file (default: ${ENV_VAR} if set, else a file in your user data "
        "directory; see 'yace-codec tables path')",
    )

    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Encode and decode text with YACE substitution tables (obfuscation), "
        "or encrypt and decrypt it with your own secret token or a stored key (encryption).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(title="commands", metavar="COMMAND")
    commands.required = True

    enc = commands.add_parser("encode", parents=[store], help="encode text or a file")
    enc.add_argument("input", nargs="?", default="-", help="file to encode (default: stdin)")
    enc.add_argument("-t", "--text", help="encode this string instead of INPUT")
    enc.add_argument("-o", "--output", metavar="PATH", help="write the token here (default: stdout)")
    enc.add_argument(
        "-n", "--name", default=DEFAULT_FAMILY, help="table family name (default: %(default)s)"
    )
    enc.add_argument(
        "-l", "--length", type=int, default=DEFAULT_LENGTH,
        help="code length, 2-62 (default: %(default)s)",
    )
    enc.add_argument(
        "-i", "--iterations", type=int, default=DEFAULT_ITERATIONS,
        help="number of encoding layers (default: %(default)s)",
    )
    enc.add_argument(
        "-b", "--binary", action="store_true",
        help="encode the input as raw bytes (any file type or text encoding)",
    )
    enc.set_defaults(handler=_cmd_encode)

    dec = commands.add_parser("decode", parents=[store], help="decode a token")
    dec.add_argument("input", nargs="?", default="-", help="file holding the token (default: stdin)")
    dec.add_argument("-t", "--text", help="decode this token string instead of INPUT")
    dec.add_argument("-o", "--output", metavar="PATH", help="write the result here (default: stdout)")
    dec.add_argument(
        "-b", "--binary", action="store_true",
        help="the token was made with 'encode --binary'; output the raw bytes",
    )
    dec.set_defaults(handler=_cmd_decode)

    backend = argparse.ArgumentParser(add_help=False)
    backend.add_argument(
        "--key-backend", choices=BACKENDS, default="json",
        help="where secret keys live: json (the key store file, default), dpapi "
        "(Windows, keys encrypted for your account), or keyring (system keyring)",
    )

    def add_secret_options(command: argparse.ArgumentParser, encrypting: bool) -> None:
        secret = command.add_mutually_exclusive_group()
        if encrypting:
            secret.add_argument(
                "--key", metavar="NAME",
                help="stored secret key to use (default: default; created on first use)",
            )
        secret.add_argument(
            "-p", "--token", "--password", dest="token", action="store_true",
            help="use your own secret token instead of a stored key (asked for, hidden)",
        )
        secret.add_argument(
            "--token-file", metavar="PATH",
            help="read your secret token from this file (one trailing newline is ignored)",
        )
        secret.add_argument(
            "--token-stdin", action="store_true",
            help="read your secret token from the first line of standard input",
        )
        command.add_argument(
            "--aad", metavar="TEXT",
            help="associated data: context (such as a record id) that must match to decrypt",
        )

    encr = commands.add_parser(
        "encrypt", parents=[store, backend], help="encrypt text or a file (any size)"
    )
    encr.add_argument("input", nargs="?", default="-", help="file to encrypt (default: stdin)")
    encr.add_argument("-t", "--text", help="encrypt this string instead of INPUT")
    encr.add_argument("-o", "--output", metavar="PATH", help="write the result here (default: stdout)")
    add_secret_options(encr, encrypting=True)
    encr.add_argument(
        "-a", "--algorithm", choices=[info.name for info in algorithms()], default=DEFAULT_ALGORITHM,
        help="encryption algorithm (default: %(default)s; see 'yace-codec algorithms')",
    )
    encr.add_argument(
        "-f", "--format", choices=("text", "bytes"), default="text",
        help="text: letters and digits (default); bytes: raw binary, about 27%% smaller",
    )
    encr.set_defaults(handler=_cmd_encrypt)

    decr = commands.add_parser(
        "decrypt", parents=[store, backend], help="decrypt the output of encrypt (any format)"
    )
    decr.add_argument("input", nargs="?", default="-", help="file to decrypt (default: stdin)")
    decr.add_argument("-t", "--text", help="decrypt this string instead of INPUT")
    decr.add_argument(
        "-o", "--output", metavar="PATH",
        help="write the result here, only if decryption succeeds (default: stdout, which may "
        "show part of the data before an error is found)",
    )
    add_secret_options(decr, encrypting=False)
    decr.add_argument(
        "--max-age", type=float, metavar="SECONDS", help="reject data encrypted longer ago than this"
    )
    decr.set_defaults(handler=_cmd_decrypt)

    algs = commands.add_parser("algorithms", help="list the encryption algorithms")
    algs.set_defaults(handler=_cmd_algorithms)

    keys = commands.add_parser("keys", help="manage and share secret keys for encrypt/decrypt")
    key_actions = keys.add_subparsers(title="actions", metavar="ACTION")
    key_actions.required = True
    key_list = key_actions.add_parser("list", parents=[store, backend], help="list secret key names")
    key_list.set_defaults(handler=_cmd_keys_list)
    key_rotate = key_actions.add_parser(
        "rotate", parents=[store, backend],
        help="give a key a new value; the old one still decrypts older data",
    )
    key_rotate.add_argument("name", help="key name")
    key_rotate.set_defaults(handler=_cmd_keys_rotate)
    key_delete = key_actions.add_parser(
        "delete", parents=[store, backend], help="delete a key (data encrypted with it is lost)"
    )
    key_delete.add_argument("name", help="key name")
    key_delete.add_argument("--yes", action="store_true", help="confirm the deletion")
    key_delete.set_defaults(handler=_cmd_keys_delete)
    key_export = key_actions.add_parser(
        "export", parents=[store, backend], help="export a secret key as JSON (keep the file private)"
    )
    key_export.add_argument("name", help="key name")
    key_export.add_argument("-o", "--output", metavar="PATH", help="write here (default: stdout)")
    key_export.set_defaults(handler=_cmd_keys_export)
    key_import = key_actions.add_parser(
        "import", parents=[store, backend], help="import secret keys from JSON"
    )
    key_import.add_argument("file", help="JSON file from 'keys export' ('-' for stdin)")
    which_key = key_import.add_mutually_exclusive_group()
    which_key.add_argument("--name", metavar="NAME", help="import only this key")
    which_key.add_argument(
        "--all-keys", action="store_true", help="import every key in a file that holds several"
    )
    key_import.add_argument(
        "--overwrite", action="store_true",
        help="replace existing keys that differ (tokens made with them stop decrypting)",
    )
    key_import.set_defaults(handler=_cmd_keys_import)

    tables = commands.add_parser("tables", help="inspect and share key store tables")
    actions = tables.add_subparsers(title="actions", metavar="ACTION")
    actions.required = True
    path = actions.add_parser("path", parents=[store], help="print the key store location")
    path.set_defaults(handler=_cmd_path)
    listing = actions.add_parser("list", parents=[store], help="list table families")
    listing.set_defaults(handler=_cmd_list)
    export = actions.add_parser("export", parents=[store], help="export a family's tables as JSON")
    export.add_argument("name", help="family name")
    export.add_argument("-o", "--output", metavar="PATH", help="write here (default: stdout)")
    export.set_defaults(handler=_cmd_export)
    imp = actions.add_parser("import", parents=[store], help="import tables from a JSON file")
    imp.add_argument("file", help="JSON file from 'tables export' ('-' for stdin)")
    which = imp.add_mutually_exclusive_group()
    which.add_argument("--family", metavar="NAME", help="import only this family's tables")
    which.add_argument(
        "--all-families", action="store_true",
        help="import every table in a file that holds several families",
    )
    imp.add_argument(
        "--overwrite", action="store_true",
        help="replace existing tables that differ (tokens made with them stop decoding)",
    )
    imp.set_defaults(handler=_cmd_import)
    return parser


def _keystore(args: argparse.Namespace) -> KeyStore:
    return KeyStore(args.keystore) if args.keystore else KeyStore.default()


def _read_input(args: argparse.Namespace) -> bytes:
    if args.text is not None:
        # The argument's original bytes: on POSIX, bytes that are not valid
        # UTF-8 arrive as surrogates, which os.fsencode turns back into bytes.
        return os.fsencode(args.text)
    if args.input == "-":
        return sys.stdin.buffer.read()
    return _read_file(args.input)


def _read_file(name: str) -> bytes:
    if os.path.isdir(name):
        raise IsADirectoryError(errno.EISDIR, "is a directory", name)
    return Path(name).read_bytes()


def _write_output(target: Optional[str], data: bytes, *, access: str = "normal") -> None:
    with _output_stream(target, access=access) as fh:
        fh.write(data)


def _cmd_encode(args: argparse.Namespace) -> int:
    codec = Codec(_keystore(args))
    raw = _read_input(args)
    options = dict(length=args.length, iterations=args.iterations)
    if args.binary:
        token = codec.encode_bytes(raw, args.name, **options)
    else:
        token = codec.encode(raw.decode("utf-8"), args.name, **options)
    _write_output(args.output, f"{token}\n".encode("ascii"))
    return 0


def _cmd_decode(args: argparse.Namespace) -> int:
    codec = Codec(_keystore(args))
    raw = _read_input(args)
    if args.binary:
        result = codec.decode_bytes(raw)
    else:
        result = codec.decode(raw).encode("utf-8")
    _write_output(args.output, result)
    return 0


def _cmd_path(args: argparse.Namespace) -> int:
    _echo(str(_keystore(args).path))
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    store = _keystore(args)
    families = store.families()
    if not families:
        _echo(f"no tables in {store.path}", err=True)
        return 0
    rows: List[Dict[str, str]] = [
        {"name": f.name, "length": str(f.length), "layers": ",".join(map(str, f.layers))}
        for f in families
    ]
    width = max(len("NAME"), *(len(r["name"]) for r in rows))
    _echo(f"{'NAME':<{width}}  LENGTH  LAYERS")
    for r in rows:
        _echo(f"{r['name']:<{width}}  {r['length']:<6}  {r['layers']}")
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    tables = _keystore(args).export_family(args.name)
    payload = json.dumps(tables, indent=2, ensure_ascii=True) + "\n"
    _write_output(args.output, payload.encode("ascii"), access="secret")
    return 0


def _cmd_import(args: argparse.Namespace) -> int:
    raw = sys.stdin.buffer.read() if args.file == "-" else _read_file(args.file)
    try:
        # json.loads detects UTF-8 (with or without a BOM), UTF-16, and UTF-32,
        # so files saved by Windows PowerShell 5.1 work too.
        tables = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise KeyStoreError(f"{args.file} is not valid JSON ({exc})") from exc
    if isinstance(tables, dict) and args.family is None and not args.all_families:
        # A shared file could add tables for families you use, such as "default",
        # so that its sender can decode your future tokens: name the family you expect.
        families = sorted({f for f in map(family_of, tables) if f is not None})
        held = ", ".join(families) or "no valid tables"
        raise KeyStoreError(
            f"{args.file} holds tables for: {held}. Name the family you expect with "
            "--family NAME, or import everything with --all-families"
        )
    store = _keystore(args)
    result = store.import_tables(tables, overwrite=args.overwrite, family=args.family)
    for label, names in (("added", result.added), ("replaced", result.replaced)):
        for name in names:
            _echo(f"{label}: {name}", err=True)
    _echo(
        f"{len(result.added)} added, {len(result.unchanged)} unchanged, "
        f"{len(result.replaced)} replaced ({args.keystore or store.path})",
        err=True,
    )
    return 0


def _cmd_encrypt(args: argparse.Namespace) -> int:
    is_text = False
    if args.text is not None:
        raw = _read_input(args)
        with contextlib.suppress(UnicodeDecodeError):
            raw.decode("utf-8")
            is_text = True  # so Python's decrypt() returns str
    secret = _secret_token(args, confirm=True)
    codec = Codec(KeyStore.in_memory()) if secret is not None else _key_codec(args)
    with _input_stream(args) as src, _output_stream(args.output) as dst:
        codec.encrypt_stream(
            src, dst, None if secret is not None else args.key, token=secret,
            aad=_aad(args), algorithm=args.algorithm, output=args.format, text=is_text,
        )
        if args.format == "text":
            dst.write(b"\n")
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    secret = _secret_token(args)
    codec = Codec(KeyStore.in_memory()) if secret is not None else _key_codec(args)
    with _input_stream(args) as src, _output_stream(args.output, access="private") as dst:
        codec.decrypt_stream(src, dst, token=secret, aad=_aad(args), max_age=args.max_age)
    return 0


def _cmd_algorithms(args: argparse.Namespace) -> int:
    infos = algorithms()
    width = max(len(info.name) for info in infos)
    for info in infos:
        marks = ["default"] if info.default else []
        if not info.available:
            marks.append("not installed")
        suffix = f" [{', '.join(marks)}]" if marks else ""
        _echo(f"{info.name:<{width}}  {info.description}{suffix}")
    return 0


def _aad(args: argparse.Namespace) -> bytes:
    return b"" if args.aad is None else os.fsencode(args.aad)


def _key_codec(args: argparse.Namespace) -> Codec:
    return Codec(KeyStore.in_memory(), key_backend=_key_backend(args))


def _key_backend(args: argparse.Namespace) -> KeyBackend:
    if args.key_backend == "json":
        return _keystore(args)
    return open_key_backend(args.key_backend, path=args.keystore)


def _describe_backend(args: argparse.Namespace, backend: KeyBackend) -> str:
    path = getattr(backend, "path", None)
    return str(args.keystore or path or backend)


@contextlib.contextmanager
def _input_stream(args: argparse.Namespace) -> Iterator[BinaryIO]:
    if args.text is not None:
        yield io.BytesIO(_read_input(args))
    elif args.input == "-":
        yield sys.stdin.buffer
    else:
        if os.path.isdir(args.input):
            raise IsADirectoryError(errno.EISDIR, "is a directory", args.input)
        with open(args.input, "rb") as fh:
            yield fh


@contextlib.contextmanager
def _output_stream(target: Optional[str], *, access: str = "normal") -> Iterator[BinaryIO]:
    """Standard output, or a file that only replaces ``target`` once everything succeeded.

    ``access`` decides who may read a file:

    - ``"normal"`` (ciphertext, encoded tokens): an existing file's mode, else the
      default for new files.
    - ``"private"`` (decrypted data): an existing file's mode, else only you.
    - ``"secret"`` (exported keys and tables): always only you.

    "Only you" is mode 0600 on POSIX and an owner-only ACL on Windows.
    """
    if target is None or target == "-":
        yield cast(BinaryIO, _StdoutWriter())
        return
    if os.path.isdir(target):
        raise IsADirectoryError(errno.EISDIR, "is a directory", target)
    try:
        existing: Optional[int] = stat.S_IMODE(os.stat(target).st_mode)
    except OSError:
        existing = None
    directory, name = os.path.split(os.path.abspath(target))
    fd, tmp = tempfile.mkstemp(prefix=f".{name}.", suffix=".part", dir=directory)
    try:
        if access != "normal":
            restrict_to_owner(tmp)  # Windows; mkstemp already gives 0600 on POSIX
        with os.fdopen(fd, "wb") as fh:
            yield fh
        if sys.platform != "win32":
            if access == "secret":
                mode = 0o600
            elif existing is not None:
                mode = existing
            elif access == "private":
                mode = 0o600
            else:
                umask = os.umask(0)
                os.umask(umask)
                mode = 0o666 & ~umask  # like a normally created file
            os.chmod(tmp, mode)
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


class _StdoutWriter(io.RawIOBase):
    """Binary standard output that reports a closed pipe as BrokenPipeError."""

    def writable(self) -> bool:
        return True

    def write(self, data: Any) -> int:
        _write_stdout(bytes(data))
        return len(data)


def _secret_token(args: argparse.Namespace, *, confirm: bool = False) -> Optional[Union[str, bytes]]:
    """The secret token chosen on the command line, or ``None`` to use a stored key."""
    if args.token_file is not None:
        return _strip_newline(_read_file(args.token_file), args.token_file)
    if args.token_stdin:
        if args.text is None and args.input == "-":
            raise EncodingError("with --token-stdin, give INPUT as a file or use --text")
        return _strip_newline(sys.stdin.buffer.readline(), "standard input")
    if not args.token:
        return None
    for name in (TOKEN_ENV_VAR, PASSWORD_ENV_VAR):
        from_env = os.environ.get(name)
        if from_env:
            message = (
                f"${name} is deprecated and will be removed: other programs running as you "
                "can read environment variables. Use the prompt, --token-file, or --token-stdin."
            )
            warnings.warn(message, DeprecationWarning, stacklevel=2)
            _echo(f"{PROG}: warning: {message}", err=True)
            return from_env
    secret = getpass.getpass("Secret token: ")
    if not secret:
        raise EncodingError("the secret token is empty")
    if confirm and getpass.getpass("Repeat secret token: ") != secret:
        raise EncodingError("the secret tokens do not match")
    return secret


def _strip_newline(data: bytes, source: str) -> Union[str, bytes]:
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    for ending in (b"\r\n", b"\n"):
        if data.endswith(ending):
            data = data[: -len(ending)]
            break
    if not data:
        raise EncodingError(f"the secret token in {source} is empty")
    try:
        return data.decode("utf-8")  # the same bytes the prompt would give
    except UnicodeDecodeError:
        return data


def _cmd_keys_list(args: argparse.Namespace) -> int:
    backend = _key_backend(args)
    names = backend.key_names()
    if not names:
        _echo(f"no keys in {_describe_backend(args, backend)}", err=True)
    for name in names:
        _echo(name)
    return 0


def _cmd_keys_rotate(args: argparse.Namespace) -> int:
    backend = _key_backend(args)
    backend.rotate_key(args.name)
    _echo(
        f"rotated key {args.name!r}: new data uses the new key; data encrypted before still "
        f"decrypts ({_describe_backend(args, backend)})",
        err=True,
    )
    return 0


def _cmd_keys_delete(args: argparse.Namespace) -> int:
    if not args.yes:
        raise KeyStoreError(
            f"deleting key {args.name!r} makes everything encrypted with it unreadable; "
            "re-run with --yes to confirm"
        )
    backend = _key_backend(args)
    backend.delete_key(args.name)
    _echo(f"deleted key {args.name!r} ({_describe_backend(args, backend)})", err=True)
    return 0


def _cmd_keys_export(args: argparse.Namespace) -> int:
    payload = json.dumps(_key_backend(args).export_key(args.name), indent=2) + "\n"
    _write_output(args.output, payload.encode("ascii"), access="secret")
    return 0


def _cmd_keys_import(args: argparse.Namespace) -> int:
    raw = sys.stdin.buffer.read() if args.file == "-" else _read_file(args.file)
    try:
        keys = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise KeyStoreError(f"{args.file} is not valid JSON ({exc})") from exc
    if isinstance(keys, dict) and args.name is None and not args.all_keys:
        # A shared file could replace or add a key you use, such as "default",
        # so that its sender can decrypt your future tokens: name the key you expect.
        names = sorted(entry[4:] for entry in keys if isinstance(entry, str) and entry.startswith("key:"))
        raise KeyStoreError(
            f"{args.file} holds keys: {', '.join(names) or 'none'}. Name the key you expect "
            "with --name NAME, or import everything with --all-keys"
        )
    backend = _key_backend(args)
    result = backend.import_keys(keys, overwrite=args.overwrite, name=args.name)
    for label, entries in (("added", result.added), ("replaced", result.replaced)):
        for entry in entries:
            _echo(f"{label}: {entry[4:]}", err=True)
    _echo(
        f"{len(result.added)} added, {len(result.unchanged)} unchanged, "
        f"{len(result.replaced)} replaced ({_describe_backend(args, backend)})",
        err=True,
    )
    return 0


def _fail(message: str) -> int:
    _echo(f"{PROG}: error: {message}", err=True)
    return 1


def _echo(text: str, *, err: bool = False) -> None:
    # Write UTF-8 bytes so redirected output never fails on the console code page.
    data = (text + "\n").encode("utf-8", "backslashreplace")
    if not err:
        _write_stdout(data)
        return
    with contextlib.suppress(OSError):  # nowhere left to report a failure
        sys.stderr.flush()
        sys.stderr.buffer.write(data)
        sys.stderr.buffer.flush()


def _write_stdout(data: bytes) -> None:
    try:
        sys.stdout.flush()
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except OSError as exc:
        # A reader that closed the pipe: EPIPE on POSIX, EINVAL on Windows.
        if isinstance(exc, BrokenPipeError) or exc.errno == errno.EINVAL:
            raise BrokenPipeError(errno.EPIPE, "broken pipe") from exc
        raise


def _silence_stdout() -> None:
    # Python flushes stdout at exit; point it at devnull so a closed pipe stays quiet.
    with contextlib.suppress(OSError, ValueError):
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())

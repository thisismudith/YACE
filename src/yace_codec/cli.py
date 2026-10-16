"""Command-line interface: ``yace-codec`` (or ``python -m yace_codec``)."""

from __future__ import annotations

import argparse
import contextlib
import errno
import getpass
import io
import json
import math
import os
import sys
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, Iterator, List, Optional, Sequence, Union, cast

from . import __version__
from ._algorithms import DEFAULT_ALGORITHM, algorithms
from ._files import Access, atomic_output
from ._text import BOM, bom_encoding
from .codec import DEFAULT_FAMILY, DEFAULT_ITERATIONS, DEFAULT_LENGTH, MAX_ITERATIONS, Codec
from .errors import (
    DecryptionError,
    EncodingError,
    InvalidNameError,
    KeyNotFoundError,
    KeyStoreError,
    TokenExpiredError,
    UnsupportedCharacterError,
    YaceError,
)
from .keybackends import BACKENDS, KeyBackend, open_key_backend
from .keystore import ENV_VAR, KeyStore, family_of, validate_key_name
from .tables import MAX_LENGTH, MIN_LENGTH

PROG = "yace-codec"
#: Deprecated environment variables that supply the secret token for --token.
#: The first one that is set wins; YACE_CODEC_PASSWORD is the 0.2.0 name.
TOKEN_ENV_VAR = "YACE_CODEC_TOKEN"
PASSWORD_ENV_VAR = "YACE_CODEC_PASSWORD"


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the command line and return the exit status."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    command: argparse.ArgumentParser = args.command_parser
    if getattr(args, "text", None) is not None and getattr(args, "input", None) is not None:
        command.error("give either INPUT or --text, not both")
    if getattr(args, "token_stdin", False) and args.text is None and args.input in (None, "-"):
        command.error("--token-stdin reads standard input, so give INPUT as a file or use --text")
    if getattr(args, "key_backend", "json") == "keyring" and args.keystore:
        command.error("--keystore does not apply to --key-backend keyring")
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


# --- argument parsing ----------------------------------------------------------------------


def _int_between(low: int, high: int) -> Callable[[str], int]:
    def parse(text: str) -> int:
        try:
            value = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"expected a whole number, not {text!r}") from None
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"must be {low}-{high}, not {value}")
        return value

    return parse


def _seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a number of seconds, not {text!r}") from None
    if math.isnan(value) or value < 0:
        raise argparse.ArgumentTypeError("must be a number of seconds, 0 or more")
    return value


def _key_name(text: str) -> str:
    try:
        return validate_key_name(text)
    except InvalidNameError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _build_parser() -> argparse.ArgumentParser:
    store = argparse.ArgumentParser(add_help=False)
    store.add_argument(
        "-k", "--keystore", metavar="PATH",
        help=f"key store file (default: ${ENV_VAR} if set, else a file in your user data "
        "directory; see 'yace-codec tables path')",
    )
    backend = argparse.ArgumentParser(add_help=False)
    backend.add_argument(
        "--key-backend", choices=BACKENDS, default="json",
        help="where stored keys live: json (in the key store file; the default), dpapi "
        "(Windows: keys-dpapi.json next to the key store, encrypted for your account), or "
        "keyring (the system keyring; needs yace-codec[keyring])",
    )

    parser = argparse.ArgumentParser(
        prog=PROG,
        allow_abbrev=False,
        description="Encrypt and decrypt any data with your own secret token or a stored key "
        "(encryption), or encode and decode text with YACE substitution tables (obfuscation).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(title="commands", metavar="COMMAND")
    commands.required = True

    def command(
        group: Any, name: str, help: str, parents: Sequence[argparse.ArgumentParser] = ()
    ) -> argparse.ArgumentParser:
        sub: argparse.ArgumentParser = group.add_parser(
            name, help=help, description=help[:1].upper() + help[1:] + ".",
            parents=list(parents), allow_abbrev=False,
        )
        sub.set_defaults(command_parser=sub)
        return sub

    def add_io(sub: argparse.ArgumentParser, what: str, output_help: str) -> None:
        sub.add_argument("input", nargs="?", metavar="INPUT", help=f"file to {what} (default: standard input)")
        sub.add_argument("-t", "--text", metavar="TEXT", help=f"{what} this string instead of INPUT")
        sub.add_argument("-o", "--output", metavar="PATH", help=output_help)

    def add_secret_options(sub: argparse.ArgumentParser, encrypting: bool) -> None:
        secret = sub.add_mutually_exclusive_group()
        if encrypting:
            secret.add_argument(
                "--key", metavar="NAME", type=_key_name,
                help="stored key to use (default: default; created on first use)",
            )
        secret.add_argument(
            "-p", "--token", "--password", dest="token", action="store_true",
            help="use your own secret token instead of a stored key; asked for without echo",
        )
        secret.add_argument(
            "--token-file", metavar="PATH",
            help="read your secret token from this file (UTF-8 or UTF-16; one trailing "
            "newline is ignored)",
        )
        secret.add_argument(
            "--token-stdin", action="store_true",
            help="read your secret token from the first line of standard input "
            "(then give INPUT as a file, or use --text)",
        )
        sub.add_argument(
            "--aad", metavar="TEXT",
            help="associated data: context (such as a record id) that must match to decrypt",
        )

    encr = command(commands, "encrypt", "encrypt text or a file of any size", [store, backend])
    add_io(encr, "encrypt", "write the result here, replacing PATH only on success "
           "(default: standard output)")
    add_secret_options(encr, encrypting=True)
    encr.add_argument(
        "-a", "--algorithm", choices=[info.name for info in algorithms()], default=DEFAULT_ALGORITHM,
        help="encryption algorithm (default: %(default)s; see 'yace-codec algorithms')",
    )
    encr.add_argument(
        "-f", "--format", choices=("text", "bytes"), default="text",
        help="text: letters and digits (default); bytes: raw binary, about 27%% smaller "
        "(use -o for binary output in Windows PowerShell)",
    )
    encr.set_defaults(handler=_cmd_encrypt)

    decr = command(commands, "decrypt", "decrypt the output of encrypt (any format)", [store, backend])
    add_io(decr, "decrypt", "write the result here, only if decryption succeeds; new files are "
           "readable only by you (default: standard output, which may show part of the data "
           "before an error is found)")
    add_secret_options(decr, encrypting=False)
    decr.add_argument(
        "--max-age", type=_seconds, metavar="SECONDS",
        help="reject data encrypted longer ago than this, by the time stored in it "
        "(fractions allowed)",
    )
    decr.set_defaults(handler=_cmd_decrypt)

    algs = command(commands, "algorithms", "list the encryption algorithms")
    algs.set_defaults(handler=_cmd_algorithms)

    keys = command(commands, "keys", "manage and share stored keys for encrypt and decrypt")
    key_actions = keys.add_subparsers(title="actions", metavar="ACTION")
    key_actions.required = True
    key_list = command(key_actions, "list", "list the stored key names", [store, backend])
    key_list.set_defaults(handler=_cmd_keys_list)
    key_rotate = command(
        key_actions, "rotate", "give a key a new value; data encrypted before still decrypts",
        [store, backend],
    )
    key_rotate.add_argument("name", metavar="NAME", type=_key_name, help="key name")
    key_rotate.set_defaults(handler=_cmd_keys_rotate)
    key_delete = command(
        key_actions, "delete", "delete a key; data encrypted with it can no longer be decrypted",
        [store, backend],
    )
    key_delete.add_argument("name", metavar="NAME", help="key name")
    key_delete.add_argument("--yes", action="store_true", help="confirm the deletion (required)")
    key_delete.set_defaults(handler=_cmd_keys_delete)
    key_export = command(
        key_actions, "export", "export a key as JSON (the file is readable only by you)",
        [store, backend],
    )
    key_export.add_argument("name", metavar="NAME", help="key name")
    key_export.add_argument("-o", "--output", metavar="PATH", help="write here (default: standard output)")
    key_export.set_defaults(handler=_cmd_keys_export)
    key_import = command(key_actions, "import", "import keys from a JSON file", [store, backend])
    key_import.add_argument("file", metavar="FILE", help="JSON file from 'keys export' ('-' for standard input)")
    which_key = key_import.add_mutually_exclusive_group()
    which_key.add_argument("--name", metavar="NAME", help="import only this key")
    which_key.add_argument("--all-keys", action="store_true", help="import every key in a file that holds several")
    key_import.add_argument(
        "--overwrite", action="store_true",
        help="replace existing keys that differ (data encrypted with them can no longer be decrypted)",
    )
    key_import.set_defaults(handler=_cmd_keys_import)

    enc = command(commands, "encode", "encode text or a file with substitution tables (not encryption)", [store])
    add_io(enc, "encode", "write the token here, replacing PATH only on success (default: standard output)")
    enc.add_argument("-n", "--name", default=DEFAULT_FAMILY, help="table family name (default: %(default)s)")
    enc.add_argument(
        "-l", "--length", metavar="N", type=_int_between(MIN_LENGTH, MAX_LENGTH), default=DEFAULT_LENGTH,
        help=f"code length, {MIN_LENGTH}-{MAX_LENGTH} (default: %(default)s)",
    )
    enc.add_argument(
        "-i", "--iterations", metavar="N", type=_int_between(1, MAX_ITERATIONS), default=DEFAULT_ITERATIONS,
        help=f"number of encoding layers, 1-{MAX_ITERATIONS} (default: %(default)s)",
    )
    enc.add_argument("-b", "--binary", action="store_true",
                     help="encode the input as raw bytes (any file type or text encoding)")
    enc.set_defaults(handler=_cmd_encode)

    dec = command(commands, "decode", "decode a token made by encode", [store])
    add_io(dec, "decode", "write the result here, replacing PATH only on success; new files are "
           "readable only by you (default: standard output)")
    dec.add_argument("-b", "--binary", action="store_true",
                     help="the token was made with 'encode --binary'; output the raw bytes")
    dec.set_defaults(handler=_cmd_decode)

    tables = command(commands, "tables", "inspect and share the substitution tables of a key store")
    actions = tables.add_subparsers(title="actions", metavar="ACTION")
    actions.required = True
    path = command(actions, "path", "print the key store location", [store])
    path.set_defaults(handler=_cmd_path)
    listing = command(actions, "list", "list table families", [store])
    listing.set_defaults(handler=_cmd_list)
    export = command(actions, "export", "export a family's tables as JSON (readable only by you)", [store])
    export.add_argument("name", metavar="NAME", help="family name")
    export.add_argument("-o", "--output", metavar="PATH", help="write here (default: standard output)")
    export.set_defaults(handler=_cmd_export)
    imp = command(actions, "import", "import tables from a JSON file", [store])
    imp.add_argument("file", metavar="FILE", help="JSON file from 'tables export' ('-' for standard input)")
    which = imp.add_mutually_exclusive_group()
    which.add_argument("--family", metavar="NAME", help="import only this family's tables")
    which.add_argument("--all-families", action="store_true",
                       help="import every table in a file that holds several families")
    imp.add_argument("--overwrite", action="store_true",
                     help="replace existing tables that differ (tokens made with them stop decoding)")
    imp.set_defaults(handler=_cmd_import)
    return parser


# --- commands ----------------------------------------------------------------------------


def _cmd_encrypt(args: argparse.Namespace) -> int:
    is_text = False
    if args.text is not None:
        with contextlib.suppress(UnicodeDecodeError):
            _read_input(args).decode("utf-8")
            is_text = True  # so Python's decrypt() returns str
    secret = _secret_token(args, confirm=True)
    codec = Codec(KeyStore.in_memory()) if secret is not None else _key_codec(args)
    # The output is opened first and closed last, so INPUT may be the same file.
    with _output_stream(args.output) as dst, _input_stream(args) as src:
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
    try:
        with _output_stream(args.output, access="private") as dst, _input_stream(args) as src:
            codec.decrypt_stream(src, dst, token=secret, aad=_aad(args), max_age=args.max_age)
    except DecryptionError as exc:
        if secret is None and not isinstance(exc, TokenExpiredError):
            raise DecryptionError(
                f"{exc} (tried the keys in {_describe_backend(args, codec.key_backend)}; "
                "was it encrypted with --token, or with another --keystore or --key-backend?)"
            ) from None
        raise
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


def _cmd_encode(args: argparse.Namespace) -> int:
    codec = Codec(_keystore(args))
    raw = _read_input(args)
    options = dict(length=args.length, iterations=args.iterations)
    if args.binary:
        token = codec.encode_bytes(raw, args.name, **options)
    else:
        token = codec.encode(_text_input(raw), args.name, **options)
    _write_output(args.output, f"{token}\n".encode("ascii"))
    return 0


def _cmd_decode(args: argparse.Namespace) -> int:
    codec = Codec(_keystore(args))
    raw = _read_input(args)
    result = codec.decode_bytes(raw) if args.binary else codec.decode(raw).encode("utf-8")
    _write_output(args.output, result, access="private")
    return 0


def _cmd_path(args: argparse.Namespace) -> int:
    _echo(str(_keystore(args).path))
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    store = _keystore(args)
    families = store.families()
    if not families:
        _echo(f"no tables in {_describe_store(args, store)}", err=True)
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
    tables = _read_json_file(args.file)
    if isinstance(tables, dict) and args.family is None and not args.all_families:
        # A shared file could add tables for families you use, such as "default",
        # so that its sender can decode your future tokens: name the family you expect.
        families = sorted({f for f in map(family_of, tables) if f is not None})
        if not families and any(str(entry).startswith("key:") for entry in tables):
            raise KeyStoreError(f"{args.file} holds keys, not tables; use 'yace-codec keys import'")
        raise KeyStoreError(
            f"{args.file} holds tables for: {', '.join(families) or 'no valid tables'}. Name the "
            "family you expect with --family NAME, or import everything with --all-families"
        )
    store = _keystore(args)
    result = store.import_tables(tables, overwrite=args.overwrite, family=args.family)
    for label, names in (("added", result.added), ("replaced", result.replaced)):
        for name in names:
            _echo(f"{label}: {name}", err=True)
    _echo(
        f"{len(result.added)} added, {len(result.unchanged)} unchanged, "
        f"{len(result.replaced)} replaced ({_describe_store(args, store)})",
        err=True,
    )
    return 0


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
    if backend.find_key(args.name) is None:
        raise KeyNotFoundError(
            f"no key {args.name!r} in {_describe_backend(args, backend)}; "
            f"'yace-codec encrypt --key {args.name}' creates one",
            args.name,
        )
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
    keys = _read_json_file(args.file)
    if isinstance(keys, dict) and args.name is None and not args.all_keys:
        # A shared file could replace or add a key you use, such as "default",
        # so that its sender can decrypt your future data: name the key you expect.
        names = sorted(entry[4:] for entry in keys if isinstance(entry, str) and entry.startswith("key:"))
        if not names and any(family_of(entry) for entry in keys):
            raise KeyStoreError(f"{args.file} holds tables, not keys; use 'yace-codec tables import'")
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


# --- helpers ------------------------------------------------------------------------------


def _keystore(args: argparse.Namespace) -> KeyStore:
    return KeyStore(args.keystore) if args.keystore else KeyStore.default()


def _key_backend(args: argparse.Namespace) -> KeyBackend:
    if args.key_backend == "json":
        return _keystore(args)
    if args.key_backend == "dpapi" and args.keystore:
        # -k always names the key store; the DPAPI file sits next to it.
        return open_key_backend("dpapi", path=Path(args.keystore).with_name("keys-dpapi.json"))
    return open_key_backend(args.key_backend)


def _key_codec(args: argparse.Namespace) -> Codec:
    return Codec(KeyStore.in_memory(), key_backend=_key_backend(args))


def _describe_store(args: argparse.Namespace, store: KeyStore) -> str:
    return str(args.keystore or store.path)


def _describe_backend(args: argparse.Namespace, backend: KeyBackend) -> str:
    path = getattr(backend, "path", None)
    if path is None:
        return str(backend)
    return str(path) if args.key_backend == "dpapi" else str(args.keystore or path)


def _aad(args: argparse.Namespace) -> bytes:
    return b"" if args.aad is None else os.fsencode(args.aad)


def _read_input(args: argparse.Namespace) -> bytes:
    if args.text is not None:
        # The argument's original bytes: on POSIX, bytes that are not valid
        # UTF-8 arrive as surrogates, which os.fsencode turns back into bytes.
        return os.fsencode(args.text)
    if args.input in (None, "-"):
        return sys.stdin.buffer.read()
    return _read_file(args.input)


def _text_input(raw: bytes) -> str:
    """Text to encode: UTF-8, or UTF-16/UTF-32 with a byte order mark (PowerShell)."""
    text = raw.decode(bom_encoding(raw) or "utf-8")
    return text[1:] if text.startswith(BOM) else text


def _read_file(name: str) -> bytes:
    if os.path.isdir(name):
        raise IsADirectoryError(errno.EISDIR, "is a directory", name)
    return Path(name).read_bytes()


def _read_json_file(name: str) -> Any:
    raw = sys.stdin.buffer.read() if name == "-" else _read_file(name)
    try:
        # json.loads detects UTF-8 (with or without a BOM), UTF-16, and UTF-32,
        # so files saved by Windows PowerShell 5.1 work too.
        return json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise KeyStoreError(f"{name} is not valid JSON ({exc})") from exc


@contextlib.contextmanager
def _input_stream(args: argparse.Namespace) -> Iterator[BinaryIO]:
    if args.text is not None:
        yield io.BytesIO(_read_input(args))
    elif args.input in (None, "-"):
        yield sys.stdin.buffer
    else:
        if os.path.isdir(args.input):
            raise IsADirectoryError(errno.EISDIR, "is a directory", args.input)
        with open(args.input, "rb") as fh:
            yield fh


@contextlib.contextmanager
def _output_stream(target: Optional[str], *, access: Access = "normal") -> Iterator[BinaryIO]:
    """Standard output, or a file that replaces ``target`` only if everything succeeded."""
    if target is None or target == "-":
        yield cast(BinaryIO, _StdoutWriter())
    else:
        with atomic_output(target, access) as fh:
            yield fh


def _write_output(target: Optional[str], data: bytes, *, access: Access = "normal") -> None:
    with _output_stream(target, access=access) as fh:
        fh.write(data)


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
        return _token_from(_read_file(args.token_file), args.token_file)
    if args.token_stdin:
        return _token_from(sys.stdin.buffer.readline(), "standard input")
    if not args.token:
        return None
    for name in (TOKEN_ENV_VAR, PASSWORD_ENV_VAR):
        from_env = os.environ.get(name)
        if from_env:
            _echo(
                f"{PROG}: warning: ${name} is deprecated and will be removed: other programs "
                "running as you can read environment variables. Use the prompt, --token-file, "
                "or --token-stdin.",
                err=True,
            )
            return from_env
    if not _can_prompt():
        raise EncodingError(
            "there is no terminal to ask for the secret token; use --token-file or --token-stdin"
        )
    secret = _prompt("Secret token: ")
    if not secret:
        raise EncodingError("the secret token is empty")
    if confirm and _prompt("Repeat secret token: ") != secret:
        raise EncodingError("the secret tokens do not match")
    return secret


def _prompt(text: str) -> str:
    try:
        return getpass.getpass(text)
    except KeyboardInterrupt:
        _echo("", err=True)  # end the prompt line
        raise


def _can_prompt() -> bool:
    """Whether getpass can ask someone (it would wait forever without a terminal)."""
    if sys.platform == "win32":
        # isatty() is also true for NUL; only a console has a console mode.
        import ctypes
        import msvcrt
        from ctypes import wintypes

        try:
            handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        except (AttributeError, OSError, ValueError):
            return False
        mode = wintypes.DWORD()
        return bool(ctypes.WinDLL("kernel32").GetConsoleMode(wintypes.HANDLE(handle), ctypes.byref(mode)))
    try:
        with open("/dev/tty"):
            return True
    except OSError:
        return sys.stdin is not None and sys.stdin.isatty()


def _token_from(data: bytes, source: str) -> Union[str, bytes]:
    """A secret token read from a file: text (UTF-8, or UTF-16/32 with a BOM) without
    one trailing newline. Bytes that are not text are used as they are."""
    encoding = bom_encoding(data)
    token: Union[str, bytes]
    if encoding is not None:
        token = data.decode(encoding).lstrip(BOM)
    else:
        try:
            token = data.decode("utf-8")  # the same bytes the prompt would give
        except UnicodeDecodeError:
            token = data
    for ending in (("\r\n", "\n") if isinstance(token, str) else (b"\r\n", b"\n")):
        if token.endswith(ending):  # type: ignore[arg-type]
            token = token[: -len(ending)]
            break
    if not token:
        raise EncodingError(f"the secret token in {source} is empty")
    return token


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

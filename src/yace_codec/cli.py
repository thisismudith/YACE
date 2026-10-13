"""Command-line interface: ``yace-codec`` (or ``python -m yace_codec``)."""

from __future__ import annotations

import argparse
import contextlib
import errno
import json
import os
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from . import __version__
from .codec import DEFAULT_FAMILY, DEFAULT_ITERATIONS, DEFAULT_LENGTH, Codec
from .errors import KeyStoreError, UnsupportedCharacterError, YaceError
from .keystore import ENV_VAR, KeyStore, family_of

PROG = "yace-codec"


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
        description="Encode and decode text with YACE substitution tables. "
        "YACE obfuscates text; it is not encryption.",
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


def _write_output(target: Optional[str], data: bytes, *, private: bool = False) -> None:
    if target is None or target == "-":
        _write_stdout(data)
        return
    if os.path.isdir(target):
        raise IsADirectoryError(errno.EISDIR, "is a directory", target)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(target, flags, 0o600 if private else 0o666)
    if private and sys.platform != "win32":
        os.fchmod(fd, 0o600)  # the open() mode only applies to new files
    with os.fdopen(fd, "wb") as fh:
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
    _write_output(args.output, payload.encode("ascii"), private=True)
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

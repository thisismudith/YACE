# YACE

**Authenticated encryption with your own secret token or keys, and reversible text encoding with random substitution tables.**

[![PyPI](https://img.shields.io/pypi/v/yace-codec)](https://pypi.org/project/yace-codec/)
[![Python versions](https://img.shields.io/pypi/pyversions/yace-codec)](https://pypi.org/project/yace-codec/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/thisismudith/YACE/blob/main/LICENSE)

YACE (Yet Another Custom Encoder) has two modes, both as a Python API and as the
`yace-codec` command:

- **Encryption** (`encrypt`/`decrypt`) turns any text or file, of any size, into
  letters and digits (or compact bytes) that reveal nothing but their approximate
  size. Only your secret token or key opens them, and any change is detected. It uses
  AES-256-GCM by default.
- **Encoding** (`encode`/`decode`) turns text into tokens of random-looking letters
  and digits with YACE's substitution tables. It hides text from casual reading, but
  it is **not** encryption.

> **Use `encrypt()` for secrets, never `encode()`.** Encoding is a substitution code
> that frequency analysis breaks. Encryption uses audited algorithms from the
> [`cryptography`](https://cryptography.io/) package, but yace-codec's own formats
> have not been audited: read [Security](#security) before relying on it for
> high-stakes data.

| | |
|---|---|
| PyPI distribution | `yace-codec` |
| Import name | `yace_codec` |
| Command | `yace-codec` |

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Which mode?](#which-mode)
- [Encryption](#encryption)
- [Encoding](#encoding)
- [Command line](#command-line)
- [API reference](#api-reference)
- [The key store file](#the-key-store-file)
- [Security](#security)
- [How it works](#how-it-works)
- [Migrating from the original scripts](#migrating-from-the-original-scripts)
- [Development and contributing](#development-and-contributing)
- [License, links, and author](#license-links-and-author)

## Installation

```bash
python -m pip install yace-codec
```

On Windows, `py -m pip install yace-codec` works too. YACE needs Python 3.10 or
newer. Its one dependency is [`cryptography`](https://cryptography.io/), which
provides the default encryption algorithm.

| Extra | Adds |
|---|---|
| `"yace-codec[keyring]"` | the system keyring as a key backend (the `keyring` package) |
| `"yace-codec[aead]"` | nothing since 0.3.0 (`cryptography` is always installed); kept so older install commands work |

## Quick start

Encrypt with your own secret token, and decrypt with the same one:

```python
import yace_codec as yace

encrypted = yace.encrypt("Meet at the north gate at 06:00.", token="blue-falcon-42")
print(encrypted)
print(yace.decrypt(encrypted, token="blue-falcon-42"))
```

```text
KNFu4tUsgMyG2Mn7VsXlJ0I7mgUfNQbP1Ba8cmXd2bFG9JzxsntY6Q58PeqA8OLOK7CfbDh54KkE4GBxUqLZxIo28EQ1jPAy6DoIhnlLINWRMvLtrBgCBLgdc13m
Meet at the north gate at 06:00.
```

Encode text so it is not readable at a glance (not secret):

```python
token = yace.encode("Hello, World!")
print(token)
print(yace.decode(token))
```

```text
default-2:3
DoreDo6HKohJKWjYPEDNwcwcW3geWGvpDNzXW3re1PoyoysC6HUvPEftKndLKhnNWG6yjY1PrceE7WOJ1PrelBsCeEzXkVyQhJwcKWHEHEDN4MHEW3oydLMuBa4MOJnNDo
Hello, World!
```

On the command line:

```console
$ yace-codec encrypt --token report.pdf -o report.yace
$ yace-codec decrypt --token report.yace -o report-copy.pdf
```

Output is random, so yours will differ.

## Which mode?

| | base64 / hex | YACE `encode` | YACE `encrypt` | Fernet (`cryptography`) |
|---|---|---|---|---|
| Who can read it | anyone | holders of the tables, or an attacker with enough samples | holders of the secret token or key | holders of the key |
| Same input, same output | yes | usually not | no | no |
| Resists cryptanalysis | no | no | yes by design (audited AEAD; the format is not audited) | yes (audited) |
| Detects tampering | no | no (only some corruption) | yes | yes |
| Hides the length | no | no | roughly (Padmé padding) | no |
| Binds to a context (associated data) | no | no | yes | no |
| Large files in constant memory | n/a | no | yes (streams) | no |
| Output size | 1.33× / 2× | about 1.25 × length<sup>iterations</sup> | bytes: +55 bytes, +up to 12% padding; text: about 1.4× that | about 1.33× plus a fixed overhead |

## Encryption

`encrypt()` turns any text or bytes into letters and digits; `decrypt()` returns
`str` for text and `bytes` for bytes. Every failure raises `DecodingError`: a wrong
secret token, key, or associated data, or any change to the encrypted output, raises
its subclass `DecryptionError`. `max_age` rejects old data:
`yace.decrypt(encrypted, token="blue-falcon-42", max_age=3600)` raises
`TokenExpiredError` for data encrypted more than an hour earlier (by the encrypting
computer's clock).

### Choosing the secret

| Secret | Use it for | Example |
|---|---|---|
| Your own secret token | sharing with people who know a passphrase | `encrypt(data, token="blue-falcon-42")` |
| A raw 32-byte key | applications that manage their own keys | `encrypt(data, key=key)`, `decrypt(encrypted, keys=[key])` |
| A stored key | everyday use on one machine or team | `encrypt(data)` or `encrypt(data, "team")` |

**A secret token** can be any non-empty text or bytes. It is stretched with scrypt,
which makes each guess slow, but anyone who guesses it can decrypt: choose a long one.
Nothing is generated or stored. `password=` is another name for `token=`.

**A raw key** comes from `yace.generate_key()` (32 random bytes) and is used as is,
without scrypt or a key store. `decrypt(..., keys=[...])` tries every key in the
list. Keys of any other size raise `InvalidKeyError`.

```python
key = yace.generate_key()
encrypted = yace.encrypt(b"\x89PNG\r\n\x1a\n...", key=key)
assert yace.decrypt(encrypted, keys=[key]) == b"\x89PNG\r\n\x1a\n..."
```

**A stored key** has a name (1–64 ASCII letters or underscores; `default` when you
give none). It is generated on first use and kept by a
[key backend](#stored-keys-backends-rotation-and-sharing), by default in the
[key store file](#the-key-store-file). `decrypt()` tries every stored key, so the
output never names its key.

```python
encrypted = yace.encrypt("Meet at the north gate at 06:00.")
print(yace.decrypt(encrypted))
```

```text
Meet at the north gate at 06:00.
```

### Algorithms

| Algorithm | Implementation | Speed (bytes output) |
|---|---|---|
| `aes-256-gcm` (the default) | AES-256-GCM from the audited `cryptography` package | hundreds of MB/s to GB/s |
| `chacha20-poly1305` | ChaCha20-Poly1305 from `cryptography`; fast without AES hardware | hundreds of MB/s to GB/s |
| `yace-hmac-sha256` | HMAC-SHA256 keystream and tag; standard library only | about 20 MB/s |

Choose one with `algorithm=` (`--algorithm` on the command line). The output records
the algorithm, hidden like everything else, so `decrypt()` needs no hint. List them
with `yace.algorithms()` or `yace-codec algorithms`:

```python
for info in yace.algorithms():
    print(info.name, "(default)" if info.default else "")
```

```text
aes-256-gcm (default)
chacha20-poly1305
yace-hmac-sha256
```

The default changes only in a new minor version, with a CHANGELOG entry. If you
install with `pip install --no-deps yace-codec` (without `cryptography`), only
`yace-hmac-sha256` works: pass it explicitly, because the default then raises
`EncodingError`.

### Associated data

`aad=` ties encrypted output to a context, such as a database row, a user, or a file
name. It is authenticated but not stored, so decryption needs the same value. That
stops valid output from being moved to another record:

```python
key = yace.generate_key()
row_1 = yace.encrypt("salary: 85000", key=key, aad="row:1")
assert yace.decrypt(row_1, keys=[key], aad="row:1") == "salary: 85000"
try:
    yace.decrypt(row_1, keys=[key], aad="row:2")  # copied into row 2
except yace.DecryptionError:
    print("rejected")
```

```text
rejected
```

`aad` accepts bytes, or text (encoded as UTF-8).

### Text or bytes output

`output="text"` (the default) gives letters and digits, safe to paste anywhere.
`output="bytes"` gives the raw form: about 27% smaller and much faster to produce
(text output runs at roughly 10–20 MB/s). `decrypt()` accepts both, and text given as
bytes, with or without a byte order mark.

```python
raw = yace.encrypt("Meet at the north gate at 06:00.", key=key, output="bytes")
print(type(raw).__name__, len(raw))
```

```text
bytes 90
```

### Large files: streaming

`encrypt_stream()` and `decrypt_stream()` work on binary file objects or paths, in
constant memory, whatever the size. One `encrypt()` call holds at most 2 GiB; use a
stream for more.

```python
import io

source = io.BytesIO(b"a large file" * 100_000)
encrypted, restored = io.BytesIO(), io.BytesIO()
yace.encrypt_stream(source, encrypted, key=key, output="bytes")
encrypted.seek(0)
info = yace.decrypt_stream(encrypted, restored, keys=[key])
print(info.size == len(source.getvalue()) == len(restored.getvalue()))
```

```text
True
```

Data is encrypted in chunks (64 KiB by default); each chunk's nonce holds its index
and a final-chunk flag, so a truncated, reordered, or spliced stream fails to
decrypt. `decrypt_stream()` verifies each chunk before writing it, but notices a
truncation only at the end: if it raises, discard what it wrote to a file object.
Given a path as the destination, both functions write a temporary file and rename it
only when everything succeeded (new decrypted files are readable only by you).
`decrypt()` also reads streams (in memory), and `decrypt_stream()` reads every format.

### Stored keys: backends, rotation, and sharing

Stored keys live in a *key backend*. Pass one as `key_backend=` (a backend object, or
its name) to `Codec` or to the functions, or use `--key-backend` on the command line:

| Backend | Where the keys are | Notes |
|---|---|---|
| `json` (`KeyStore`, the default) | in the key store file | **plain text** (base64): anyone who reads the file can decrypt. New files are readable only by you. |
| `dpapi` (`DpapiKeyStore`) | `keys-dpapi.json` next to the key store | Windows only. Keys are encrypted with DPAPI for your Windows account, so a copied file is useless elsewhere. |
| `keyring` (`KeyringKeyStore`) | the system keyring (Windows Credential Manager, macOS Keychain, Secret Service) | Needs `pip install "yace-codec[keyring]"`. |

```python
backend = yace.open_key_backend("json", path="team-keys.json")
codec = yace.Codec(key_backend=backend)
old = codec.encrypt("before rotation", "team")
backend.rotate_key("team")  # a new key for new data; the old one still decrypts
new = codec.encrypt("after rotation", "team")
print(codec.decrypt(old), "/", codec.decrypt(new))
```

```text
before rotation / after rotation
```

- **Rotation:** `rotate_key()` gives a key a new value and keeps the previous ones as
  *retired* keys: they still decrypt, but nothing new is encrypted with them.
  (Version 0.2 ignores retired keys: it only sees the current one.)
- **Deletion:** `delete_key()` removes a key with its retired keys.
- **Sharing:** `export_key("team")` (CLI: `yace-codec keys export team`) gives
  portable JSON, retired keys included, and `import_keys(data, name="team")` (CLI:
  `yace-codec keys import FILE --name team`) adds it to another backend. Anyone with
  a key can decrypt and encrypt with it.

### What encrypted output reveals

Only roughly how long the data is, and whether it is a stream or a single message:
the size is padded to a Padmé length, which leaks at most a few bits. There is no
prefix or readable header, so the output does not show that YACE made it, which
algorithm encrypted it, or which key. The exact length, the creation time, and
whether the data was text or bytes are encrypted. The same data gives different
output every time. Output of versions 0.2.0 (it starts with `yace2_`) and 0.2.1
still decrypts.

## Encoding

A **table** maps each of the 100 characters of Python's
[`string.printable`](https://docs.python.org/3/library/string.html#string.printable)
to a random code of `length` letters and digits. Tables are named
`<family>-<length>:<layer>`, are generated on first use, and are saved in the
[key store file](#the-key-store-file). Decoding needs the tables that encoded a
token: the key store is the key. See [How encoding works](#how-encoding-works) for
the steps.

### Choosing a key store, family, and settings

```python
from yace_codec import Codec, KeyStore

codec = Codec(KeyStore("my-keystore.json"))
token = codec.encode("Meet me at 7pm.\nBring the blue folder!", "team", length=3, iterations=2)
print(token)
print(codec.decode(token))
```

```text
team-3:2
rhvnH11s0X1f3cQ5VuX1fEh8cU0Y7KHJNX1fMajU1S2GYLrqvQMx6VC82uRbiRafm2X1fcpNY7K9HlihQNxSQbHu6nA6ljeU3cQMajUhZAER9HliRaHJNvQMdoC6GiQbHAzW5VuyLoPjYoFjqRaUhZX1frWSuRb104CDtcU0MajjeUmdwdV0PjYhWOA1xcU0IpNeamQbdIpNAERmdwU7yc5y6cHrhvNxSNr6Nr65VuyFD6GijLYvi0Wu8DJucpN104iRaU1SoFjfm2mTprWSdV03cQY7K6cHLrqvQMWu8N2xjLYIpNNxS2GYrZcMajMQZU1SQbHX1f104Y7KNxSHJN6cHEh8U1SROLQbH3cQNxS1W26GiNxS2GYdV0MajeamoFjSglCNS1043cQY7K3cQIpN6GiY7Kc5IU1SU7FX1fDJu
Meet me at 7pm.
Bring the blue folder!
```

The defaults are `name="default"`, `length=2` (2–62), and `iterations=3` (1–32).
Family names are 1–64 ASCII letters or underscores. A `Codec` reuses one key store,
which is faster than the module functions when you encode many values. Equal texts
usually give different tokens, because the space has several codes and noise chunks
go in random places.

### Reading a token's header

```python
header = yace.parse_header(token)
print(header, "|", header.family, header.length, header.iterations, "|", header.table_names)
```

```text
team-3:2 | team 3 2 | ('team-3:1', 'team-3:2')
```

### Sharing tables

To let someone decode your tokens, export the family and have them import it. Only
that family is shared; your other families stay private.

```python
tables = codec.keystore.export_family("team")

colleague = Codec(KeyStore("colleague-keystore.json"))
print(colleague.keystore.import_tables(tables, family="team"))
print(colleague.decode(token))
```

```text
ImportResult(added=('team-3:1', 'team-3:2'), unchanged=(), replaced=())
Meet me at 7pm.
Bring the blue folder!
```

Between machines, use `yace-codec tables export` (the file is readable only by you)
and `tables import`. **Import only the family you expect** (`family=` in Python,
`--family NAME` on the command line): a file could otherwise add tables to a family
you use, such as `default`, and its sender could then decode your later tokens.

### Unicode text and binary data

`encode()` accepts the 100 characters of `string.printable`. For any other text, or
for binary data, use `encode_bytes()`: it base64-encodes the bytes first, which makes
tokens about a third longer.

```python
try:
    codec.encode("naïve café")
except yace.UnsupportedCharacterError as exc:
    print(exc.characters)

data = codec.encode_bytes("naïve café".encode("utf-8"), "team", length=3, iterations=1)
print(codec.decode_bytes(data).decode("utf-8"))
```

```text
('é', 'ï')
naïve café
```

### Handling errors

```python
try:
    codec.decode("unknown-2:1\nAbCd")
except yace.TableNotFoundError as exc:
    print("missing:", exc.table_name)

try:
    codec.decode(token[:-1])
except yace.DecodingError as exc:
    print("corrupted:", exc)
```

```text
missing: unknown-2:1
corrupted: layer 2 has 428 characters, which is not a multiple of the code length 3; the token is truncated or corrupted
```

Decoding catches many corruptions, but not all: tokens have no cryptographic
integrity check, so a changed token can decode to different text.

### Reproducible output in tests

Pass a seeded `random.Random` to get the same tables and tokens on every run. Use
this only in tests: seeded tables are predictable.

```python
import random

def make_token():
    seeded = Codec(KeyStore.in_memory(), rng=random.Random(42))
    return seeded.encode("reproducible", "test", length=2, iterations=1)

assert make_token() == make_token()
```

### Encoding limits

- **Size.** Tokens grow by `length ** iterations`, plus 25% for noise chunks. Encoding
  is refused when `len(text) × length ** iterations` exceeds 2<sup>25</sup> (about
  33 million characters), and decoding refuses longer tokens. Encoding is pure Python
  and holds everything in memory (25–40 bytes per token character): it is for
  strings and small files.
- **Empty input** gives a header-only token, which decodes to `""`.
- **Whitespace** in a token is ignored, so wrapped lines and CRLF are fine.
- **Bytes tokens.** `decode_bytes()` raises `DecodingError` if the decoded text is not
  base64; short texts can happen to be valid base64, so keep track of which function
  made a token.
- **Family names.** Decoding accepts any family name the original scripts allowed,
  such as `my cat`, except one that starts with a space.

More runnable scripts are in
[`examples/`](https://github.com/thisismudith/YACE/tree/main/examples).

## Command line

Installing the package adds the `yace-codec` command (`python -m yace_codec` works
too). Input comes from a file argument, `--text`, or standard input; output goes to
`-o PATH` or standard output.

```console
$ yace-codec encrypt --token --text "Meet at the north gate at 06:00."
Secret token:
Repeat secret token:
Lo6IzVRchEH9NzI1642E1XBvW0ElUuhJsKCww0j3uzWq6VVKNVusHs9JXJLZFyHmlkJRTDfENQ3fJ3fha0wyBXZg9Mo7nlxtyEh4ftoWcwsYYS1LE7VrjCF0

$ yace-codec encrypt --token notes.txt -o notes.yace
$ yace-codec decrypt --token notes.yace
Secret token:
Shopping list:
- milk
- 12 eggs

$ yace-codec encrypt backup.tar -o backup.yace --key team --format bytes
$ yace-codec decrypt backup.yace -o backup-copy.tar

$ yace-codec encrypt invoice.pdf -o invoice.yace --aad "customer:42" --algorithm chacha20-poly1305
$ yace-codec decrypt invoice.yace -o invoice-copy.pdf --aad "customer:42"

$ yace-codec algorithms
aes-256-gcm        AES-256-GCM from the audited cryptography package [default]
chacha20-poly1305  ChaCha20-Poly1305 from cryptography; fast without AES hardware
yace-hmac-sha256   HMAC-SHA256 keystream and tag; standard library only, slower

$ yace-codec keys list
default
team
$ yace-codec keys rotate team
rotated key 'team': new data uses the new key; data encrypted before still decrypts (...)

$ yace-codec encode --text "Hello, World!" | yace-codec decode
Hello, World!
$ yace-codec tables export groceries -o groceries.json
$ yace-codec tables import groceries.json --family groceries --keystore colleague.json
added: groceries-3:1
added: groceries-3:2
2 added, 0 unchanged, 0 replaced (colleague.json)
```

**Your secret token**, safest first:

- `--token` (or `-p`) asks for it without echoing it (twice when encrypting). It
  needs a terminal; without one, it says so instead of waiting.
- `--token-file PATH` reads it from a file you protect (UTF-8, or UTF-16 with a byte
  order mark as PowerShell writes it; one trailing newline is ignored).
- `--token-stdin` reads it from the first line of standard input; give the data as a
  file or with `--text`.

The `YACE_CODEC_TOKEN` and `YACE_CODEC_PASSWORD` environment variables still work
with `--token`, but are deprecated (other programs running as you can read them) and
print a warning. Without a token option, `encrypt` uses a stored key (`--key NAME`,
default `default`) and `decrypt` tries every current and retired stored key, from
`--key-backend json|dpapi|keyring`. With `dpapi`, `-k PATH` still names the key store,
and the keys go in `keys-dpapi.json` next to it.

**Output files.** `-o PATH` is written to a temporary file that replaces `PATH` only
when everything succeeded, so a failed decryption never leaves a partial file, and a
file can be encrypted onto itself. Decrypted and decoded files are created readable
only by you, and so are exported keys and tables. Standard output cannot be taken
back: if decryption fails part way, discard what was printed. In Windows PowerShell,
use `-o` for binary output: its `>` redirection rewrites bytes.

**Imports.** `tables import` needs `--family NAME` (or `--all-families`), and
`keys import` needs `--name NAME` (or `--all-keys`), so a shared file cannot slip in
tables or keys you use. `keys delete` needs `--yes`.

| Command | Options |
|---|---|
| `encrypt [INPUT]` | `-t/--text TEXT`, `-o/--output PATH`; one of `--key NAME`, `-p/--token`, `--token-file PATH`, `--token-stdin`; `-a/--algorithm NAME`, `--aad TEXT`, `-f/--format text\|bytes`, `--key-backend json\|dpapi\|keyring`, `-k/--keystore PATH` |
| `decrypt [INPUT]` | `-t/--text TEXT`, `-o/--output PATH`; one of `-p/--token`, `--token-file PATH`, `--token-stdin`; `--aad TEXT`, `--max-age SECONDS`, `--key-backend ...`, `-k/--keystore PATH` |
| `algorithms` | |
| `keys list` | `--key-backend ...`, `-k/--keystore PATH` |
| `keys rotate NAME` | `--key-backend ...`, `-k/--keystore PATH` |
| `keys delete NAME` | `--yes` (required), `--key-backend ...`, `-k/--keystore PATH` |
| `keys export NAME` | `-o/--output PATH`, `--key-backend ...`, `-k/--keystore PATH` |
| `keys import FILE` | `--name NAME` or `--all-keys` (one is required), `--overwrite`, `--key-backend ...`, `-k/--keystore PATH` |
| `encode [INPUT]` | `-t/--text TEXT`, `-o/--output PATH`, `-n/--name NAME` (default `default`), `-l/--length N` (2–62, default 2), `-i/--iterations N` (1–32, default 3), `-b/--binary`, `-k/--keystore PATH` |
| `decode [INPUT]` | `-t/--text TEXT`, `-o/--output PATH`, `-b/--binary`, `-k/--keystore PATH` |
| `tables path` / `tables list` | `-k/--keystore PATH` |
| `tables export NAME` | `-o/--output PATH`, `-k/--keystore PATH` |
| `tables import FILE` | `--family NAME` or `--all-families` (one is required), `--overwrite`, `-k/--keystore PATH` (`-` as `FILE` reads standard input) |

`--password` is another name for `--token`; `--version` prints the version. Text is
read and written as UTF-8 (UTF-16 and UTF-32 input with a byte order mark is
accepted), and `decode` returns exactly the bytes that were encoded. Errors print
`yace-codec: error: …` and exit with status 1; invalid arguments exit with status 2.

## API reference

Everything below is importable from `yace_codec`.

### Functions

| Function | Description |
|---|---|
| `encrypt(data, key=None, *, token=None, keystore=None, key_backend=None, aad=b"", algorithm=None, output="text") -> str \| bytes` | Encrypt text or bytes. The secret is your `token`, a raw 32-byte `key`, or the stored key named `key` (default `"default"`, created on first use). Returns `str` for `output="text"`, `bytes` for `output="bytes"`. |
| `decrypt(encrypted, *, token=None, keys=None, aad=b"", max_age=None, keystore=None, key_backend=None) -> str \| bytes` | Decrypt any format (text or bytes, message or stream, 0.2.x included); returns `str` or `bytes`, as encrypted. `keys` limits decryption to those raw keys. |
| `encrypt_stream(src, dst, key=None, *, token=None, keystore=None, key_backend=None, aad=b"", algorithm=None, output="text", text=False, chunk_size=65536) -> int` | Encrypt a binary file object or path in constant memory; returns the bytes written. |
| `decrypt_stream(src, dst, *, token=None, keys=None, aad=b"", max_age=None, keystore=None, key_backend=None) -> StreamInfo` | Decrypt into a binary file object or path. |
| `generate_key() -> bytes` | A new random 32-byte key. |
| `algorithms() -> list[AlgorithmInfo]` | The encryption algorithms, the default first. |
| `open_key_backend(kind, *, path=None, service=None) -> KeyBackend` | Open the `"json"` or `"dpapi"` backend (at `path`) or the `"keyring"` backend (under `service`, default `"yace-codec"`). |
| `encode(text, name="default", *, length=2, iterations=3, keystore=None) -> str` | Encode `text`. Missing tables are generated and saved. |
| `decode(token, *, keystore=None) -> str` | Decode a token: a `str`, or `bytes` in UTF-8 (UTF-16 and UTF-32 need a byte order mark). |
| `encode_bytes(data, name="default", *, length=2, iterations=3, keystore=None) -> str` | Encode any bytes (base64 first). |
| `decode_bytes(token, *, keystore=None) -> bytes` | Decode a token made by `encode_bytes`. |
| `parse_header(token) -> Header` | Read an encoded token's header without decoding it. |
| `default_keystore_path() -> pathlib.Path` | Where the default key store lives (an absolute path). |

`keystore` accepts a `KeyStore`, a path, or `None` for the default key store.
`key_backend` accepts a `KeyBackend`, a backend name (`"json"`, `"dpapi"`,
`"keyring"`), or `None` for the key store's own keys. With a `token`, a raw `key`, or
`keys`, no key store is used at all. `password=` works everywhere as another name for
`token=`. Every argument is checked before a key is created.

### `Codec(keystore=None, *, rng=None, key_backend=None)`

Encodes, decodes, encrypts, and decrypts with one key store. It has the same
`encode`, `decode`, `encode_bytes`, `decode_bytes`, `encrypt`, `decrypt`,
`encrypt_stream`, and `decrypt_stream` methods as the functions above (without the
`keystore` and `key_backend` arguments), and `keystore` and `key_backend`
attributes. `rng` replaces the system random source with a `random.Random`, for
reproducible tests only.

### `KeyStore(path)`

The key store file; also the default key backend. A relative path is resolved
against the current directory when the `KeyStore` is created. The file is created on
the first write.

| Member | Description |
|---|---|
| `KeyStore.default()`, `KeyStore.in_memory()` | Open the default key store; create a store that is never written to disk. |
| `path` | The absolute file path, or `None` for an in-memory store. |
| `get(name) -> Table`, `find(name) -> Table \| None` | A table, or `TableNotFoundError` / `None`. |
| `ensure_tables(family, length, iterations, *, rng=None) -> list[Table]` | The family's tables, generating missing ones. |
| `table_names() -> list[str]`, `families() -> list[Family]` | Table names; tables grouped as `Family(name, length, layers)`. |
| `export_family(family) -> dict` | All tables of a family, as JSON-ready data. |
| `import_tables(tables, *, overwrite=False, family=None) -> ImportResult` | Add tables; with `family`, only that family's. Validates everything first and writes nothing if every table is already there. |
| `reload()` | Drop cached data and re-read the file on next use. |
| `name in store`, `len(store)` | Membership test and count, for tables. |

### Key backends

`KeyBackend` is the interface; `KeyStore`, `DpapiKeyStore(path=None)` (Windows), and
`KeyringKeyStore(service="yace-codec")` implement it:

| Member | Description |
|---|---|
| `ensure_key(name, *, rng=None) -> bytes` | The current key `name`, created and saved if missing. |
| `get_key(name) -> bytes`, `find_key(name) -> bytes \| None` | The current key `name`, or `KeyNotFoundError` / `None`. |
| `key_names() -> list[str]` | Names of the stored keys. |
| `rotate_key(name, *, rng=None) -> bytes` | A new key for `name` (created if missing); the old one is kept for decryption. |
| `delete_key(name)` | Remove a key and its retired keys. |
| `decryption_keys() -> list[bytes]` | Every current and retired key. A damaged entry is skipped with a warning. |
| `export_key(name) -> dict` | A key and its retired keys as portable JSON data. |
| `import_keys(keys, *, overwrite=False, name=None) -> ImportResult` | Add keys; with `name`, only that key. |

### Data types

- `Header(family, length, iterations)`: `str(header)` gives the header line, and
  `header.table_names` lists the tables needed for decoding.
- `Table`: an immutable, validated table with `name`, `length`, `codes`,
  `space_codes`, `bin_codes`, and `characters`, plus `to_dict()`,
  `Table.from_dict(name, data)`, and `Table.generate(name, rng)`.
- `ImportResult(added, unchanged, replaced)`: entries affected by an import.
- `StreamInfo(size, text)`: what `decrypt_stream` wrote, and whether it was text.
- `AlgorithmInfo(name, id, tag_size, available, default, description)`.

### Exceptions

```text
YaceError
├── InvalidNameError           invalid family or key name (also a ValueError)
├── InvalidKeyError            a raw key is not 32 bytes (also a ValueError)
├── EncodingError              invalid input or settings, unknown algorithm (also a ValueError)
│   └── UnsupportedCharacterError   .characters, .table_name
├── DecodingError              malformed, truncated, or corrupted input (also a ValueError)
│   └── DecryptionError        cannot be opened: wrong token, key, or aad, or the data was changed
│       └── TokenExpiredError  it was encrypted longer ago than max_age
├── TableNotFoundError         a needed table is missing; .table_name (also a LookupError)
│   └── KeyNotFoundError       a stored key is missing; .key_name
└── KeyStoreError              unreadable, invalid, or unwritable key store or backend
```

Wrong argument types raise `TypeError`. Messages and `repr()` never contain keys or
secret tokens, and invalid key names are not repeated in errors.

### Constants

`DEFAULT_ALGORITHM` (`"aes-256-gcm"`), `DEFAULT_CHUNK_SIZE` (65536),
`DEFAULT_FAMILY` (`"default"`), `DEFAULT_KEY` (`"default"`), `DEFAULT_LENGTH` (2),
`DEFAULT_ITERATIONS` (3), `KEY_SIZE` (32), `MAX_MESSAGE_SIZE` (2<sup>31</sup> − 1),
`MIN_LENGTH` (2), `MAX_LENGTH` (62), `MAX_ITERATIONS` (32), `MAX_ENCODED_CHARS`
(2<sup>25</sup>), `SUPPORTED_CHARACTERS`, `ENV_VAR` (`"YACE_CODEC_KEYSTORE"`), and
`__version__`.

## The key store file

| Platform | Default path |
|---|---|
| Windows | `%APPDATA%\yace-codec\keystore.json` |
| macOS | `~/Library/Application Support/yace-codec/keystore.json` |
| Linux and other systems | `$XDG_DATA_HOME/yace-codec/keystore.json` (default `~/.local/share/...`) |

Set the `YACE_CODEC_KEYSTORE` environment variable, pass `--keystore`, or pass a path
or `KeyStore` to the API to use another file. It is a JSON object that maps table
names to tables (the format of the original scripts' `encodings.json`), plus stored
keys as `key:<name>` entries holding a base64 `secret` and, after rotation, a
`retired` list:

```json
{"team-3:1": {"!": "B1x", "a": "yI4", "...": "...", " ": ["6nM", "..."], "bin": ["EbC", "..."]},
 "key:team": {"secret": "q2v...=", "retired": ["Zk1...="]}}
```

- **It holds secrets in plain text.** Anyone who can read the file can decode your
  tokens and decrypt everything encrypted with its keys. **Back it up:** if you lose
  it, those tokens and that data are gone. Keep stored keys in the `dpapi` or
  `keyring` backend to keep them out of the file.
- **New files are private:** mode `0600` (and a `0700` folder) on POSIX, an
  owner-only access control list on Windows. An existing file keeps its permissions,
  owner, and group, so a deliberately shared key store stays shared. (On Windows, key
  stores created before 0.3.0 inherited their folder's permissions: check them with
  `icacls`.)
- **Writes are atomic and safe in parallel.** Data goes to a temporary file that
  replaces the key store, under a `keystore.json.lock` lock file, so a crash cannot
  leave a half-written file and parallel processes never lose each other's changes.
  A symbolic link is followed; a key store with several hard links is refused.
- **Existing entries are never changed** except by an explicit overwrite, rotation,
  or deletion. Damaged files are left alone (you get a `KeyStoreError`), and entries
  the package does not understand are kept.

## Security

- **Encoding is not encryption.** It is a substitution code: frequency analysis, or a
  few tokens with known text, breaks it, and it has no integrity protection.
- **Encryption is not audited.** AES-256-GCM and ChaCha20-Poly1305 come from the
  audited `cryptography` package and keys are derived with HKDF-SHA256 and scrypt,
  but yace-codec's formats, header mask, and streaming construction are its own
  design. For high-stakes data, use the default algorithm and consider an audited
  higher-level tool.
- **A secret token is only as strong as you make it.** scrypt slows guessing, but a
  short or common token can be found. Raw and stored keys are 32 random bytes.
- **The JSON key store holds keys in plain text.** Use the `dpapi` or `keyring`
  backend to keep them out of a file.
- **There is no forward secrecy**: a leaked token or key opens earlier data too.
- **Stream output can be partial**: `decrypt_stream()` writes verified chunks before
  it reaches the end; discard the output if it raises.

[SECURITY.md](https://github.com/thisismudith/YACE/blob/main/SECURITY.md) has the
threat model, the byte-level format specification, supported versions, and how to
report a vulnerability privately.

## How it works

### How encryption works

1. A random 16-byte salt is drawn every time.
2. The secret is a 32-byte key, or your secret token stretched with scrypt
   (N = 2<sup>17</sup>, r = 8, p = 1) and the salt.
3. HKDF-SHA256 derives, from the secret and the salt, the algorithm's key (and nonce,
   or keys) and a mask for the header. Every output gets its own keys, so a nonce is
   never reused under a key.
4. A frame holds the data type, the creation time, the length, the data, and zero
   padding up to a Padmé length.
5. The algorithm encrypts the frame. Its 16-byte tag covers the salt, the format
   version and algorithm id, the length-prefixed associated data, and the ciphertext.
6. The output is `salt || masked header || ciphertext || tag`. The masked header
   hides the version, the algorithm, and four check bytes that let decryption reject
   a wrong key at once. Text output writes every 8 bytes as 11 letters and digits.

Streams seal each chunk separately, with the chunk index and a final-chunk flag in
its nonce. [SECURITY.md](https://github.com/thisismudith/YACE/blob/main/SECURITY.md)
specifies both formats byte by byte, and `tests/vectors/` has test vectors for every
algorithm.

### How encoding works

A table maps each character to a code of `length` letters and digits; the space gets
**10 codes**, picked at random, and each table holds **26 bin codes** (noise). No code
repeats. Encoding `"Hi Bob"` with family `demo`, code length 2, and 1 iteration:

1. **Substitute.** Each character becomes its code from `demo-2:1` (`H`→`lN`,
   `i`→`bx`, `B`→`bJ`, `o`→`La`, `b`→`4R`); the space becomes `ni`, one of its codes:
   `lN bx ni bJ La 4R`.
2. **Repeat for each iteration.** Layer *k* encodes the output of layer *k−1* with
   table `demo-2:k`; codes are letters and digits, so every layer can encode them.
3. **Insert bins.** ⌈chunks / 4⌉ random bin codes go into random positions (here 2,
   the code `J3` twice): `J3 lN bx ni bJ J3 La 4R`.
4. **Swap chunks.** For x = L, 2L, 3L, … while x < n (L is the code length, n the
   number of chunks), chunk x−1 swaps with chunk n−x: `J3 La J3 bJ ni bx lN 4R`.
5. **Add the header**: `demo-2:1`, a newline, then `J3LaJ3bJnibxlN4R`.

Decoding reverses these steps; the swap is its own inverse. For *n* characters, code
length *L*, and *I* iterations, the body has *L* · (*m* + ⌈*m* / 4⌉) characters,
where *m* = *n* · *L*<sup>*I*−1</sup>: with the defaults, 13 characters become 130.
The swap uses no key, so it hides nothing from someone who knows the format; the
tables are the only secret.

## Migrating from the original scripts

<details>
<summary>From the <code>encoder/</code> scripts used before version 0.1.0</summary>

The package keeps the original algorithm, table format, and token format.

- **Keep your old tables.** If you still have tokens made with the original scripts,
  keep your copy of `encoder/encodings.json` (it was removed in 0.1.0): it is the key
  store those tokens need. Use it with `--keystore path/to/encodings.json` or
  `KeyStore("path/to/encodings.json")`, or import it with
  `yace-codec tables import path/to/encodings.json --all-families`.
- **New tokens decode with the original scripts** when the package generated the
  tables.
- Errors raise exceptions instead of calling `exit()`, and characters a table cannot
  encode raise `UnsupportedCharacterError` instead of corrupting the token. See the
  [0.1.0 changelog](https://github.com/thisismudith/YACE/blob/main/CHANGELOG.md#010---2026-10-14)
  for every change.

| Original scripts | yace-codec |
|---|---|
| `Encoder().encoding_loop(data, hash_length, final_hash_iteration, hash_name)` | `Codec().encode(data, hash_name, length=hash_length, iterations=final_hash_iteration)` |
| `Decoder().decode_string(data)` | `Codec().decode(data)` |
| `randomizer.random_main(hash_length, hash_name, hash_iteration)` | `KeyStore(path).ensure_tables(hash_name, hash_length, hash_iteration)` |
| `encodings.json` next to the scripts | a key store file in your user data directory |

</details>

## Development and contributing

```bash
git clone https://github.com/thisismudith/YACE.git
cd YACE
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[test,keyring]" mypy
python -m pytest
python -m mypy --strict src/yace_codec
python benchmarks/bench.py         # throughput per algorithm (not a test)
```

The tests run the examples and the Python snippets in this README, decrypt the
published test vectors with an independent implementation, and check output made by
earlier releases. Issues and pull requests are welcome at
<https://github.com/thisismudith/YACE>: open an issue first for larger changes, and
keep output of earlier versions readable.

## License, links, and author

MIT, see [LICENSE](https://github.com/thisismudith/YACE/blob/main/LICENSE). Source:
<https://github.com/thisismudith/YACE> · Issues:
<https://github.com/thisismudith/YACE/issues> · PyPI:
<https://pypi.org/project/yace-codec/> · Changelog:
<https://github.com/thisismudith/YACE/blob/main/CHANGELOG.md>

By Mudith Daga ([@thisismudith](https://github.com/thisismudith)). Not affiliated
with the `yace` package on PyPI ("Yet Another Code Emitter") or its `yace-*`
companions, nor with YACE, the Prometheus CloudWatch exporter.

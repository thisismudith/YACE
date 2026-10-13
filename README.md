# YACE

**Reversible text encoding with random substitution tables, layered re-encoding, noise chunks, and chunk shuffling.**

[![PyPI](https://img.shields.io/pypi/v/yace-codec)](https://pypi.org/project/yace-codec/)
[![Python versions](https://img.shields.io/pypi/pyversions/yace-codec)](https://pypi.org/project/yace-codec/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/thisismudith/YACE/blob/main/LICENSE)

YACE (Yet Another Custom Encoder) turns text into tokens made of random-looking
letters and digits. Decoding a token needs the substitution tables that produced
it, which you keep in a key store. It ships as a Python library and a command-line
tool with no third-party dependencies.

| | |
|---|---|
| PyPI distribution | `yace-codec` |
| Import name | `yace_codec` |
| Command | `yace-codec` |

This project is not affiliated with the `yace` package on PyPI ("Yet Another Code
Emitter") or its `yace-*` companions, nor with YACE, the Prometheus CloudWatch
exporter.

> **Warning: YACE obfuscates; it does not encrypt.** At its core it is a substitution
> code with extra noise. Frequency analysis, or a couple of tokens whose text an
> attacker knows, can break it. Do not use it to protect passwords, personal data,
> API keys, or anything else that must stay secret. Use a vetted library such as
> [`cryptography`](https://cryptography.io/) for that.

## Contents

- [Why YACE](#why-yace)
- [How the encoder works](#how-the-encoder-works)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Command line](#command-line)
- [API reference](#api-reference)
- [The key store](#the-key-store)
- [Limits and edge cases](#limits-and-edge-cases)
- [Security](#security)
- [Migrating from the original scripts](#migrating-from-the-original-scripts)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Why YACE

Common encodings such as base64 or hex are public mappings, so anyone can reverse
them. Decoding a YACE token needs the tables in your key store, and encoding the same
text twice usually gives two different tokens.

You can use YACE to:

- keep text from being read at a glance, when it is not actually secret (puzzle or
  game content, test fixtures, or messages for people you share tables with);
- produce plain ASCII output: a short header line followed by a body of letters and
  digits only;
- learn how substitution, homophones, nulls, and transposition combine in classical
  ciphers.

| | base64 / hex | YACE | Encryption (e.g. Fernet) |
|---|---|---|---|
| Who can decode | anyone | holders of the tables, or an attacker with enough samples | holders of the key |
| Same input, same output | yes | usually not | no |
| Resists cryptanalysis | no | no | yes |
| Detects tampering | no | no (only some corruption) | yes |
| Output size | 1.33x / 2x | about 1.25 x length<sup>iterations</sup> | about 1.33x plus a fixed overhead |

## How the encoder works

### Tables, families, and the key store

A **table** maps each of the 100 characters in Python's
[`string.printable`](https://docs.python.org/3/library/string.html#string.printable)
to a random **code** of `length` ASCII letters and digits:

- every character except the space gets one code;
- the space gets **10 codes**, and the encoder picks one at random for each space;
- each table also holds **26 bin codes**: noise chunks that the encoder inserts and
  the decoder drops.

Every code in a table is unique, and no code repeats a character.

Tables are named `<family>-<length>:<layer>`, for example `team-3:1`. Encoding with
family `team`, code length 3, and 2 iterations uses the tables `team-3:1` and
`team-3:2`. Missing tables are generated on first use and saved in the
**key store**, a JSON file. The key store is the key: decoding needs the tables that
encoded a token.

### Encoding, step by step

Encoding `"Hi Bob"` with family `demo`, code length 2, and 1 iteration, using a
seeded random generator so the example is reproducible:

1. **Substitute.** Each character is replaced by its code from `demo-2:1`
   (`H`→`lN`, `i`→`bx`, `B`→`bJ`, `o`→`La`, `b`→`4R`). The space becomes `ni`, one
   of its 10 codes chosen at random.

   ```text
   lN bx ni bJ La 4R                 6 chunks of 2 characters
   ```

2. **Repeat for each iteration.** With more iterations, layer *k* encodes the output
   of layer *k−1* with table `demo-2:k`. Codes consist of letters and digits, which
   every table covers, so each layer multiplies the length by the code length.

3. **Insert bins.** ⌈chunks / 4⌉ random bin codes from the last table go into random
   chunk positions. Here ⌈6 / 4⌉ = 2, and the bin code `J3` was picked twice:

   ```text
   J3 lN bx ni bJ J3 La 4R           8 chunks
   ```

4. **Swap chunks.** For x = L, 2L, 3L, … (L is the code length) while x < n (the
   number of chunks), chunk x−1 swaps with chunk n−x. Here L = 2 and n = 8, so the
   pairs are (1, 6), (3, 4) and (5, 2):

   ```text
   J3 La J3 bJ ni bx lN 4R
   ```

5. **Add the header.** The token is `<family>-<length>:<iterations>`, a newline, and
   the chunks:

   ```text
   demo-2:1
   J3LaJ3bJnibxlN4R
   ```

**Decoding** reverses these steps. It reads the header, loads tables
`demo-2:1` … `demo-2:I`, undoes the swap (the swap is its own inverse), drops the
bins, and maps codes back to characters from the last layer down to the first.

### Token size

For a text of *n* characters, code length *L*, and *I* iterations:

- data chunks: *m* = *n* · *L*<sup>*I*−1</sup>
- bins: ⌈*m* / 4⌉
- token body: *L* · (*m* + ⌈*m* / 4⌉) characters, plus the header line

With the defaults (*L* = 2, *I* = 3), `"Hello, World!"` (13 characters) becomes a
130-character body: about 10 times the input.

### Design decisions

- **Letters and digits only.** The token body is safe to copy, paste, and embed,
  and each layer's output is valid input for the next layer.
- **Unique codes.** No two entries in a generated table share a code, so decoding is
  never ambiguous. (The original generator could produce shared codes; see
  [Migrating](#migrating-from-the-original-scripts).)
- **Several codes for the space.** The most common character in most text has no
  single code, so equal texts usually give different tokens.
- **A fixed number of bins.** The bin count depends only on the data length. The
  decoder uses this to check a token's length and to tell how many bins it holds.
- **A self-inverse swap.** The same function shuffles and unshuffles chunks. It uses
  no key, so it hides nothing from someone who knows the format.
- **System randomness.** Tables, space codes, and bins come from the operating
  system's cryptographic random source (`secrets.SystemRandom`), so tables are not
  predictable from a seed. This does not make the scheme secure (see
  [Security](#security)).

## Installation

```bash
python -m pip install yace-codec
```

On Windows, `py -m pip install yace-codec` works too.

To install the latest code from GitHub:

```bash
python -m pip install "git+https://github.com/thisismudith/YACE.git"
```

YACE needs Python 3.9 or newer and has no third-party dependencies.

## Quick start

```python
import yace_codec as yace

token = yace.encode("Hello, World!")
print(token)
print(yace.decode(token))
```

Example output (tables and tokens are random, so yours will differ):

```text
default-2:3
IjC5wSwsIjMkC5wKIvpGZw7qxjed1zIj7qWlxjhp1zQcnNUNw4OrWlMkxj3DOmGaqSGDZwsGg17qsGYxSAwsg1QcwspGYxOrwSV9SApGwSZwxj7q1zao1zYxUNV9VGD4wG
Hello, World!
```

`encode()` and `decode()` use the [default key store](#the-key-store) and the
defaults `name="default"`, `length=2`, `iterations=3`.

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

A `Codec` reuses one key store, which is faster than the module-level functions
when you encode many values.

### Reading a token's header

```python
header = yace.parse_header(token)
print(header)
print(header.family, header.length, header.iterations)
print(header.table_names)
```

```text
team-3:2
team 3 2
('team-3:1', 'team-3:2')
```

### Same text, different tokens

```python
a = codec.encode("same text", "team", length=3, iterations=2)
b = codec.encode("same text", "team", length=3, iterations=2)
print(a == b, codec.decode(a) == codec.decode(b) == "same text")
```

```text
False True
```

Empty and very short texts are the exception: they have so few possible tokens that
the same token can come out twice.

### Sharing tables

To let someone decode your tokens, export the family and have them import it.
Only that family is shared; your other families stay private.

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

Between machines, use `yace-codec tables export` and `tables import` (see
[Command line](#command-line)). On POSIX systems the export command creates the file
with owner-only permissions.

When you import tables from someone else, import only the family you expect
(`family=` in Python, or the command line's default behaviour). A file could
otherwise add tables for a family you use, such as `default`, and its sender could
then decode your later tokens.

### Unicode text and binary data

`encode()` accepts the 100 characters of `string.printable`. For any other text, or
for binary data, use `encode_bytes()`. It base64-encodes the bytes first, which makes
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

More runnable scripts are in
[`examples/`](https://github.com/thisismudith/YACE/tree/main/examples).

## Command line

Installing the package adds the `yace-codec` command (`python -m yace_codec` works
too). Input comes from a file argument, `--text`, or standard input. Output goes to
`-o PATH` or standard output.

```console
$ yace-codec encode --text "Hello, World!"
default-2:3
M0nsak8qa3KdTOLRKdKtenPBM0KMMtRfRfi6KMM0KfiKluO8O87d7dVW7dSzDLFp7dnsLRa2gL8qKfnsluMGGZ7dpSPBi6M0i4PBM0KMptRfWDuDFpKfpSHlaB8qiKi6kO

$ yace-codec encode --text "Hello, World!" | yace-codec decode
Hello, World!
```

Encode a file with your own family and settings, then decode it:

```console
$ yace-codec encode notes.txt -o notes.yace --name groceries --length 3 --iterations 2
$ yace-codec decode notes.yace
Shopping list:
- milk
- 12 eggs
```

Encode any file byte for byte with `--binary` (use it again when decoding):

```console
$ yace-codec encode --binary photo.jpg -o photo.yace
$ yace-codec decode --binary photo.yace -o photo-copy.jpg
```

Inspect and share tables:

```console
$ yace-codec tables list
NAME       LENGTH  LAYERS
default    2       1,2,3
files      2       1
groceries  3       1,2

$ yace-codec tables export groceries -o groceries.json
$ yace-codec tables import groceries.json --keystore colleague.json
added: groceries-3:1
added: groceries-3:2
2 added, 0 unchanged, 0 replaced (colleague.json)

$ yace-codec tables path
C:\Users\you\AppData\Roaming\yace-codec\keystore.json
```

`tables import` refuses a file that holds tables for more than one family, because
such a file could replace a family you use. Choose one with `--family NAME`, or pass
`--all-families` if you trust the file:

```console
$ yace-codec tables import mixed.json
yace-codec: error: mixed.json holds tables for 2 families (default, groceries); choose one with --family NAME, or import all with --all-families
```

| Command | Options |
|---|---|
| `encode [INPUT]` | `-t/--text TEXT`, `-o/--output PATH`, `-n/--name NAME` (default `default`), `-l/--length N` (default 2), `-i/--iterations N` (default 3), `-b/--binary`, `-k/--keystore PATH` |
| `decode [INPUT]` | `-t/--text TOKEN`, `-o/--output PATH`, `-b/--binary`, `-k/--keystore PATH` |
| `tables path` | `-k/--keystore PATH` |
| `tables list` | `-k/--keystore PATH` |
| `tables export NAME` | `-o/--output PATH`, `-k/--keystore PATH` |
| `tables import FILE` | `--family NAME` or `--all-families`, `--overwrite`, `-k/--keystore PATH` (use `-` as `FILE` for standard input) |

Text mode reads and writes UTF-8 and keeps line endings unchanged, so `decode`
returns exactly the bytes that were encoded. Token and JSON files saved by Windows
PowerShell (UTF-16, or UTF-8 with a byte order mark) are accepted. Errors print
`yace-codec: error: …` and exit with status 1. Invalid arguments exit with status 2.

## API reference

Everything below is importable from `yace_codec`.

### Functions

| Function | Description |
|---|---|
| `encode(text, name="default", *, length=2, iterations=3, keystore=None) -> str` | Encode `text`. Missing tables are generated and saved. |
| `decode(token, *, keystore=None) -> str` | Decode a token: a `str`, or `bytes` in UTF-8 (UTF-16 and UTF-32 need a byte order mark). |
| `encode_bytes(data, name="default", *, length=2, iterations=3, keystore=None) -> str` | Encode any bytes (base64 first). |
| `decode_bytes(token, *, keystore=None) -> bytes` | Decode a token made by `encode_bytes`. |
| `parse_header(token) -> Header` | Read a token's header without decoding it. |
| `default_keystore_path() -> pathlib.Path` | Where the default key store lives (an absolute path). |

`keystore` accepts a `KeyStore`, a path to a key store file, or `None` for the
default key store.

### `Codec(keystore=None, *, rng=None)`

Encodes and decodes with one key store. It has the same `encode`, `decode`,
`encode_bytes`, and `decode_bytes` methods as the functions above (without the
`keystore` argument), and a `keystore` attribute. `rng` replaces the system random
source with a `random.Random`, for reproducible tests only.

### `KeyStore(path)`

A key store file. A relative path is resolved against the current directory when
the `KeyStore` is created. The file is created on the first write.

| Member | Description |
|---|---|
| `KeyStore.default()` | Open the default key store. |
| `KeyStore.in_memory()` | Create a store that is never written to disk. |
| `path` | The absolute file path, or `None` for an in-memory store. |
| `get(name) -> Table` | Return a table, or raise `TableNotFoundError`. |
| `find(name) -> Table \| None` | Return a table, or `None`. |
| `ensure_tables(family, length, iterations, *, rng=None) -> list[Table]` | Return the family's tables, generating missing ones. |
| `table_names() -> list[str]` | Names of all tables, sorted. |
| `families() -> list[Family]` | Tables grouped as `Family(name, length, layers)`. |
| `export_family(family) -> dict` | All tables of a family, as JSON-ready data. |
| `import_tables(tables, *, overwrite=False, family=None) -> ImportResult` | Add tables; with `family`, only that family's. Returns `ImportResult(added, unchanged, replaced)`. |
| `reload()` | Drop cached data and re-read the file on next use. |
| `name in store`, `len(store)` | Membership test and table count. |

`import_tables` validates every table before it writes anything, and it writes
nothing when every table is already present. It raises `KeyStoreError` if a table
already exists with different codes, unless `overwrite=True`.

### Data types

- `Header(family, length, iterations)`: a named tuple. `str(header)` gives the header
  line, and `header.table_names` lists the tables needed for decoding.
- `Table`: an immutable, validated table with `name`, `length`, `codes` (a read-only
  mapping from character to code), `space_codes`, `bin_codes`, and `characters` (what
  it can encode), plus `to_dict()`, `Table.from_dict(name, data)`, and
  `Table.generate(name, rng)`.

### Exceptions

```text
YaceError
├── InvalidNameError           invalid family name (also a ValueError)
├── EncodingError              invalid settings (also a ValueError)
│   └── UnsupportedCharacterError   .characters, .table_name
├── DecodingError              malformed or corrupted token, or wrong tables (also a ValueError)
├── TableNotFoundError         a needed table is missing; .table_name (also a LookupError)
└── KeyStoreError              unreadable, invalid, or unwritable key store
```

### Constants

`DEFAULT_FAMILY` (`"default"`), `DEFAULT_LENGTH` (2), `DEFAULT_ITERATIONS` (3),
`MIN_LENGTH` (2), `MAX_LENGTH` (62), `MAX_ITERATIONS` (32), `MAX_ENCODED_CHARS`
(2<sup>25</sup>), `SUPPORTED_CHARACTERS`, `ENV_VAR` (`"YACE_CODEC_KEYSTORE"`), and
`__version__`.

## The key store

The default key store is:

| Platform | Path |
|---|---|
| Windows | `%APPDATA%\yace-codec\keystore.json` |
| macOS | `~/Library/Application Support/yace-codec/keystore.json` |
| Linux and other systems | `$XDG_DATA_HOME/yace-codec/keystore.json` (default `~/.local/share/...`) |

Set the `YACE_CODEC_KEYSTORE` environment variable, pass `--keystore` to the
command, or pass a path or `KeyStore` to the API to use another file.

The file is a JSON object that maps table names to tables, in the same format as the
original scripts' `encodings.json`:

```json
{"team-3:1": {"!": "B1x", "a": "yI4", "...": "...", " ": ["6nM", "..."], "bin": ["EbC", "..."]}}
```

How the key store behaves:

- **Existing tables are never changed.** New tables are only added, except through
  `import_tables(..., overwrite=True)`.
- **Writes are atomic.** Data goes to a temporary file that then replaces the key
  store, so a crash cannot leave a half-written file. A symbolic link is followed,
  so the file it points to is updated and the link stays. A key store with more than
  one hard link is refused instead, because replacing it would split the copies.
- **Permissions are kept.** New key store files get mode `0600`, and a new
  `yace-codec` directory gets mode `0700`, on POSIX. An existing key store keeps its
  access control list on Windows, and its mode on POSIX, plus its owner and group
  where the system allows it.
- **Concurrent writers are safe.** Writes are serialised with a `keystore.json.lock`
  file next to the key store, so parallel processes never lose each other's tables.
  Reading, and encoding with tables that already exist, need no write access.
- **Damaged files are left alone.** If the file is not valid JSON, you get a
  `KeyStoreError` and the file is not overwritten. Entries the package does not
  understand are kept.

**Back up your key store.** If you lose it, every token encoded with its tables
becomes undecodable. Anyone who has it can decode your tokens.

## Limits and edge cases

- **Characters.** `encode()` supports the 100 characters of `string.printable`:
  ASCII letters, digits, punctuation, space, `\t`, `\n`, `\r`, `\x0b`, and `\x0c`.
  It raises `UnsupportedCharacterError` before creating any table if the text
  contains anything else. Use `encode_bytes()` for other text. Tables from the
  original scripts do not cover `\t`, `\r`, `\x0b`, or `\x0c`.
- **Settings.** `length` must be 2–62 and `iterations` 1–32. Encoding is refused if
  `len(text) × length ** iterations` exceeds 2<sup>25</sup> (about 33 million token
  characters).
- **Size.** Tokens grow by `length ** iterations`, plus 25% for bins (see
  [Token size](#token-size)). Keep `iterations` small for long texts.
- **Memory and speed.** Encoding and decoding hold the whole input and token in
  memory and are written in pure Python. They need roughly 25–40 bytes of memory per
  token character, so tokens near the size limit need 1–2 GB. YACE is meant for
  strings and small to medium files, not streams.
- **Empty input.** Encoding `""` gives a header-only token, which decodes to `""`.
- **Whitespace.** Decoding ignores whitespace in a token, so wrapped lines, CRLF line
  endings, and leading blank lines are fine.
- **Corruption.** Decoding raises `DecodingError` when a chunk is not a valid code,
  when the length does not fit the code length, or when the number of noise chunks
  does not match the token length. These checks catch many truncations, but not all:
  removing or swapping data chunks can go unnoticed. Tokens have no cryptographic
  integrity check.
- **Bytes tokens.** `decode_bytes()` raises `DecodingError` if the decoded text is
  not base64. Short texts can happen to be valid base64, so keep track of which
  function made a token.
- **Family names.** Encoding needs a family name of 1–64 ASCII letters or
  underscores, including for existing families from the original scripts. Digits,
  `-`, and `:` are reserved for table names. Decoding accepts any family name the
  original scripts allowed, such as `my cat` or `café`, except a name that starts or
  ends with a space.

## Security

- YACE is a randomised substitution code with a keyless, public chunk shuffle.
  Within a family, every character except the space always has the same code. So
  frequency analysis over enough tokens recovers the text, and a couple of tokens
  whose text an attacker knows can be enough to decode other tokens.
- The header shows the family name, code length, and iteration count. The token
  length reveals the exact length of the text (for `encode_bytes`, of its base64
  form).
- Tokens have no integrity protection or authentication.
- The key store is the key. Store it like a credential, share single families with
  `tables export` instead of sharing the whole file, and import only the family you
  expect from files other people send you.
- Use real encryption (for example AES-GCM or Fernet from
  [`cryptography`](https://cryptography.io/)) whenever confidentiality matters.

To report a bug, including a security issue in the code, please
[open an issue](https://github.com/thisismudith/YACE/issues).

## Migrating from the original scripts

Before version 0.1.0, YACE was a set of scripts in `encoder/` that stored tables in
`encoder/encodings.json`. The package keeps the same algorithm, table format, and
token format.

- **Keep your old tables.** This release removes `encoder/encodings.json` from the
  repository, so copy it somewhere safe before you update if you still have tokens
  made with it. A clone that still has the old history can restore it with
  `git show 01d44a2:encoder/encodings.json > encodings.json`.
- **Old tokens decode with the package.** Use your old `encodings.json` as the key
  store (`--keystore path/to/encodings.json`, or `KeyStore("path/to/encodings.json")`),
  or import its tables with `yace-codec tables import path/to/encodings.json --all-families`.
- **New tokens decode with the original scripts when the package generated the
  tables.** With tables from the original generator, the original decoder can return
  wrong text when a token contains a character whose code that table also uses as a
  bin. About half of the original generator's length-2 tables have such a code.

| Original scripts | yace-codec |
|---|---|
| `Encoder().encoding_loop(data, hash_length, final_hash_iteration, hash_name)` | `Codec().encode(data, hash_name, length=hash_length, iterations=final_hash_iteration)` (returns the token only, not a tuple) |
| `Decoder().decode_string(data)` | `Codec().decode(data)` |
| `randomizer.random_main(hash_length, hash_name, hash_iteration)` | `KeyStore(path).ensure_tables(hash_name, hash_length, hash_iteration)` (creates every layer up to `hash_iteration` and returns `Table` objects) |
| `encodings.json` next to the scripts | a key store file in your user data directory |
| hash name, hash length, hash iteration | family name, length, iterations |

Behaviour changes:

- Errors raise exceptions instead of printing a message and calling `exit()`.
- Characters a table cannot encode raise `UnsupportedCharacterError`. Previously
  they were copied into the token unencoded, which corrupted it.
- Empty text works, a code length of 1 is rejected (it used to hang), and family
  names with repeated letters such as `hello` are accepted (the old check rejected
  them by mistake).
- Encoding needs a family name of ASCII letters and underscores, even for existing
  families. Families with other names, such as `my cat`, can still be decoded.
- Without a name, the family `default` is used instead of random letters.
- New tables cover tab, carriage return, vertical tab, and form feed, and never share
  codes.
- The original generator sometimes gave a space or a bin the same code as another
  entry, which could make the original decoder return garbled text. The package
  never emits a shared space or bin code. (A character keeps its code even when a
  legacy table also uses that code as a bin.) When it decodes old tokens, it uses the
  token length to tell how many bins they hold, and the fact that inner layers can
  only contain letters and digits. This recovers many tokens the original decoder
  could not. Some remain ambiguous: for example, a space that was encoded with a code
  shared by a character.
- `randomizer_data.json`, `errors.log`, and the unfinished file analyser were
  removed. Use `yace-codec encode FILE` (or `--binary`) to encode files.

## Development

```bash
git clone https://github.com/thisismudith/YACE.git
cd YACE
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e .
python examples/quickstart.py
```

To build the wheel and source distribution into `dist/`, run
`python -m pip install build` and then `python -m build`.

## Contributing

Issues and pull requests are welcome at
<https://github.com/thisismudith/YACE>.

1. Open an issue first for larger changes.
2. Keep the token and key store formats backward compatible: tokens made by earlier
   versions, and by the original scripts, must keep decoding.
3. Run the scripts in `examples/` to check your change.

## License

MIT. See [LICENSE](https://github.com/thisismudith/YACE/blob/main/LICENSE).

## Links

- Source: <https://github.com/thisismudith/YACE>
- Issues: <https://github.com/thisismudith/YACE/issues>
- PyPI: <https://pypi.org/project/yace-codec/>
- Changelog: <https://github.com/thisismudith/YACE/blob/main/CHANGELOG.md>

## Author

Mudith Daga ([@thisismudith](https://github.com/thisismudith))

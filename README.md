# YACE

**Reversible text encoding with random substitution tables, and authenticated encryption (AES-256-GCM by default) with your own secret token or keys.**

[![PyPI](https://img.shields.io/pypi/v/yace-codec)](https://pypi.org/project/yace-codec/)
[![Python versions](https://img.shields.io/pypi/pyversions/yace-codec)](https://pypi.org/project/yace-codec/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/thisismudith/YACE/blob/main/LICENSE)

YACE (Yet Another Custom Encoder) has two modes. Both come as a Python API and as
the `yace-codec` command:

- **Encoding** (`encode`/`decode`) turns text into tokens of random-looking letters
  and digits with YACE's substitution tables. It hides text from casual reading,
  but it is not encryption.
- **Encryption** (`encrypt`/`decrypt`) turns any text or file, of any size, into
  letters and digits (or compact bytes) that reveal nothing but their approximate
  size. Only your secret token or key can open them, and any change is detected.

| | |
|---|---|
| PyPI distribution | `yace-codec` |
| Import name | `yace_codec` |
| Command | `yace-codec` |

This project is not affiliated with the `yace` package on PyPI ("Yet Another Code
Emitter") or its `yace-*` companions, nor with YACE, the Prometheus CloudWatch
exporter.

> **Use `encrypt()` for secrets, never `encode()`.** Encoding is a substitution code
> with extra noise: frequency analysis, or a couple of tokens whose text an attacker
> knows, can break it. Encryption uses AES-256-GCM (or ChaCha20-Poly1305) from the
> audited [`cryptography`](https://cryptography.io/) package, with standard key
> derivation, but yace-codec's own formats and the way it combines these parts have
> not been audited. Read [Security](#security) before you rely on it for high-stakes
> data.

## Contents

- [Why YACE](#why-yace)
- [How the encoder works](#how-the-encoder-works)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Encryption](#encryption)
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
text twice usually gives two different tokens. Encryption goes further: without
your secret token or key, the output cannot be read, linked to its key, or changed
without detection.

You can use YACE to:

- keep text from being read at a glance, when it is not actually secret (puzzle or
  game content, test fixtures, or messages for people you share tables with);
- produce plain ASCII output: a short header line followed by a body of letters and
  digits only;
- encrypt messages and files for people who share a secret token or key with you;
- learn how substitution, homophones, nulls, and transposition combine in classical
  ciphers.

| | base64 / hex | YACE `encode` | YACE `encrypt` | Fernet (`cryptography`) |
|---|---|---|---|---|
| Who can read it | anyone | holders of the tables, or an attacker with enough samples | holders of the secret token or key | holders of the key |
| Same input, same output | yes | usually not | no | no |
| Resists cryptanalysis | no | no | yes by design (audited AEAD; the format is not audited) | yes (audited) |
| Detects tampering | no | no (only some corruption) | yes | yes |
| Hides the length | no | no | roughly (Padmé padding) | no |
| Binds to a context (associated data) | no | no | yes | no |
| Output size | 1.33x / 2x | about 1.25 x length<sup>iterations</sup> | text: about 1.4x plus 70 characters; bytes: 1.0x plus 51 bytes (plus up to 12% padding) | about 1.33x plus a fixed overhead |

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

YACE needs Python 3.10 or newer. Its one dependency is
[`cryptography`](https://cryptography.io/), which provides the default encryption
algorithm. Optional extras:

| Extra | Adds |
|---|---|
| `yace-codec[keyring]` | the system keyring as a key backend (`keyring`) |
| `yace-codec[aead]` | nothing new since 0.3.0 (`cryptography` is always installed); kept so existing install commands work |

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
(`family=` in Python, `--family NAME` on the command line). A file could otherwise
add tables for a family you use, such as `default`, and its sender could then
decode your later tokens.

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

## Encryption

`encrypt()` turns any text or bytes into letters and digits, and `decrypt()` turns
them back. Choose your own secret token, and pass the same one to decrypt:

```python
secret = yace.encrypt("Meet at the north gate at 06:00.", token="blue-falcon-42")
print(secret)
print(yace.decrypt(secret, token="blue-falcon-42"))
```

```text
KIenASpyg8G9CtvxNrVgaVBod9zglP5L4HznFPOujEil4IhxYGl0lZlIZfGnGopzVxJugzVWrgHr06AbowWVp6VlDr0Q8UudiuiCmy9En1rrwW1HsPImQ2e
Meet at the north gate at 06:00.
```

`decrypt()` returns `str` for text and `bytes` for bytes. A wrong secret, or any
change to the encrypted text, raises `DecryptionError`. `max_age` rejects old data:
`yace.decrypt(secret, token="blue-falcon-42", max_age=3600)` raises
`TokenExpiredError` for data encrypted more than an hour ago.

### Choosing the secret

| Secret | Use it for | Example |
|---|---|---|
| Your own token | Sharing with people who know a passphrase | `encrypt(data, token="blue-falcon-42")` |
| A raw 32-byte key | Applications that manage their own keys | `encrypt(data, key=key)`, `decrypt(out, keys=[key])` |
| A stored key | Everyday use on one machine or team | `encrypt(data)` or `encrypt(data, "team")` |

**Your own token** can be any non-empty text or bytes. It is stretched with scrypt,
which makes guessing slow, but anyone who guesses it can decrypt: choose a long one.
Nothing is generated or stored. `password=` is another name for `token=`.

**A raw key** comes from `yace.generate_key()` (32 random bytes). It is used as is,
without scrypt or a key store. `decrypt(..., keys=[...])` tries every key in the
list. Keys of any other size raise `InvalidKeyError`.

```python
key = yace.generate_key()
secret = yace.encrypt(b"\x89PNG\r\n\x1a\n...", key=key)
assert yace.decrypt(secret, keys=[key]) == b"\x89PNG\r\n\x1a\n..."
```

**A stored key** is generated on first use and kept by a
[key backend](#key-backends-rotation-and-sharing): by default the
[key store](#the-key-store) file, under the name `default`. `decrypt()` tries every
stored key, so the output never names its key.

```python
secret = yace.encrypt("Meet at the north gate at 06:00.")
print(yace.decrypt(secret))
```

```text
Meet at the north gate at 06:00.
```

### Algorithms

| Algorithm | Implementation | Speed (bytes output) |
|---|---|---|
| `aes-256-gcm` (the default) | AES-256-GCM from the audited [`cryptography`](https://cryptography.io/) package | hundreds of MB/s to GB/s |
| `chacha20-poly1305` | ChaCha20-Poly1305 from `cryptography`; fast without AES hardware | hundreds of MB/s to GB/s |
| `yace-hmac-sha256` | HMAC-SHA256 keystream and tag, Python's standard library only | about 20 MB/s |

Choose one with `algorithm=`. The output records which algorithm made it (hidden,
see below), so `decrypt()` needs no hint. List them with `yace.algorithms()` or
`yace-codec algorithms`:

```python
for info in yace.algorithms():
    print(info.name, "(default)" if info.default else "")
```

```text
aes-256-gcm (default)
chacha20-poly1305
yace-hmac-sha256
```

The default is `aes-256-gcm`, and it only changes in a new minor version with a
CHANGELOG entry. `cryptography` is installed with yace-codec. If you install with
`pip install --no-deps yace-codec`, only `yace-hmac-sha256` works: pass it
explicitly, because the default raises `EncodingError` without `cryptography`.

### Associated data

`aad=` ties the output to a context, such as a database row, a user, or a file name.
The associated data is authenticated but not stored, so decryption needs the same
value. That stops a valid ciphertext from being moved to another record:

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
`output="bytes"` gives the raw binary form, about 27% smaller and much faster to
produce. `decrypt()` accepts both, and text given as bytes (with or without a byte
order mark).

```python
raw = yace.encrypt("Meet at the north gate at 06:00.", key=key, output="bytes")
print(type(raw).__name__, len(raw))
```

```text
bytes 86
```

### Large files: streaming

`encrypt_stream()` and `decrypt_stream()` work on binary files or paths in constant
memory, whatever the size:

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

Data is encrypted in chunks (64 KiB by default). Each chunk's nonce holds its index
and a final-chunk flag, so a stream that was truncated, reordered, or spliced with
chunks from elsewhere fails to decrypt. `decrypt_stream()` verifies every chunk
before writing it, but it can only notice truncation at the end: if it raises,
discard what it wrote. Given a path as the destination, both functions write a
temporary file and rename it only when everything succeeded. `decrypt()` also reads
stream output (in memory), and `decrypt_stream()` reads every format.

### Key backends, rotation, and sharing

Stored keys live in a *key backend*. Pass one as `key_backend=` (to `Codec` or to the
functions), or `--key-backend` on the command line:

| Backend | Where the keys are | Notes |
|---|---|---|
| `KeyStore` (`json`, the default) | the key store JSON file | **plain text** (base64): anyone who can read the file can decrypt. New files are readable by you only. |
| `DpapiKeyStore` (`dpapi`) | `keys-dpapi.json` next to the key store | Windows only. Keys are encrypted with DPAPI for your Windows account, so a copied file is useless elsewhere. |
| `KeyringKeyStore` (`keyring`) | the system keyring (Windows Credential Manager, macOS Keychain, Secret Service) | Needs `pip install "yace-codec[keyring]"`. |

```python
backend = yace.open_key_backend("json", path="team-keys.json")
codec = yace.Codec(key_backend=backend)
old = codec.encrypt("before rotation", "team")
backend.rotate_key("team")  # new key for new data; the old one is kept for decryption
new = codec.encrypt("after rotation", "team")
print(codec.decrypt(old), "/", codec.decrypt(new))
```

```text
before rotation / after rotation
```

`rotate_key()` gives a key a new value and keeps the previous ones as *retired* keys:
they still decrypt, but nothing new is encrypted with them. `delete_key()` removes a
key with its retired keys. To share a key, `export_key("team")` (CLI:
`yace-codec keys export team`) gives portable JSON, including retired keys, and
`import_keys(data, name="team")` (CLI: `yace-codec keys import FILE --name team`)
adds it to another backend. Anyone with a key can decrypt and encrypt with it.

### What the encrypted output reveals

Only roughly how long the data is: the size is padded to a Padmé length, which leaks
at most a few bits. The output has no prefix or readable header: the format version
and algorithm are hidden with a key-derived mask, so the output does not show that
YACE made it. The key name, the exact length, the creation time, and whether the
data was text or bytes are all encrypted. The same data gives different output every
time.

### How encryption works

1. A random 16-byte salt is drawn every time.
2. The secret is a 32-byte key, or your token stretched with scrypt
   (N = 2<sup>17</sup>, r = 8, p = 1) and the salt.
3. HKDF-SHA256 (RFC 5869) derives, from the secret and the salt, the algorithm's key
   (and nonce, or keys) and a mask for the format version and algorithm id. Every
   output gets its own keys, so nonces never repeat under a key.
4. A frame holds the data type, the creation time, the length, the data, and zero
   padding up to a Padmé length.
5. The algorithm encrypts the frame. Its tag covers the salt, the (unmasked) version
   and algorithm id, the length-prefixed associated data, and the ciphertext.
6. Output is `salt || masked header || ciphertext || tag`, as bytes or as letters and
   digits (YACE62: every 8 bytes become 11 characters).

The byte-level format, for versions 3 (messages) and 4 (streams), is in
[SECURITY.md](https://github.com/thisismudith/YACE/blob/main/SECURITY.md), and
`tests/vectors/` has test vectors for every algorithm. Output from versions 0.2.0
(it starts with `yace2_`) and 0.2.1 still decrypts.

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

Encrypt and decrypt (any file works, byte for byte, in constant memory):

```console
$ yace-codec encrypt --token --text "Meet at the north gate at 06:00."
Secret token:
Repeat secret token:
KIenASpyg8G9CtvxNrVgaVBod9zglP5L4HznFPOujEil4IhxYGl0lZlIZfGnGopzVxJugzVWrgHr06AbowWVp6VlDr0Q8UudiuiCmy9En1rrwW1HsPImQ2e

$ yace-codec encrypt --token notes.txt -o notes.yace
Secret token:
Repeat secret token:
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
aes-256-gcm        AES-256 in GCM mode (needs the cryptography package) [default]
chacha20-poly1305  ChaCha20-Poly1305 (fast without AES hardware; needs the cryptography package)
yace-hmac-sha256   HMAC-SHA256 keystream and tag (standard library only; slower, not audited)

$ yace-codec keys list
default
team
$ yace-codec keys rotate team
rotated key 'team': new data uses the new key; data encrypted before still decrypts (...)
```

How to give your secret token, safest first:

- `--token` (or `-p`) asks for it without echoing it (twice when encrypting).
- `--token-file PATH` reads it from a file you protect (one trailing newline is
  ignored).
- `--token-stdin` reads it from the first line of standard input, for scripts. Give
  the data as a file or with `--text`.

The `YACE_CODEC_TOKEN` and `YACE_CODEC_PASSWORD` environment variables still work
with `--token`, but they are deprecated: other programs running as you can read
environment variables. Using them prints a warning. Without a token option, a stored
key is used (`--key NAME`, default `default`), from the backend chosen with
`--key-backend json|dpapi|keyring`.

`-o PATH` is written to a temporary file that replaces `PATH` only when everything
succeeded, so a failed decryption never leaves a partial file. Standard output
cannot be taken back: if decryption fails part way, discard what was printed.
`keys import` needs `--name NAME` (or `--all-keys`), and `keys delete` needs `--yes`.

Inspect and share tables:

```console
$ yace-codec tables list
NAME       LENGTH  LAYERS
default    2       1,2,3
files      2       1
groceries  3       1,2

$ yace-codec tables export groceries -o groceries.json
$ yace-codec tables import groceries.json --family groceries --keystore colleague.json
added: groceries-3:1
added: groceries-3:2
2 added, 0 unchanged, 0 replaced (colleague.json)

$ yace-codec tables path
C:\Users\you\AppData\Roaming\yace-codec\keystore.json
```

`tables import` needs `--family NAME`, which imports only that family's tables, or
`--all-families` for a file you trust completely. A file could otherwise add tables
to a family you use, such as `default`, and its sender could then decode your later
tokens:

```console
$ yace-codec tables import groceries.json
yace-codec: error: groceries.json holds tables for: groceries. Name the family you expect with --family NAME, or import everything with --all-families
```

| Command | Options |
|---|---|
| `encode [INPUT]` | `-t/--text TEXT`, `-o/--output PATH`, `-n/--name NAME` (default `default`), `-l/--length N` (default 2), `-i/--iterations N` (default 3), `-b/--binary`, `-k/--keystore PATH` |
| `decode [INPUT]` | `-t/--text TOKEN`, `-o/--output PATH`, `-b/--binary`, `-k/--keystore PATH` |
| `tables path` | `-k/--keystore PATH` |
| `tables list` | `-k/--keystore PATH` |
| `tables export NAME` | `-o/--output PATH`, `-k/--keystore PATH` |
| `tables import FILE` | `--family NAME` or `--all-families` (one is required), `--overwrite`, `-k/--keystore PATH` (use `-` as `FILE` for standard input) |
| `encrypt [INPUT]` | `-t/--text TEXT`, `-o/--output PATH`, one of `--key NAME` (default `default`), `-p/--token`, `--token-file PATH`, `--token-stdin`; `-a/--algorithm NAME`, `--aad TEXT`, `-f/--format text\|bytes`, `--key-backend json\|dpapi\|keyring`, `-k/--keystore PATH` |
| `decrypt [INPUT]` | `-t/--text TEXT`, `-o/--output PATH`, one of `-p/--token`, `--token-file PATH`, `--token-stdin`; `--aad TEXT`, `--max-age SECONDS`, `--key-backend ...`, `-k/--keystore PATH` |
| `algorithms` | |
| `keys list` | `--key-backend ...`, `-k/--keystore PATH` |
| `keys rotate NAME` | `--key-backend ...`, `-k/--keystore PATH` |
| `keys delete NAME` | `--yes` (required), `--key-backend ...`, `-k/--keystore PATH` |
| `keys export NAME` | `-o/--output PATH`, `--key-backend ...`, `-k/--keystore PATH` |
| `keys import FILE` | `--name NAME` or `--all-keys` (one is required), `--overwrite`, `--key-backend ...`, `-k/--keystore PATH` |

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
| `encrypt(data, key=None, *, token=None, keystore=None, key_backend=None, aad=b"", algorithm=None, output="text") -> str \| bytes` | Encrypt text or bytes. The secret is your `token`, a raw 32-byte `key`, or a stored key named `key` (default `"default"`, generated on first use). Returns `str` for `output="text"`, `bytes` for `output="bytes"`. |
| `decrypt(encrypted, *, token=None, keys=None, aad=b"", max_age=None, keystore=None, key_backend=None) -> str \| bytes` | Decrypt any format (text or bytes, message or stream, 0.2.x included); returns `str` or `bytes`, as encrypted. `keys` limits decryption to those raw keys. |
| `encrypt_stream(src, dst, key=None, *, token=None, keystore=None, key_backend=None, aad=b"", algorithm=None, output="text", text=False, chunk_size=65536) -> int` | Encrypt a binary file object or path in constant memory; returns the bytes written. |
| `decrypt_stream(src, dst, *, token=None, keys=None, aad=b"", max_age=None, keystore=None, key_backend=None) -> StreamInfo` | Decrypt into a binary file object or path. |
| `generate_key() -> bytes` | A new random 32-byte key. |
| `algorithms() -> list[AlgorithmInfo]` | The encryption algorithms, the default first. |
| `open_key_backend(kind, *, path=None, service="yace-codec") -> KeyBackend` | Open the `"json"`, `"dpapi"`, or `"keyring"` backend. |
| `parse_header(token) -> Header` | Read an encoded token's header without decoding it. |
| `default_keystore_path() -> pathlib.Path` | Where the default key store lives (an absolute path). |

`keystore` accepts a `KeyStore`, a path to a key store file, or `None` for the
default key store. `password=` is accepted everywhere as another name for `token=`.

### `Codec(keystore=None, *, rng=None, key_backend=None)`

Encodes, decodes, encrypts, and decrypts with one key store. It has the same
`encode`, `decode`, `encode_bytes`, `decode_bytes`, `encrypt`, `decrypt`,
`encrypt_stream`, and `decrypt_stream` methods as the functions above (without the
`keystore` and `key_backend` arguments), and `keystore` and `keys` (the key backend)
attributes. `rng` replaces the system random source with a `random.Random`, for
reproducible tests only.

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

`KeyStore` is also the default key backend, with the methods below.

`import_tables` validates every table before it writes anything, and it writes
nothing when every table is already present. It raises `KeyStoreError` if a table
already exists with different codes, unless `overwrite=True`.

### Key backends

`KeyBackend` is the interface; `KeyStore`, `DpapiKeyStore(path=None)` (Windows), and
`KeyringKeyStore(service="yace-codec")` implement it:

| Member | Description |
|---|---|
| `ensure_key(name, *, rng=None) -> bytes` | The current key `name`, generated and saved if missing. |
| `get_key(name) -> bytes`, `find_key(name) -> bytes \| None` | The current key `name`. |
| `key_names() -> list[str]` | Names of the stored keys. |
| `rotate_key(name, *, rng=None) -> bytes` | A new key for `name`; the old one is kept (retired) for decryption. |
| `delete_key(name)` | Remove a key and its retired keys. |
| `decryption_keys() -> list[bytes]` | Every current and retired key. |
| `export_key(name) -> dict` | A key and its retired keys as portable JSON data. |
| `import_keys(keys, *, overwrite=False, name=None) -> ImportResult` | Add keys; with `name`, only that key. |

### Data types

- `Header(family, length, iterations)`: a named tuple. `str(header)` gives the header
  line, and `header.table_names` lists the tables needed for decoding.
- `Table`: an immutable, validated table with `name`, `length`, `codes` (a read-only
  mapping from character to code), `space_codes`, `bin_codes`, and `characters` (what
  it can encode), plus `to_dict()`, `Table.from_dict(name, data)`, and
  `Table.generate(name, rng)`.
- `StreamInfo(size, text)`: what `decrypt_stream` wrote, and whether it was text.
- `AlgorithmInfo(name, id, tag_size, available, default, description)`.

### Exceptions

```text
YaceError
├── InvalidNameError           invalid family name (also a ValueError)
├── InvalidKeyError            a raw key is not 32 bytes (also a ValueError)
├── EncodingError              invalid settings, unknown algorithm (also a ValueError)
│   └── UnsupportedCharacterError   .characters, .table_name
├── DecodingError              malformed or corrupted token, or wrong tables (also a ValueError)
│   └── DecryptionError        cannot be opened: wrong token, key, or aad, or changed
│       └── TokenExpiredError  it was encrypted longer ago than max_age
├── TableNotFoundError         a needed table or key is missing; .table_name (also a LookupError)
└── KeyStoreError              unreadable, invalid, or unwritable key store or backend
```

Messages and `repr()` never contain keys or secret tokens.

### Constants

`DEFAULT_ALGORITHM` (`"aes-256-gcm"`), `DEFAULT_FAMILY` (`"default"`), `DEFAULT_KEY`
(`"default"`), `DEFAULT_LENGTH` (2), `DEFAULT_ITERATIONS` (3), `MIN_LENGTH` (2),
`MAX_LENGTH` (62), `MAX_ITERATIONS` (32), `MAX_ENCODED_CHARS` (2<sup>25</sup>),
`SUPPORTED_CHARACTERS`, `ENV_VAR` (`"YACE_CODEC_KEYSTORE"`), and `__version__`.

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

Secret keys for `encrypt` live in the same file, as entries named `key:<name>` that
hold a base64 `secret` of 32 random bytes and, after `rotate_key()`, a `retired`
list. **These keys are stored in plain text:** anyone who can read the file can
decrypt. Keep the file private, or keep keys in the `dpapi` or `keyring`
[key backend](#key-backends-rotation-and-sharing) instead.

How the key store behaves:

- **Existing tables are never changed.** New tables are only added, except through
  `import_tables(..., overwrite=True)`.
- **Writes are atomic.** Data goes to a temporary file that then replaces the key
  store, so a crash cannot leave a half-written file. A symbolic link is followed,
  so the file it points to is updated and the link stays. A key store with more than
  one hard link is refused instead, because replacing it would split the copies.
- **New files are private.** New key store files get mode `0600`, and a new
  `yace-codec` directory gets mode `0700`, on POSIX. On Windows, new key store files
  get an access control list that allows only you (and the SYSTEM account), with
  nothing inherited from the folder.
- **Existing permissions are kept.** An existing key store keeps its access control
  list on Windows, and its mode on POSIX, plus its owner and group where the system
  allows it, so a deliberately shared key store stays shared.
- **Concurrent writers are safe.** Writes are serialised with a `keystore.json.lock`
  file next to the key store, so parallel processes never lose each other's tables.
  Reading, and encoding with tables that already exist, need no write access.
- **Damaged files are left alone.** If the file is not valid JSON, you get a
  `KeyStoreError` and the file is not overwritten. Entries the package does not
  understand are kept.

**Back up your key store.** If you lose it, every token encoded with its tables or
encrypted with its keys becomes unreadable. Anyone who has it can read those tokens.

## Limits and edge cases

- **Characters.** `encode()` supports the 100 characters of `string.printable`:
  ASCII letters, digits, punctuation, space, `\t`, `\n`, `\r`, `\x0b`, and `\x0c`.
  It raises `UnsupportedCharacterError` before creating any table if the text
  contains anything else. Use `encode_bytes()` for other text. Tables from the
  original scripts do not cover `\t`, `\r`, `\x0b`, or `\x0c`.
- **Settings.** `length` must be 2–62 and `iterations` 1–32. Encoding is refused if
  `len(text) × length ** iterations` exceeds 2<sup>25</sup> (about 33 million
  characters before bins; with bins, tokens reach about 42 million characters).
- **Size.** Tokens grow by `length ** iterations`, plus 25% for bins (see
  [Token size](#token-size)). Keep `iterations` small for long texts.
- **Memory and speed.** Encoding and decoding hold the whole input and token in
  memory and are written in pure Python. They need roughly 25–40 bytes of memory per
  token character, so tokens near the size limit need 1–2 GB. YACE is meant for
  strings and small to medium files, not streams.
- **Empty input.** Encoding `""` gives a header-only token, which decodes to `""`.
- **Encryption size and memory.** `encrypt()` and `decrypt()` hold the data and
  the output in memory; `encrypt_stream()` and `decrypt_stream()` (and the command
  line) use constant memory for any size. Text output is about 1.4 times the size of
  the data plus about 70 characters; bytes output adds 51 bytes plus Padmé padding
  (at most about 12%, less for large data).
- **Encryption speed.** With `output="bytes"`, `aes-256-gcm` and `chacha20-poly1305`
  run at hundreds of MB/s or more; `yace-hmac-sha256` at about 20 MB/s. Text output
  is limited to roughly 10–20 MB/s by its pure-Python letters-and-digits encoding.
  Run `python benchmarks/bench.py` to measure your machine.
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
  original scripts allowed, such as `my cat` or `café`, except a name that starts
  with a space.

## Security

### Encoding (`encode`)

- YACE encoding is a randomised substitution code with a keyless, public chunk shuffle.
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
- Use `encrypt()` whenever confidentiality matters.

### Encryption (`encrypt`)

- **Not audited.** `aes-256-gcm` and `chacha20-poly1305` come from the audited
  [`cryptography`](https://cryptography.io/) package, and the key derivation uses
  standard constructions (HKDF-SHA256, scrypt). How yace-codec combines them (the
  formats, the header mask, the stream construction) has not been audited by anyone.
  For high-stakes data, use the default `aes-256-gcm` (or `chacha20-poly1305`), and
  consider an audited higher-level tool.
- `yace-hmac-sha256` uses only the standard library. It is a sound construction
  (HMAC-SHA256 as a pseudorandom function, encrypt-then-MAC), but it is slower and
  pure Python gives no protection against attackers who can measure timing or memory
  on your machine.
- Encryption with your own token is only as strong as the token. scrypt makes each
  guess slow, but a short or common token can still be found. Raw and stored keys are
  32 random bytes.
- The JSON key store holds keys in plain text: anyone who copies it can decrypt
  everything encrypted with its keys. Use `DpapiKeyStore` or `KeyringKeyStore` to keep
  keys out of plain files.
- There is no forward secrecy: a leaked token or key opens everything encrypted with
  it, including earlier data. Rotation limits new exposure, not old.
- The output hides the key name, algorithm, creation time, and exact length, but not
  roughly how long the data is.
- `decrypt_stream()` writes verified chunks before it reaches the end, so a truncated
  stream is detected only at the end; discard the output when it raises.

See [SECURITY.md](https://github.com/thisismudith/YACE/blob/main/SECURITY.md) for the
threat model, the format specification, supported versions, and how to report a
vulnerability privately.

## Migrating from the original scripts

Before version 0.1.0, YACE was a set of scripts in `encoder/` that stored tables in
`encoder/encodings.json`. The package keeps the same algorithm, table format, and
token format.

- **Keep your old tables.** This release no longer includes `encoder/encodings.json`.
  If you still have tokens made with the original scripts, keep your copy of that
  file: it is the key store those tokens need.
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
python -m pip install -e ".[test]"
python -m pytest
python benchmarks/bench.py         # throughput per algorithm (not a test)
```

The tests include the published test vectors in `tests/vectors/` (with an
independent implementation that decrypts them), property-based tests, and tokens
made by earlier releases. To build the wheel and source distribution into `dist/`,
run `python -m pip install build` and then `python -m build`.

## Contributing

Issues and pull requests are welcome at
<https://github.com/thisismudith/YACE>.

1. Open an issue first for larger changes.
2. Keep the token and key store formats backward compatible: tokens made by earlier
   versions, and by the original scripts, must keep decoding.
3. Run `python -m pytest`; the tests also run the scripts in `examples/` and the
   Python examples in this README.

## License

MIT. See [LICENSE](https://github.com/thisismudith/YACE/blob/main/LICENSE).

## Links

- Source: <https://github.com/thisismudith/YACE>
- Issues: <https://github.com/thisismudith/YACE/issues>
- PyPI: <https://pypi.org/project/yace-codec/>
- Changelog: <https://github.com/thisismudith/YACE/blob/main/CHANGELOG.md>

## Author

Mudith Daga ([@thisismudith](https://github.com/thisismudith))

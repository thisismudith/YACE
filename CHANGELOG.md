# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-10-16

Output of 0.3.0 cannot be decrypted by 0.2.x. Everything 0.2.x made still decrypts.

### Added

- **Versioned format.** Messages (format 3) and streams (format 4) carry a version
  byte, an algorithm id, and four check bytes, authenticated by the tag and hidden
  under a key-derived mask: output still has no recognisable prefix, and a wrong key
  or secret token is rejected from the header alone. SECURITY.md specifies both
  formats byte by byte.
- **Algorithms:** `aes-256-gcm` (the default) and `chacha20-poly1305` from the
  audited `cryptography` package, and the standard-library `yace-hmac-sha256`. Every
  algorithm has a 16-byte tag, so output length does not reveal the algorithm.
  Choose with `algorithm=` or `--algorithm`; list them with `algorithms()` or
  `yace-codec algorithms`.
- **Associated data:** `aad=` (and `--aad`) binds output to a context; a wrong `aad`
  raises `DecryptionError`.
- **Raw keys:** `encrypt(data, key=<32 bytes>)`, `decrypt(out, keys=[...])`, and
  `generate_key()`, with no key store and no scrypt. Other key sizes raise the new
  `InvalidKeyError`.
- **Output format:** `output="bytes"` (and `--format bytes`) gives raw output with no
  expansion; `"text"` stays the default. `decrypt()` accepts both.
- **Streaming:** `encrypt_stream()` and `decrypt_stream()` encrypt files of any size in
  constant memory, in chunks whose nonces hold the chunk index and a final flag, so
  truncation, reordering, and duplication are detected. `decrypt()` also reads
  streams, and `decrypt_stream()` reads every format.
- **Key backends:** the `KeyBackend` interface, `Codec(key_backend=...)` (an object
  or a name), `open_key_backend()`, and `--key-backend`; `DpapiKeyStore` (Windows;
  keys encrypted with DPAPI) and `KeyringKeyStore` (the system keyring;
  `pip install "yace-codec[keyring]"`).
- **Key rotation and deletion:** `rotate_key()` / `yace-codec keys rotate` keep the
  previous key for decryption; `delete_key()` / `yace-codec keys delete --yes`.
- **Command line:** `--token-file PATH` and `--token-stdin`; `encrypt` and `decrypt`
  stream files in constant memory (`encrypt` always writes the stream format).
- New names: `DEFAULT_ALGORITHM`, `DEFAULT_CHUNK_SIZE`, `KEY_SIZE`,
  `MAX_MESSAGE_SIZE`, `AlgorithmInfo`, `StreamInfo`, `KeyBackend`,
  `KeyNotFoundError`, and the `Codec.key_backend` attribute.
- `SECURITY.md` with the threat model, the format specification, supported versions,
  and how to report a vulnerability privately.
- The test suite ships in the sdist and runs in CI on Linux, Windows, and macOS for
  Python 3.10–3.15, against the built wheel and the oldest supported dependencies:
  test vectors for every algorithm and format (`tests/vectors/`), an independent
  implementation that decrypts them, property tests, and tamper, stream, concurrency,
  and legacy tests. `benchmarks/bench.py` reports throughput.

### Changed

- **The default algorithm is now `aes-256-gcm`**, and `cryptography` is a dependency.
  (0.2.x used an HMAC-SHA256 construction; it remains available as
  `yace-hmac-sha256`.)
- Python 3.10 or newer is required (3.9 reached end of life in October 2025).
- Every bad argument raises a `YaceError` subclass (or `TypeError`), and every
  argument is checked before a stored key is created.
- Command line:
  - every `-o` writes a temporary file that replaces the target only on success;
  - decrypted and decoded files, and exported keys and tables, are created readable
    only by you;
  - usage mistakes (bad `--max-age`, `-l`, `-i`, or `--key`, and conflicting inputs)
    exit with status 2;
  - abbreviated option names are no longer accepted;
  - `--token-file` reads UTF-16 files with a byte order mark (PowerShell);
  - `--token` fails at once without a terminal;
  - `keys rotate` refuses a key that does not exist;
  - with `--key-backend dpapi`, `-k` names the key store and the keys go in
    `keys-dpapi.json` next to it.
- New key store files are readable only by their owner on Windows too (an
  access control list for you and SYSTEM, with nothing inherited).
- Stored keys can have a `retired` list after rotation. Version 0.2 ignores it, so
  after a rotation 0.2 can no longer decrypt data made with the old key.
- Text output encodes about twice as fast.

### Fixed

- Readers no longer see an empty key store while another process replaces it on
  Windows.
- A damaged key entry no longer blocks decryption with the other keys.
- `decode()` rejects tokens longer than the encoder can make, instead of using
  gigabytes of memory.

### Deprecated

- The `YACE_CODEC_TOKEN` and `YACE_CODEC_PASSWORD` environment variables still work
  with `--token`, but print a warning. Use the prompt, `--token-file`, or
  `--token-stdin`.

### Security

- Releases publish only after the full test suite passes. They are built with
  hash-pinned tools and actions pinned to commits, reproducibly, and publish build
  provenance attestations.

## [0.2.1] - 2026-10-15

### Added

- `encrypt(data, token=...)` and `decrypt(encrypted, token=...)`: choose your own
  secret token (any non-empty text or bytes). With a token, nothing is generated or
  stored. Without one, a key is generated and kept in the key store, as before.
- `yace-codec encrypt --token` and `decrypt --token` ask for the secret token, or
  read `YACE_CODEC_TOKEN`.

### Changed

- Encrypted output is only letters and digits, with no `yace2_` prefix, so it does
  not reveal that YACE made it. Output from 0.2.0 still decrypts.
- `decrypt()`'s first parameter is named `encrypted` (it was `token`).
- `password=`, `--password`, and `YACE_CODEC_PASSWORD` remain as other names for
  `token=`, `--token`, and `YACE_CODEC_TOKEN`.

## [0.2.0] - 2026-10-14

### Added

- Encryption: `encrypt()` and `decrypt()` (also `Codec.encrypt()` /
  `Codec.decrypt()`) turn text or bytes into `yace2_` tokens and back. Tokens are
  authenticated (HMAC-SHA256, encrypt-then-MAC), use per-token keys derived with
  HKDF-SHA256 from a random salt, and are padded to a Padmé length. They reveal neither
  the key name, the creation time, the exact length, nor the data type. Everything
  comes from Python's standard library.
- Secret keys in the key store (`key:<name>` entries): `ensure_key()`, `get_key()`,
  `find_key()`, `key_names()`, `export_key()`, and `import_keys(..., name=...)`.
  `decrypt()` tries every stored key.
- Password mode: `encrypt(data, password=...)` stretches the password with scrypt and
  does not touch the key store.
- `decrypt(..., max_age=SECONDS)` rejects old tokens with `TokenExpiredError`.
- `DecryptionError` and `TokenExpiredError` (both subclasses of `DecodingError`), and
  the `DEFAULT_KEY` constant.
- `yace-codec encrypt`, `yace-codec decrypt` (with `--password`, `--key`, and
  `--max-age`), and `yace-codec keys list|export|import`. `keys import` needs
  `--name NAME` or `--all-keys`. `YACE_CODEC_PASSWORD` can supply the password.

### Changed

- `decode()` on a `yace2_` token points to `decrypt()`, and `decrypt()` on an
  encoded token points to `decode()`.
- `import_tables()` refuses secret key entries; import them with `import_keys()`.

## [0.1.0] - 2026-10-14

First release on PyPI, as `yace-codec` (import name `yace_codec`).

### Added

- `yace_codec` package with `Codec`, `encode()`, `decode()`, `parse_header()`, and
  `encode_bytes()` / `decode_bytes()` for binary data and any Unicode text.
- `KeyStore`: a JSON key store in the per-user data directory (override with
  `YACE_CODEC_KEYSTORE`). It writes atomically, uses a lock file so concurrent
  writers never lose tables, keeps the file's permissions, and can export and import
  table families. `import_tables(..., family=...)` imports a single family.
- `yace-codec` command (also `python -m yace_codec`) with `encode`, `decode`, and
  `tables path|list|export|import`. `tables import` needs `--family NAME` (or
  `--all-families`), so a shared file cannot add tables for a family you did not
  expect, and it lists the tables it adds.
- Decoding checks that a token's number of noise chunks matches its length, which
  catches many truncated tokens.
- Tokens and JSON files saved as UTF-16 or with a byte order mark (as Windows
  PowerShell writes them) are accepted.
- An exception hierarchy under `YaceError`, type hints (`py.typed`), and runnable
  examples.

### Changed

- The scripts in `encoder/` were replaced by the package. The algorithm, the table
  format (`encodings.json`), and the token format are unchanged. Old tokens decode
  with the package. New tokens decode with the original scripts when the package
  generated the tables.
- New tables cover all of `string.printable` (tab, carriage return, vertical tab, and
  form feed were added) and never share a code between characters, spaces, and bins.
- Tables and per-token randomness come from `secrets.SystemRandom`.
- Errors raise exceptions instead of printing a message and calling `exit()`.
- Without a name, the family `default` is used instead of random letters.
- Encoding needs a family name of 1–64 ASCII letters or underscores, also for
  existing families. Families with other names can still be decoded.
- Encoding is refused when `len(text) × length ** iterations` exceeds
  2<sup>25</sup> (`MAX_ENCODED_CHARS`); with bins, tokens reach about
  1.25 × 2<sup>25</sup> characters.

### Fixed

- Characters missing from a table were copied into the token unencoded, which
  corrupted it. They now raise `UnsupportedCharacterError`.
- Shared codes in tables from the original generator could make decoding return
  garbled text. The encoder no longer emits a shared space or bin code, and the
  decoder recovers many affected legacy tokens.
- Empty input crashed, a code length of 1 hung, and family names with repeated
  letters (such as `hello`) were rejected.
- Tables were written into the source directory with a truncate-then-write, so a
  crash could erase them. They are now written atomically to a key store file.
- Importing the scripts configured the root logger and wrapped standard output, and
  every encode logged three debug entries to `errors.log` for each encoding layer.

### Removed

- `encoder/encodings.json`, the tables of the original scripts. Keep a copy if you
  still have tokens made with them (see the README's migration section).
- `randomizer_data.json`, `errors.log`, and `update.log`.
- The deprecated `encoder (beta).py` and the unfinished `analyzer.py` file encoder
  (use `yace-codec encode FILE` or `--binary` instead).
- Scratch files unrelated to the encoder, and compiled `__pycache__` files.

[0.3.0]: https://github.com/thisismudith/YACE/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/thisismudith/YACE/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/thisismudith/YACE/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/thisismudith/YACE/releases/tag/v0.1.0

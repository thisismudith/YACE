# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

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

# Security

## Reporting a vulnerability

Please report security problems privately, through GitHub's
[private vulnerability reporting](https://github.com/thisismudith/YACE/security/advisories/new)
for this repository, rather than in a public issue. Include what you found, how to
reproduce it, and the version you used. Once a fix is released, the advisory is
published with credit to you, unless you prefer otherwise.

## Supported versions

| Version | Security fixes |
|---|---|
| 0.3.x | yes |
| 0.2.x and older | no: upgrade to 0.3.x, which still decrypts their output |

## What yace-codec is, and is not

yace-codec has two unrelated modes:

- **`encode()` / `decode()` is obfuscation, not encryption.** It is a randomised
  substitution code. Frequency analysis, or a few tokens with known text, breaks it.
  It has no integrity protection. Never use it for secrets.
- **`encrypt()` / `decrypt()` is authenticated encryption.** The rest of this file
  is about this mode.

**Nobody has audited yace-codec.** The default algorithms, AES-256-GCM and
ChaCha20-Poly1305, come from the audited [`cryptography`](https://cryptography.io/)
package, and keys are derived with standard constructions (HKDF-SHA256, scrypt). The
token formats below, the header mask, and the streaming construction are this
project's own design, built from those parts. For high-stakes data, use the default
algorithm, read this file, and consider an audited higher-level tool.

## Threat model

### What is protected

Against an attacker who sees, stores, or changes encrypted output, but has neither
the secret token nor the key:

- **Confidentiality** of the data, its exact length, its type (text or bytes), and
  its creation time.
- **Integrity and authenticity**: any change to the output, including its header,
  is detected, and decryption fails before any data is released (for streams: before
  each chunk is released; see below).
- **Context binding**: with associated data (`aad`), output moved to another
  context (another record, user, or file) fails to decrypt.
- **Stream ordering**: truncated, reordered, duplicated, or spliced stream chunks
  are detected.
- **Unlinkability of keys**: output does not name its key or algorithm, and two
  outputs do not reveal whether they share a key.
- **Freshness, if you ask for it**: `max_age` rejects output older than you allow
  (the creation time is authenticated; it is not protection against replay within
  that window).

### What is not protected

- **Approximate length.** Sizes are padded to a Padmé length, which leaks at most a
  few bits, but the rough size is visible.
- **Weak secret tokens.** A token is stretched with scrypt (N = 2<sup>17</sup>,
  r = 8, p = 1), which slows guessing, but a short or common token can be guessed.
  Use long, random tokens, or 32-byte keys.
- **Stolen keys.** Anyone with a key, or a copy of a JSON key store, can decrypt
  everything encrypted with that key. The JSON key store keeps keys in plain text
  (new files are readable only by their owner; files created before 0.3.0 keep their
  permissions, so check them with `icacls` on Windows or `ls -l` on POSIX). `DpapiKeyStore` (Windows) and
  `KeyringKeyStore` keep keys out of plain files, but anything running as your user
  can still use them.
- **Forward secrecy.** There is none: a leaked key or token opens earlier output
  too. Rotating a key protects only new output.
- **Partial stream output.** `decrypt_stream()` writes each chunk once it is
  verified. A truncated or changed stream is detected when the damaged part is
  reached, so earlier chunks may already be written: discard the output if it
  raises. The command line and path destinations write to a temporary file that is
  only kept on success.
- **Local attackers.** Code running as your user, memory dumps, or swap can expose
  keys and data. Python cannot reliably erase secrets from memory. The
  `yace-hmac-sha256` algorithm is pure Python and gives no protection against
  attackers who can measure timing or cache behaviour on your machine. (Tag checks
  are constant-time in every algorithm: `hmac.compare_digest` for HMAC, and
  `cryptography`'s own checks for AEAD.)
- **Secrets in the environment.** `YACE_CODEC_TOKEN` and `YACE_CODEC_PASSWORD` are
  deprecated, because other processes running as you can read them. Use the prompt,
  `--token-file`, or `--token-stdin`.
- **Traffic analysis and metadata** such as file names, timestamps, and who sends
  output to whom.

## Format specification

Notation: `||` is concatenation; `u8`, `u32`, `u64` are big-endian unsigned
integers; `HKDF-Expand` is RFC 5869 with SHA-256.

### Secrets and key derivation

```
secret = key                                    (a raw or stored 32-byte key)
       | scrypt(token, salt, N=2^17, r=8, p=1, dklen=32)   (token as UTF-8, or bytes)
PRK    = HMAC-SHA256(key=salt, message=secret)  (HKDF-Extract)
mask   = HKDF-Expand(PRK, "yace3 header mask", 3)
info(label) = "yace3" || u8(version) || u8(algorithm_id) || label
```

| Algorithm | id | Keys | Tag |
|---|---|---|---|
| `yace-hmac-sha256` | 1 | `Kenc = HKDF-Expand(PRK, info(" enc"), 32)`, `Kmac = HKDF-Expand(PRK, info(" mac"), 32)` | 32 bytes |
| `aes-256-gcm` | 2 | `K = HKDF-Expand(PRK, info(" key"), 32)`, `N = HKDF-Expand(PRK, info(" nonce"), 12)` | 16 bytes |
| `chacha20-poly1305` | 3 | as for `aes-256-gcm` | 16 bytes |

Every output has a fresh random 16-byte salt, so every output has its own keys and
nonce; a nonce is never used twice with the same key.

Sealing with associated data `AD` and a `suffix` (empty for messages):

- **AEAD (ids 2, 3):** `body = AEAD-Encrypt(K, nonce, plaintext, AD)` (ciphertext
  followed by the tag), where `nonce = N` for messages and
  `N[0:7] || suffix` for stream chunks.
- **HMAC (id 1):** `ciphertext = plaintext XOR (HMAC-SHA256(Kenc, suffix || u64(0)) || HMAC-SHA256(Kenc, suffix || u64(1)) || ...)`,
  `tag = HMAC-SHA256(Kmac, AD || suffix || ciphertext)`, `body = ciphertext || tag`.
  Decryption checks the tag (constant time) before it decrypts.

`aad_block = u64(len(aad)) || aad`, so associated data has an unambiguous length.

### Version 3: single message

```
plaintext = u8(kind) || u64(created) || u64(len(data)) || data || zeros
            kind: 0 = bytes, 1 = text (UTF-8); created: Unix time in seconds;
            zeros pad the plaintext to padme(17 + len(data)) bytes
AD        = salt || u8(3) || u8(algorithm_id) || aad_block
output    = salt (16) || u8(3 XOR mask[0]) || u8(algorithm_id XOR mask[1]) || body
```

### Version 4: stream

```
C         = 2^log2       (chunk size, 64 bytes to 1 MiB; default 64 KiB)
AD        = salt || u8(4) || u8(algorithm_id) || u8(log2) || aad_block
output    = salt (16) || u8(4 XOR mask[0]) || u8(algorithm_id XOR mask[1])
            || u8(log2 XOR mask[2]) || chunk_0 || chunk_1 || ... || chunk_n
chunk_i   = seal(suffix = u32(i) || u8(last), plaintext_i)    (last = 1 only for chunk_n)
plaintext_i = u32(count) || count data bytes || zeros
```

The data bytes of all chunks, in order, are `u8(kind) || u64(created) || data`.
Every chunk except the last has a plaintext of exactly `C` bytes; the last has 4 to
`C` bytes. Chunks after the data, and the zeros, pad the total of data bytes plus
zeros to `padme(9 + len(data))`. Decryption reads chunks of `C + tag` bytes; the
chunk followed by end of input must have `last = 1`, and every other chunk
`last = 0`.

### Text form and Padmé

- **YACE62:** each 8-byte block becomes 11 characters (`0-9A-Za-z`, base 62, most
  significant first); a final block of 1–8 bytes becomes 2, 3, 5, 6, 7, 9, 10, or 11
  characters. Decoders ignore whitespace and accept UTF-8, or UTF-16 and UTF-32 with
  a byte order mark.
- **Padmé:** for `L >= 2`, with `E = floor(log2(L))` and `S = floor(log2(E)) + 1`,
  round `L` up to a multiple of `2^(E - S)`.

### Decryption and older formats

For each candidate secret (the token, or each key), decryption derives the mask and
reads the version and algorithm id. Version 4 is decrypted as a stream, version 3 as
a message. Output from 0.2.1 (no header: `salt || ciphertext || HMAC tag`) and 0.2.0
(the same, as text after `yace2_`) is tried next; it has no associated data, so it
only decrypts with an empty `aad`.

Test vectors for every algorithm and both versions are in
[`tests/vectors/v3.json`](tests/vectors/v3.json), with intermediate values (PRK,
mask, keys, nonce). `tests/test_spec_independent.py` decrypts them with an
implementation written only from this specification.

## Release integrity

Releases are built and published by GitHub Actions with PyPI Trusted Publishing (no
long-lived API tokens). The workflow pins every action to a commit and every build
tool to a hash, and publishes build provenance attestations for the files on PyPI
and on the GitHub release.

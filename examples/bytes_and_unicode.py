"""Encode text outside string.printable, or any binary data, with encode_bytes().

YACE tables cover the 100 characters of string.printable. encode_bytes()
base64-encodes the data first, so it works for any bytes.

Run with:  python examples/bytes_and_unicode.py
"""

import os

import yace_codec as yace

codec = yace.Codec(yace.KeyStore.in_memory())
text = "Grüße, 世界 \U0001F600"  # "Grüße, 世界 😀"

try:
    codec.encode(text)
except yace.UnsupportedCharacterError as exc:
    print("encode() refuses:", ascii(exc.characters))

token = codec.encode_bytes(text.encode("utf-8"), "unicode", length=2, iterations=1)
print("Unicode round trip ok:", codec.decode_bytes(token).decode("utf-8") == text)

blob = os.urandom(32)
token = codec.encode_bytes(blob, "blobs", length=3, iterations=1)
print("Binary round trip ok:", codec.decode_bytes(token) == blob)

assert codec.decode_bytes(token) == blob

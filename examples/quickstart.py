"""Encode and decode a message with yace-codec.

Run with:  python examples/quickstart.py
"""

import yace_codec as yace

# An in-memory key store keeps this demo from writing files. Use
# yace.KeyStore("my-keystore.json") (or the default store) to keep the tables:
# a token can only be decoded with the tables that encoded it.
codec = yace.Codec(yace.KeyStore.in_memory())

message = "Meet me at 7pm.\nBring the blue folder!"
token = codec.encode(message, "demo", length=3, iterations=2)

print("Token:")
print(token)
print()
print("Header:", yace.parse_header(token))
print("Tables needed:", ", ".join(yace.parse_header(token).table_names))
print("Decoded:", codec.decode(token))

assert codec.decode(token) == message

"""Encrypt with a secret token, a raw key, associated data, and a stream."""

import io

import yace_codec as yace

# Your own secret token: nothing is stored.
secret = yace.encrypt("Meet at the north gate at 06:00.", token="blue-falcon-42")
print(secret)
print(yace.decrypt(secret, token="blue-falcon-42"))

# A raw 32-byte key, bound to a database row with associated data.
key = yace.generate_key()
row = yace.encrypt("salary: 85000", key=key, aad="row:1", output="bytes")
print(len(row), "bytes:", yace.decrypt(row, keys=[key], aad="row:1"))
try:
    yace.decrypt(row, keys=[key], aad="row:2")
except yace.DecryptionError:
    print("moved to row 2: rejected")

# A large file, in constant memory.
source, encrypted, restored = io.BytesIO(b"x" * 1_000_000), io.BytesIO(), io.BytesIO()
yace.encrypt_stream(source, encrypted, key=key, output="bytes")
encrypted.seek(0)
info = yace.decrypt_stream(encrypted, restored, keys=[key])
print("stream round trip:", restored.getvalue() == source.getvalue(), info)

# The algorithms you can choose from.
for algorithm in yace.algorithms():
    print(algorithm.name, "(default)" if algorithm.default else "")

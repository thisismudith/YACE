"""Streaming encryption (format version 4): chunked, constant memory, tamper-evident."""

import io
import os
import tracemalloc

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import yace_codec as yace
from yace_codec import sealed

KEY = bytes(range(32))
ALGORITHMS = ["aes-256-gcm", "chacha20-poly1305", "yace-hmac-sha256"]
TAGS = {"aes-256-gcm": 16, "chacha20-poly1305": 16, "yace-hmac-sha256": 16}
HEADER = 16 + 3 + 4


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    monkeypatch.setattr(sealed, "SCRYPT_N", 2**10)


class Trickle(io.RawIOBase):
    """A source that returns at most ``step`` bytes per read, like a pipe."""

    def __init__(self, data: bytes, step: int = 7) -> None:
        self._data, self._pos, self._step = data, 0, step

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        chunk = self._data[self._pos : self._pos + min(self._step, len(buffer))]
        buffer[: len(chunk)] = chunk
        self._pos += len(chunk)
        return len(chunk)


def encrypt(data: bytes, **kwargs) -> bytes:
    out = io.BytesIO()
    kwargs.setdefault("key", KEY)
    kwargs.setdefault("output", "bytes")
    yace.encrypt_stream(io.BytesIO(data), out, **kwargs)
    return out.getvalue()


def decrypt(blob: bytes, **kwargs) -> bytes:
    out = io.BytesIO()
    kwargs.setdefault("keys", [KEY])
    yace.decrypt_stream(io.BytesIO(blob), out, **kwargs)
    return out.getvalue()


def chunks(token: bytes, chunk_size: int, algorithm: str = "aes-256-gcm"):
    size = chunk_size + TAGS[algorithm]
    body = token[HEADER:]
    return token[:HEADER], [body[i : i + size] for i in range(0, len(body), size)]


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("size", [0, 1, 50, 51, 52, 64, 200, 1000, 5000])
def test_round_trip(algorithm, size):
    data = os.urandom(size)
    token = encrypt(data, algorithm=algorithm, chunk_size=64)
    assert decrypt(token) == data


@pytest.mark.parametrize("output", ["text", "bytes"])
def test_pipes_and_text_output(output):
    data = os.urandom(3000)
    out = io.BytesIO()
    yace.encrypt_stream(Trickle(data), out, key=KEY, output=output, chunk_size=256)
    token = out.getvalue()
    if output == "text":
        assert token.isalnum()
        wrapped = b"\r\n".join(token[i : i + 76] for i in range(0, len(token), 76))
        assert decrypt(wrapped) == data
        assert decrypt(b"\xef\xbb\xbf" + token) == data
        assert decrypt(token.decode().encode("utf-16")) == data
    out = io.BytesIO()
    result = yace.decrypt_stream(Trickle(token, step=5), out, keys=[KEY])
    assert out.getvalue() == data and result == yace.StreamInfo(size=3000, text=False)


def test_text_flag_round_trips_through_decrypt():
    token = encrypt("नमस्ते".encode(), text=True, output="text")
    assert yace.decrypt(token, keys=[KEY]) == "नमस्ते"
    out = io.BytesIO()
    assert yace.decrypt_stream(io.BytesIO(token), out, keys=[KEY]).text is True


def test_decrypt_reads_streams_and_decrypt_stream_reads_messages():
    stream_token = encrypt(b"stream", chunk_size=64)
    assert yace.decrypt(stream_token, keys=[KEY]) == b"stream"
    message = yace.encrypt(b"message", key=KEY)
    assert decrypt(message.encode()) == b"message"
    assert decrypt(yace.encrypt(b"raw message", key=KEY, output="bytes")) == b"raw message"


def test_decrypt_stream_reads_legacy_tokens():
    import json
    from pathlib import Path

    vectors = json.loads((Path(__file__).parent / "vectors" / "legacy.json").read_text("utf-8"))
    for vector in vectors["vectors"]:
        if "key" in vector and vector["text"]:
            out = io.BytesIO()
            yace.decrypt_stream(io.BytesIO(vector["token"].encode()), out, keys=[bytes.fromhex(vector["key"])])
            assert out.getvalue() == vector["plaintext"].encode()


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_truncation_is_detected(algorithm):
    token = encrypt(os.urandom(500), algorithm=algorithm, chunk_size=64)
    header, parts = chunks(token, 64, algorithm)
    assert len(parts) > 5
    for keep in range(len(parts)):  # drop the final chunk, and everything after any chunk
        with pytest.raises(yace.DecodingError):
            decrypt(header + b"".join(parts[:keep]))
    for cut in (1, 5, TAGS[algorithm], 70):  # cut inside the last chunk
        with pytest.raises(yace.DecodingError):
            decrypt(token[:-cut])


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_reorder_duplicate_and_extra_chunks_are_detected(algorithm):
    token = encrypt(os.urandom(500), algorithm=algorithm, chunk_size=64)
    header, parts = chunks(token, 64, algorithm)
    swapped = parts[:]
    swapped[1], swapped[2] = swapped[2], swapped[1]
    duplicated = parts[:2] + [parts[1]] + parts[2:]
    final_moved = parts[:-2] + [parts[-1], parts[-2]]
    for changed in (swapped, duplicated, final_moved, parts + [parts[-1]], parts + [b"x"]):
        with pytest.raises(yace.DecryptionError):
            decrypt(header + b"".join(changed))


def test_chunks_from_another_stream_are_rejected():
    first = encrypt(os.urandom(300), chunk_size=64)
    second = encrypt(os.urandom(300), chunk_size=64)
    header, parts = chunks(first, 64)
    _, other = chunks(second, 64)
    with pytest.raises(yace.DecryptionError):
        decrypt(header + b"".join(parts[:2] + other[2:]))


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_every_header_byte_is_authenticated(algorithm):
    token = encrypt(b"header", algorithm=algorithm, chunk_size=64)
    for index in range(HEADER):
        changed = bytearray(token)
        changed[index] ^= 0x01
        with pytest.raises(yace.DecodingError):
            decrypt(bytes(changed))


def test_smallest_stream_decrypts():
    token = encrypt(b"", chunk_size=64)
    assert len(token) == 53
    assert decrypt(token) == b"" and yace.decrypt(token, keys=[KEY]) == b""


def test_wrong_key_aad_and_secret():
    token = encrypt(b"aad", aad=b"file:1", chunk_size=64)
    assert decrypt(token, aad=b"file:1") == b"aad"
    for kwargs in ({"aad": b"file:2"}, {"aad": b""}, {"keys": [bytes(32)], "aad": b"file:1"}):
        with pytest.raises(yace.DecryptionError):
            decrypt(token, **kwargs)
    token = encrypt(b"pw", key=None, token="secret")
    assert decrypt(token, keys=None, token="secret") == b"pw"
    with pytest.raises(yace.DecryptionError):
        decrypt(token, keys=None, token="wrong")


def test_several_keys_and_the_key_store(codec):
    keys = [bytes([n]) * 32 for n in range(1, 5)]
    for key in keys:
        assert decrypt(encrypt(b"k", key=key), keys=keys) == b"k"
    src, out = io.BytesIO(b"stored"), io.BytesIO()
    codec.encrypt_stream(src, out, output="bytes")
    back = io.BytesIO()
    codec.decrypt_stream(io.BytesIO(out.getvalue()), back)
    assert back.getvalue() == b"stored"


def test_max_age():
    out = io.BytesIO()
    sealed.seal_stream(io.BytesIO(b"old"), out, key=KEY, output="bytes", now=1_000)
    with pytest.raises(yace.TokenExpiredError):
        sealed.unseal_stream(io.BytesIO(out.getvalue()), io.BytesIO(), keys=[KEY], max_age=10, now=2_000)
    target = io.BytesIO()
    sealed.unseal_stream(io.BytesIO(out.getvalue()), target, keys=[KEY], max_age=10, now=1_005)
    assert target.getvalue() == b"old"


def test_length_is_padded():
    # 9 bytes of metadata + 1016..1079 bytes of data share the Padmé length 1088.
    sizes = {len(encrypt(b"x" * n, chunk_size=1024)) for n in range(1016, 1080)}
    assert len(sizes) == 1


@pytest.mark.parametrize("chunk_size", [0, 63, 100, 2**21, -64])
def test_invalid_chunk_sizes(chunk_size):
    with pytest.raises(ValueError):
        encrypt(b"x", chunk_size=chunk_size)


def test_paths(tmp_path):
    source = tmp_path / "in.bin"
    source.write_bytes(os.urandom(10_000))
    yace.encrypt_stream(source, tmp_path / "enc.yace", key=KEY, output="bytes")
    yace.decrypt_stream(tmp_path / "enc.yace", tmp_path / "out.bin", keys=[KEY])
    assert (tmp_path / "out.bin").read_bytes() == source.read_bytes()


def test_failed_decryption_to_a_path_leaves_no_file(tmp_path):
    token = encrypt(os.urandom(500), chunk_size=64)
    (tmp_path / "bad.yace").write_bytes(token[:-1])
    with pytest.raises(yace.DecryptionError):
        yace.decrypt_stream(tmp_path / "bad.yace", tmp_path / "out.bin", keys=[KEY])
    assert list(tmp_path.iterdir()) == [tmp_path / "bad.yace"]


class Zeros(io.RawIOBase):
    def __init__(self, size: int) -> None:
        self.left = size

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        n = min(len(buffer), self.left)
        buffer[:n] = bytes(n)
        self.left -= n
        return n


class Sink(io.RawIOBase):
    def __init__(self) -> None:
        self.size = 0

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:
        self.size += len(data)
        return len(data)


def test_memory_stays_constant():
    size = 64 * 1024 * 1024
    sink = Sink()
    tracemalloc.start()
    yace.encrypt_stream(Zeros(size), sink, key=KEY, output="bytes")
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert sink.size > size
    assert peak < 4 * 1024 * 1024, peak


def test_decryption_memory_stays_constant(tmp_path):
    size = 32 * 1024 * 1024
    path = tmp_path / "big.yace"
    with open(path, "wb") as fh:
        yace.encrypt_stream(Zeros(size), fh, key=KEY, output="bytes")
    sink = Sink()
    tracemalloc.start()
    with open(path, "rb") as fh:
        info = yace.decrypt_stream(fh, sink, keys=[KEY])
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert info.size == size == sink.size
    assert peak < 4 * 1024 * 1024, peak


@settings(max_examples=60, deadline=None)
@given(
    data=st.binary(max_size=3000),
    chunk_size=st.sampled_from([64, 128, 1024]),
    algorithm=st.sampled_from(ALGORITHMS),
    output=st.sampled_from(["text", "bytes"]),
    aad=st.binary(max_size=40),
)
def test_round_trip_property(data, chunk_size, algorithm, output, aad):
    token = encrypt(data, chunk_size=chunk_size, algorithm=algorithm, output=output, aad=aad)
    assert decrypt(token, aad=aad) == data

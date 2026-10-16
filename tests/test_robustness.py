"""Edge cases and misuse: wrong keys, odd inputs, limits, and argument checking."""

import array
import io

import pytest

import yace_codec as yace
from yace_codec import sealed

KEY = bytes(range(32))


# --- the header check value ---------------------------------------------------------------


def test_wrong_keys_are_rejected_from_the_header_alone(monkeypatch):
    """A wrong key never gets past the header, so a stream is not read any further."""
    token = yace.encrypt(b"x" * 1000, key=KEY, output="bytes")
    opened = []
    real = sealed._open_message
    monkeypatch.setattr(sealed, "_open_message", lambda *a: opened.append(1) or real(*a))
    wrong = [bytes([n]) * 32 for n in range(1, 256)]
    with pytest.raises(yace.DecryptionError):
        yace.decrypt(token, keys=wrong)
    assert opened == []


def test_a_huge_junk_stream_is_rejected_after_the_header():
    class Endless(io.RawIOBase):
        def __init__(self):
            self.read_bytes = 0

        def readable(self):
            return True

        def readinto(self, buffer):
            self.read_bytes += len(buffer)
            buffer[:] = b"\x9b" * len(buffer)
            return len(buffer)

    source = Endless()
    with pytest.raises(yace.DecryptionError):
        yace.decrypt_stream(source, io.BytesIO(), keys=[KEY], aad=b"ctx")
    assert source.read_bytes < 1024 * 1024


def test_a_legacy_prefix_with_aad_fails_without_reading_everything():
    class Prefixed(io.RawIOBase):
        def __init__(self):
            self.sent = 0

        def readable(self):
            return True

        def readinto(self, buffer):
            data = (b"yace2_" if self.sent == 0 else b"") + b"1" * (len(buffer) - (6 if self.sent == 0 else 0))
            buffer[: len(data)] = data
            self.sent += len(data)
            return len(data)

    source = Prefixed()
    with pytest.raises(yace.DecryptionError):
        yace.decrypt_stream(source, io.BytesIO(), keys=[KEY], aad=b"ctx")
    assert source.sent < 1024 * 1024


# --- inputs ------------------------------------------------------------------------------------


def test_non_blocking_sources_are_refused_not_truncated():
    class Sometimes(io.RawIOBase):
        def __init__(self):
            self.calls = 0

        def readable(self):
            return True

        def read(self, size=-1):
            self.calls += 1
            return None if self.calls % 3 == 0 else b"y" * min(size, 10)

    with pytest.raises(OSError, match="would block"):
        yace.encrypt_stream(Sometimes(), io.BytesIO(), key=KEY)


def test_text_mode_sources_are_refused():
    with pytest.raises(TypeError, match="binary mode"):
        yace.encrypt_stream(io.StringIO("text"), io.BytesIO(), key=KEY)


def test_memoryviews_of_any_item_size_are_encrypted_whole():
    data = memoryview(array.array("I", [0x41424344, 0x45464748]))
    token = sealed.seal(data, text=False, key=KEY)
    assert sealed.unseal(token, keys=[KEY])[0] == data.tobytes()


def test_text_data_must_be_utf8():
    with pytest.raises(yace.EncodingError, match="UTF-8"):
        sealed.seal(b"\xff", text=True, key=KEY)


def test_only_ascii_whitespace_is_ignored():
    token = yace.encrypt("x", key=KEY)
    wrapped = token[:20] + " \t\r\n" + token[20:]
    assert yace.decrypt(wrapped, keys=[KEY]) == "x"
    assert yace.decrypt(wrapped.encode(), keys=[KEY]) == "x"
    with pytest.raises(yace.DecodingError):
        yace.decrypt(token[:20] + " " + token[20:], keys=[KEY])


def test_messages_over_the_limit_point_to_streams(monkeypatch):
    monkeypatch.setattr(sealed, "MAX_MESSAGE_SIZE", 1000)
    with pytest.raises(yace.EncodingError, match="encrypt_stream"):
        yace.encrypt(b"x" * 2000, key=KEY)


def test_overflow_in_the_aead_library_is_a_failed_open():
    cipher = sealed._algorithms.by_name("aes-256-gcm").cipher(bytes(32), 3, b"")

    class Huge:
        def decrypt(self, *args):
            raise OverflowError("Data or associated data too long")

    cipher._aead = Huge()
    assert cipher.open(b"", bytes(64)) is None


# --- the test hooks and limits ------------------------------------------------------------


@pytest.mark.parametrize("now", [float("nan"), float("inf"), -1, 2**64])
def test_invalid_creation_times_are_rejected(now):
    with pytest.raises(yace.EncodingError):
        sealed.seal(b"x", text=False, key=KEY, now=now)


@pytest.mark.parametrize("max_age", [True, "5", [1]])
def test_max_age_must_be_a_number(max_age):
    with pytest.raises(TypeError):
        yace.decrypt(yace.encrypt("x", key=KEY), keys=[KEY], max_age=max_age)


def test_a_nan_clock_does_not_disable_max_age():
    token = sealed.seal(b"x", text=False, key=KEY, now=1000)
    with pytest.raises(yace.DecodingError):
        sealed.unseal(token, keys=[KEY], max_age=10, now=float("nan"))


def test_an_empty_secret_token_on_decrypt_is_a_decryption_error():
    with pytest.raises(yace.DecryptionError, match="empty"):
        yace.decrypt(yace.encrypt("x", key=KEY), token="")


def test_streams_needing_a_missing_algorithm_say_so(monkeypatch):
    out = io.BytesIO()
    yace.encrypt_stream(io.BytesIO(b"x"), out, key=KEY, output="bytes", algorithm="chacha20-poly1305")
    monkeypatch.setattr(type(sealed._algorithms.by_name("chacha20-poly1305")), "available", property(lambda self: False))
    with pytest.raises(yace.DecryptionError, match="cryptography"):
        yace.decrypt_stream(io.BytesIO(out.getvalue()), io.BytesIO(), keys=[KEY])


# --- argument checking in the public API ---------------------------------------------------


@pytest.mark.parametrize(
    "kwargs, error",
    [
        ({"output": "hex"}, yace.EncodingError),
        ({"algorithm": "aes"}, yace.EncodingError),
        ({"aad": 5}, TypeError),
    ],
)
def test_bad_options_never_create_a_key(codec, kwargs, error):
    with pytest.raises(error):
        codec.encrypt("x", "fresh", **kwargs)
    with pytest.raises(TypeError):
        codec.encrypt(123, "fresh")
    with pytest.raises(yace.EncodingError):
        codec.encrypt_stream(io.BytesIO(b"x"), io.BytesIO(), "fresh", chunk_size=100)
    assert codec.key_backend.key_names() == []


def test_every_bad_argument_error_is_a_yace_error():
    for call in (
        lambda: yace.encrypt("x", key=KEY, output="hex"),
        lambda: yace.encrypt_stream(io.BytesIO(), io.BytesIO(), key=KEY, chunk_size=3),
        lambda: yace.open_key_backend("vault"),
    ):
        with pytest.raises(yace.YaceError):
            call()


def test_key_backend_can_be_named(memory_keyring):
    assert isinstance(yace.Codec(yace.KeyStore.in_memory(), key_backend="keyring").key_backend, yace.KeyringKeyStore)
    store = yace.KeyStore.in_memory()
    assert yace.Codec(store, key_backend="json").key_backend is store
    with pytest.raises(TypeError):
        yace.Codec(key_backend=42)


def test_key_names_are_not_echoed_in_errors(codec):
    secretish = yace.generate_key().hex()
    with pytest.raises(yace.InvalidNameError) as info:
        codec.encrypt("x", secretish)
    assert secretish not in str(info.value) and "key name" in str(info.value)


def test_decode_rejects_impossibly_long_tokens(codec, monkeypatch):
    from yace_codec import codec as codec_module

    monkeypatch.setattr(codec_module, "_MAX_TOKEN_CHARS", 1000)
    with pytest.raises(yace.DecodingError, match="longer than any token"):
        codec.decode("default-2:3\n" + "ab" * 600)

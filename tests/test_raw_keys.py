"""Encrypting with raw 32-byte keys, without a key store or scrypt."""

import hashlib

import pytest

import yace_codec as yace

KEY = bytes(range(32))


@pytest.fixture
def no_scrypt(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("scrypt must not run for raw keys")

    monkeypatch.setattr(hashlib, "scrypt", fail)


def test_module_functions_need_no_key_store(default_keystore, no_scrypt):
    token = yace.encrypt("raw", key=KEY)
    assert yace.decrypt(token, keys=[KEY]) == "raw"
    assert yace.decrypt(token, keys=[bytes(32), bytearray(KEY)]) == "raw"
    assert not default_keystore.exists()


def test_codec_raw_key_leaves_the_store_alone(codec, no_scrypt):
    token = codec.encrypt(b"\x00bytes", key=KEY)
    assert codec.keystore.key_names() == []
    assert codec.decrypt(token, keys=[KEY]) == b"\x00bytes"
    with pytest.raises(yace.DecryptionError):
        codec.decrypt(token)  # the (empty) key store does not have it


def test_keys_replace_the_key_store(codec):
    stored = codec.encrypt("stored")
    with pytest.raises(yace.DecryptionError):
        codec.decrypt(stored, keys=[KEY])
    assert codec.decrypt(stored) == "stored"


def test_generate_key():
    key = yace.generate_key()
    assert isinstance(key, bytes) and len(key) == 32 and key != yace.generate_key()
    assert yace.decrypt(yace.encrypt("fresh", key=key), keys=[key]) == "fresh"


@pytest.mark.parametrize("size", [0, 16, 31, 33, 64])
def test_wrong_key_sizes_are_rejected(size):
    with pytest.raises(yace.InvalidKeyError, match="32 bytes"):
        yace.encrypt("x", key=bytes(size))
    with pytest.raises(yace.InvalidKeyError, match="32 bytes"):
        yace.decrypt(yace.encrypt("x", key=KEY), keys=[bytes(size)])
    assert issubclass(yace.InvalidKeyError, ValueError)


@pytest.mark.parametrize("bad", [["not bytes"], [123], "a string, not a list"])
def test_keys_must_be_bytes(bad):
    with pytest.raises(TypeError):
        yace.decrypt(yace.encrypt("x", key=KEY), keys=bad)


def test_conflicting_secrets_are_rejected(codec):
    with pytest.raises(TypeError):
        codec.encrypt("x", key=KEY, token="pw")
    with pytest.raises(TypeError):
        codec.decrypt("x", keys=[KEY], token="pw")


def test_keys_never_appear_in_errors(codec):
    token = codec.encrypt("x", key=KEY)
    wrong = bytes([0xAB]) * 32
    with pytest.raises(yace.DecryptionError) as info:
        codec.decrypt(token, keys=[wrong])
    with pytest.raises(yace.InvalidKeyError) as size_info:
        codec.encrypt("x", key=wrong[:31])
    for exc in (info.value, size_info.value):
        text = f"{exc} {exc!r}"
        assert wrong.hex() not in text and "\\xab" not in text and "ab" * 8 not in text

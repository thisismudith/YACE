"""The versioned (v3) token format, its algorithms, and decryption of older tokens."""

import json
import string
from pathlib import Path

import pytest

import yace_codec as yace
from yace_codec import sealed

VECTORS = Path(__file__).parent / "vectors"
KEY = bytes(range(32))
ALGORITHMS = ["aes-256-gcm", "chacha20-poly1305", "yace-hmac-sha256"]


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    monkeypatch.setattr(sealed, "SCRYPT_N", 2**10)


def flip(token: str, index: int, bit: int = 0) -> str:
    raw = bytearray(sealed.yace62_decode(token))
    raw[index] ^= 1 << bit
    return sealed.yace62_encode(bytes(raw))


def test_algorithms_are_listed_with_an_explicit_default():
    infos = {info.name: info for info in yace.algorithms()}
    assert list(infos) == ALGORITHMS
    assert yace.DEFAULT_ALGORITHM == "aes-256-gcm"
    assert [name for name, info in infos.items() if info.default] == ["aes-256-gcm"]
    assert {info.id for info in infos.values()} == {1, 2, 3}
    assert all(info.available for info in infos.values())
    assert infos["aes-256-gcm"].tag_size == 16 and infos["yace-hmac-sha256"].tag_size == 32


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("data", ["", "Hello, World!", "नमस्ते दुनिया 😀", b"", b"\x00\xff" * 300])
def test_round_trip(algorithm, data):
    token = sealed.seal(
        data.encode() if isinstance(data, str) else data,
        text=isinstance(data, str), key=KEY, algorithm=algorithm,
    )
    assert set(token) <= set(string.ascii_letters + string.digits)
    plain, is_text = sealed.unseal(token, keys=[KEY])
    assert (plain.decode() if is_text else plain) == data


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_codec_algorithm_choice(codec, algorithm):
    token = codec.encrypt("pick me", algorithm=algorithm)
    assert codec.decrypt(token) == "pick me"
    token = codec.encrypt("pick me", token="secret", algorithm=algorithm)
    assert codec.decrypt(token, token="secret") == "pick me"


def test_unknown_algorithm_lists_the_options(codec):
    with pytest.raises(yace.EncodingError, match="aes-256-gcm, chacha20-poly1305, yace-hmac-sha256"):
        codec.encrypt("x", algorithm="rot13")


def test_header_is_masked():
    # Version and algorithm bytes are XORed with a key-derived mask, so tokens
    # have no fixed leading characters.
    tokens = [sealed.seal(b"x", text=False, key=KEY) for _ in range(300)]
    assert len({token[:2] for token in tokens}) > 100
    raw = [sealed.yace62_decode(token) for token in tokens]
    assert len({r[16] for r in raw}) > 100 and len({r[17] for r in raw}) > 100


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_every_byte_and_bit_is_authenticated(algorithm):
    token = sealed.seal(b"tamper", text=False, key=KEY, algorithm=algorithm)
    size = len(sealed.yace62_decode(token))
    for index in range(size):
        for bit in range(8):
            with pytest.raises(yace.DecryptionError):
                sealed.unseal(flip(token, index, bit), keys=[KEY])


def test_version_and_algorithm_bytes_are_authenticated():
    # Rewriting the (unmasked) algorithm id to another valid one must fail.
    token = sealed.seal(b"swap", text=False, key=KEY, algorithm="aes-256-gcm")
    raw = bytearray(sealed.yace62_decode(token))
    for target in (1, 3):
        changed = bytearray(raw)
        changed[17] ^= 2 ^ target
        with pytest.raises(yace.DecryptionError):
            sealed.unseal(sealed.yace62_encode(bytes(changed)), keys=[KEY])


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_wrong_key_and_wrong_secret(algorithm):
    token = sealed.seal(b"k", text=False, key=KEY, algorithm=algorithm)
    with pytest.raises(yace.DecryptionError):
        sealed.unseal(token, keys=[bytes(32)])
    token = sealed.seal(b"k", text=False, secret="right", algorithm=algorithm)
    with pytest.raises(yace.DecryptionError):
        sealed.unseal(token, secret="wrong")


def test_several_keys_are_tried():
    keys = [bytes([i]) * 32 for i in range(1, 6)]
    for key in keys:
        token = sealed.seal(b"which", text=False, key=key)
        assert sealed.unseal(token, keys=keys) == (b"which", False)


def test_fixed_salt_and_time_give_fixed_tokens():
    first = sealed.seal(b"same", text=False, key=KEY, salt=bytes(16), now=0)
    assert first == sealed.seal(b"same", text=False, key=KEY, salt=bytes(16), now=0)
    assert first != sealed.seal(b"same", text=False, key=KEY, salt=bytes(15) + b"\x01", now=0)


def test_new_tokens_are_not_legacy_tokens():
    token = sealed.seal(b"new", text=True, key=KEY)
    assert not token.startswith("yace2_")
    raw = sealed.yace62_decode(token)
    assert len(raw) == 16 + 2 + sealed.padme(17 + 3) + 16


def test_max_age_still_works():
    old = sealed.seal(b"old", text=False, key=KEY, now=1_000)
    assert sealed.unseal(old, keys=[KEY], max_age=60, now=1_030)[0] == b"old"
    with pytest.raises(yace.TokenExpiredError):
        sealed.unseal(old, keys=[KEY], max_age=60, now=1_100)


@pytest.mark.parametrize(
    "vector",
    json.loads((VECTORS / "legacy.json").read_text(encoding="utf-8"))["vectors"],
    ids=lambda v: f"{v['made_by']}-{'password' if 'password' in v else 'key'}",
)
def test_legacy_tokens_still_decrypt(vector, monkeypatch):
    expected = (
        vector["plaintext"].encode() if "plaintext" in vector else bytes.fromhex(vector["plaintext_hex"])
    )
    if "password" in vector:
        monkeypatch.setattr(sealed, "SCRYPT_N", vector["scrypt_n"])
        result = sealed.unseal(vector["token"], secret=vector["password"])
    else:
        result = sealed.unseal(vector["token"], keys=[bytes(32), bytes.fromhex(vector["key"])])
    assert result == (expected, vector["text"])
    with pytest.raises(yace.DecryptionError):
        sealed.unseal(vector["token"], keys=[bytes(32)], secret=None)

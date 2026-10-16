"""The versioned (v3) token format, its algorithms, and decryption of older tokens."""

import hmac
import json
import os
import random
import string
from pathlib import Path

import pytest

import yace_codec as yace
from yace_codec import sealed
from yace_codec._algorithms import hkdf_expand

VECTORS = Path(__file__).parent / "vectors"
KEY = bytes(range(32))
ALGORITHMS = ["aes-256-gcm", "chacha20-poly1305", "yace-hmac-sha256"]


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
    assert {info.tag_size for info in infos.values()} == {16}  # lengths do not reveal the algorithm


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
    assert len(raw) == 16 + 6 + sealed.padme(17 + 3) + 16


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


# --- building blocks and the Codec API ---------------------------------------------------


def test_hkdf_matches_rfc5869():
    def hkdf(ikm, salt, info, length):
        return hkdf_expand(hmac.digest(salt, ikm, "sha256"), info, length)

    assert hkdf(b"\x0b" * 22, bytes(range(13)), bytes(range(0xF0, 0xFA)), 42).hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
    assert hkdf(b"\x0b" * 22, bytes(32), b"", 42).hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    )


def test_padme():
    assert [sealed.padme(n) for n in (0, 1, 2, 3, 9, 17, 100, 1000)] == [0, 1, 2, 3, 10, 18, 104, 1024]
    for n in range(1, 5000):
        assert n <= sealed.padme(n) <= n + n // 8 + 1


@pytest.mark.parametrize("size", list(range(0, 40)) + [255, 1000])
def test_yace62_round_trip(size):
    data = os.urandom(size)
    text = sealed.yace62_encode(data)
    assert set(text) <= set(string.ascii_letters + string.digits)
    assert sealed.yace62_decode(text) == data


@pytest.mark.parametrize("text", ["A", "ABCD", "zzzzzzzzzzz", "zz", "ab!cd"])
def test_yace62_rejects_invalid_text(text):
    with pytest.raises(yace.DecodingError):
        sealed.yace62_decode(text)


@pytest.mark.parametrize(
    "data", ["Hello, World!", "", "café ☕ 日本語 😀\ttab\r\n", b"", b"\x00\xff" * 100, random.Random(0).randbytes(5000)]
)
def test_round_trip_keeps_type(codec, data):
    token = codec.encrypt(data)
    assert set(token) <= set(string.ascii_letters + string.digits)
    back = codec.decrypt(token)
    assert back == data and type(back) is type(data)


def test_tokens_reveal_nothing_readable(codec):
    token = codec.encrypt("team-3:2 secret plan", "teamkey")
    for leak in ("team", "secret", "plan", "default", "3:2", "yace"):
        assert leak not in token
    assert codec.encrypt("same") != codec.encrypt("same")


def test_length_is_padded(codec):
    # Frames of 121-128 bytes (17-byte header + 104-111 bytes of data) share one Padmé size.
    sizes = {len(codec.encrypt("x" * n)) for n in range(104, 112)}
    assert len(sizes) == 1


def test_large_round_trip(codec):
    data = os.urandom(300_000)
    assert codec.decrypt(codec.encrypt(data)) == data


def test_whitespace_and_bom_are_tolerated(codec):
    token = codec.encrypt("wrapped")
    wrapped = "\n".join(token[i : i + 20] for i in range(0, len(token), 20)) + "\r\n"
    assert codec.decrypt(wrapped) == "wrapped"
    assert codec.decrypt(b"\xef\xbb\xbf" + token.encode()) == "wrapped"
    assert codec.decrypt(token.encode("utf-16")) == "wrapped"


def test_wrong_key_store(codec):
    token = codec.encrypt("mine")
    other = yace.Codec(yace.KeyStore.in_memory())
    other.encrypt("their own key")
    with pytest.raises(yace.DecryptionError, match="cannot be opened"):
        other.decrypt(token)
    with pytest.raises(yace.DecryptionError, match="no keys"):
        yace.Codec(yace.KeyStore.in_memory()).decrypt(token)


def test_any_stored_key_is_tried(codec):
    tokens = {name: codec.encrypt(f"for {name}", name) for name in ("alpha", "beta", "gamma")}
    for name, token in tokens.items():
        assert codec.decrypt(token) == f"for {name}"


def test_own_secret_token(codec):
    out = codec.encrypt("pw", token="correct horse")
    assert codec.decrypt(out, token="correct horse") == "pw"
    assert yace.decrypt(out, token="correct horse") == "pw"
    assert yace.decrypt(out, password="correct horse") == "pw"  # 0.2.0 name
    assert codec.keystore.key_names() == []  # nothing generated
    with pytest.raises(yace.DecryptionError):
        codec.decrypt(out, token="wrong")
    with pytest.raises(yace.DecryptionError):
        codec.decrypt(out)  # stored keys do not open it
    with pytest.raises(yace.EncodingError, match="empty"):
        codec.encrypt("x", token="")
    with pytest.raises(TypeError):
        codec.encrypt("x", "key", token="pw")
    with pytest.raises(TypeError):
        codec.encrypt("x", token="a", password="a")
    with pytest.raises(TypeError):
        codec.encrypt("x", token=123)


def test_bytes_secret_token(codec):
    secret = os.urandom(32)
    out = codec.encrypt(b"raw", token=secret)
    assert codec.decrypt(out, token=bytearray(secret)) == b"raw"
    assert codec.decrypt(codec.encrypt("é", token="é"), token="é".encode()) == "é"


def test_token_mode_does_not_touch_the_default_key_store(default_keystore):
    out = yace.encrypt("no store", token="pw")
    assert yace.decrypt(out, token="pw") == "no store"
    assert not default_keystore.exists()


@pytest.mark.real_scrypt
def test_real_scrypt_cost():
    out = yace.encrypt("slow on purpose", token="pw")
    assert yace.decrypt(out, token="pw") == "slow on purpose"


def test_modes_point_to_each_other(codec):
    with pytest.raises(yace.DecodingError, match="use decrypt"):
        codec.decode(codec.encrypt("x"))
    with pytest.raises(yace.DecodingError, match="use decode"):
        codec.decrypt(codec.encode("x"))


@pytest.mark.parametrize("value", [123, None, ["x"]])
def test_encrypt_rejects_other_types(codec, value):
    with pytest.raises(TypeError):
        codec.encrypt(value)

"""Associated data (AAD): context that must match for decryption to succeed."""

import json
from pathlib import Path

import pytest

import yace_codec as yace
from yace_codec import sealed

KEY = bytes(range(32))
ALGORITHMS = ["aes-256-gcm", "chacha20-poly1305", "yace-hmac-sha256"]


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_matching_aad_decrypts(algorithm):
    token = sealed.seal(b"salary: 1", text=False, key=KEY, aad=b"row:1", algorithm=algorithm)
    assert sealed.unseal(token, keys=[KEY], aad=b"row:1") == (b"salary: 1", False)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_moved_token_does_not_decrypt(algorithm):
    token = sealed.seal(b"salary: 1", text=False, key=KEY, aad=b"row:1", algorithm=algorithm)
    for wrong in (b"row:2", b"", b"row:1 ", b"ROW:1"):
        with pytest.raises(yace.DecryptionError):
            sealed.unseal(token, keys=[KEY], aad=wrong)


def test_missing_aad_is_the_empty_aad():
    token = sealed.seal(b"x", text=False, key=KEY)
    assert sealed.unseal(token, keys=[KEY], aad=b"")[0] == b"x"
    with pytest.raises(yace.DecryptionError):
        sealed.unseal(token, keys=[KEY], aad=b"\x00")


def test_text_aad_is_utf8(codec):
    token = codec.encrypt("नमस्ते", aad="पंक्ति:1")
    assert codec.decrypt(token, aad="पंक्ति:1".encode()) == "नमस्ते"
    with pytest.raises(yace.DecryptionError):
        codec.decrypt(token, aad="पंक्ति:2")


def test_swap_between_rows(codec):
    rows = {f"row:{i}": codec.encrypt(f"value {i}", aad=f"row:{i}") for i in (1, 2)}
    assert codec.decrypt(rows["row:1"], aad="row:1") == "value 1"
    with pytest.raises(yace.DecryptionError):
        codec.decrypt(rows["row:1"], aad="row:2")


def test_aad_with_secret_token_and_module_functions():
    token = yace.encrypt("pw", token="secret", aad=b"ctx")
    assert yace.decrypt(token, token="secret", aad=b"ctx") == "pw"
    with pytest.raises(yace.DecryptionError):
        yace.decrypt(token, token="secret", aad=b"other")


@pytest.mark.parametrize("bad", [123, ["row"], None])
def test_aad_type_is_checked(codec, bad):
    with pytest.raises(TypeError):
        codec.encrypt("x", aad=bad)


def test_legacy_tokens_have_no_aad():
    vectors = json.loads((Path(__file__).parent / "vectors" / "legacy.json").read_text("utf-8"))
    legacy = next(v for v in vectors["vectors"] if v["made_by"] == "0.2.1" and "key" in v)
    key = bytes.fromhex(legacy["key"])
    assert sealed.unseal(legacy["token"], keys=[key])[0] == legacy["plaintext"].encode()
    with pytest.raises(yace.DecryptionError):
        sealed.unseal(legacy["token"], keys=[key], aad=b"row:1")

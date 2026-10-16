import hmac
import io
import json
import os
import random
import string
import sys
import time

import pytest

import yace_codec as yace
from yace_codec import sealed
from yace_codec._algorithms import hkdf_expand
from yace_codec.cli import main


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    """Use a cheap scrypt cost so password tests stay fast (one test uses the real cost)."""
    monkeypatch.setattr(sealed, "SCRYPT_N", 2**10)


@pytest.fixture
def codec():
    return yace.Codec(yace.KeyStore.in_memory())


# --- building blocks ----------------------------------------------------------


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


# --- encrypt / decrypt ----------------------------------------------------------


@pytest.mark.parametrize(
    "data", ["Hello, World!", "", "café ☕ 日本語 😀\ttab\r\n", b"", b"\x00\xff" * 100, os.urandom(5000)]
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


def test_every_changed_character_is_detected(codec):
    token = codec.encrypt("do not touch")
    for i in range(len(token)):
        alternative = "A" if token[i] != "A" else "B"
        with pytest.raises(yace.DecodingError):
            codec.decrypt(token[:i] + alternative + token[i + 1 :])


@pytest.mark.parametrize("cut", [1, 11, 40])
def test_truncation_is_detected(codec, cut):
    token = codec.encrypt("truncate me")
    with pytest.raises(yace.DecodingError):
        codec.decrypt(token[:-cut])


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


def test_tokens_from_0_2_0_still_decrypt():
    key_token = "yace2_32joe7Eeqrg2VYKzAx8Aa29ALANd7CjWZJektnTvWA3n6YdHQlimnW3JJT5EvItpz6D7nBNv84hHx7251RgLjreRHfJuPakqFoT0jeMVsGRn"
    assert sealed.unseal(key_token, keys=[bytes(range(32))]) == (b"made by 0.2.0", True)
    password_token = "yace2_KopBtgU1eRvJdFXHMTIKGJ7V9J8Em0QQ364OrHz8DjPW9fGaONvExjP4Kw25owKv361PVerIzq6QG1kyx1U9xHZwBpXHvguFaiR86p1agUV2x90rmMJN"
    assert yace.decrypt(password_token, password="pw020") == "password from 0.2.0"
    assert yace.decrypt(password_token, token="pw020") == "password from 0.2.0"
    with pytest.raises(yace.DecryptionError):  # the prefix is authenticated
        sealed.unseal(key_token[6:], keys=[bytes(range(32))])


def test_real_scrypt_cost(monkeypatch):
    monkeypatch.setattr(sealed, "SCRYPT_N", 2**17)
    out = yace.encrypt("slow on purpose", token="pw")
    assert yace.decrypt(out, token="pw") == "slow on purpose"


def test_max_age():
    key = os.urandom(32)
    old = sealed.seal(b"old", text=False, key=key, now=time.time() - 120)
    assert sealed.unseal(old, keys=[key], max_age=600)[0] == b"old"
    with pytest.raises(yace.TokenExpiredError):
        sealed.unseal(old, keys=[key], max_age=60)


def test_modes_point_to_each_other(codec):
    with pytest.raises(yace.DecodingError, match="use decrypt"):
        codec.decode(codec.encrypt("x"))
    with pytest.raises(yace.DecodingError, match="use decode"):
        codec.decrypt(codec.encode("x"))


@pytest.mark.parametrize("value", [123, None, ["x"]])
def test_encrypt_rejects_other_types(codec, value):
    with pytest.raises(TypeError):
        codec.encrypt(value)


# --- key store ------------------------------------------------------------------


def test_keys_persist_and_stay_out_of_tables(tmp_path):
    path = tmp_path / "keystore.json"
    codec = yace.Codec(path)
    token = codec.encrypt("persisted", "vault")
    codec.encode("x", "fam", length=2, iterations=1)
    reopened = yace.KeyStore(path)
    assert reopened.key_names() == ["vault"]
    assert reopened.table_names() == ["fam-2:1"] and len(reopened) == 1
    assert [f.name for f in reopened.families()] == ["fam"]
    assert yace.Codec(reopened).decrypt(token) == "persisted"
    assert reopened.ensure_key("vault") == reopened.get_key("vault")


def test_export_and_import_keys(codec):
    token = codec.encrypt("shared", "team")
    exported = json.loads(json.dumps(codec.keystore.export_key("team")))
    other = yace.KeyStore.in_memory()
    assert other.import_keys(exported, name="team").added == ("key:team",)
    assert yace.Codec(other).decrypt(token) == "shared"
    assert other.import_keys(exported).unchanged == ("key:team",)
    other.ensure_key("default")
    clash = {"key:default": {"secret": "A" * 43 + "="}}
    with pytest.raises(yace.KeyStoreError, match="already exist"):
        other.import_keys(clash)
    with pytest.raises(yace.KeyStoreError, match="no key named"):
        other.import_keys(exported, name="ghost")


@pytest.mark.parametrize(
    "data",
    [{"key:x": {"secret": "short"}}, {"key:x": "nope"}, {"key:bad-name": {"secret": "A" * 43 + "="}},
     {"notakey": {"secret": "A" * 43 + "="}}],
)
def test_invalid_key_imports(data):
    with pytest.raises(yace.KeyStoreError):
        yace.KeyStore.in_memory().import_keys(data)


def test_tables_import_refuses_keys(codec):
    codec.encrypt("x", "k")
    with pytest.raises(yace.KeyStoreError, match="import_keys"):
        yace.KeyStore.in_memory().import_tables(codec.keystore.export_key("k"))


# --- command line ---------------------------------------------------------------


@pytest.fixture
def run(capsysbinary, monkeypatch):
    def runner(*argv, stdin=b""):
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin)))
        code = main(list(argv))
        out, err = capsysbinary.readouterr()
        return code, out, err.decode("utf-8", "replace")

    return runner


def test_cli_encrypt_decrypt(run, tmp_path):
    code, token, _ = run("encrypt", "--text", "cli secret")
    assert code == 0 and token.strip().isalnum()
    assert run("decrypt", stdin=token)[:2] == (0, b"cli secret")
    blob = tmp_path / "blob.bin"
    blob.write_bytes(os.urandom(777))
    code, token, _ = run("encrypt", str(blob), "--key", "files")
    assert run("decrypt", stdin=token)[:2] == (0, blob.read_bytes())


def test_cli_token(run, monkeypatch):
    monkeypatch.delenv("YACE_CODEC_PASSWORD", raising=False)
    monkeypatch.setenv("YACE_CODEC_TOKEN", "s3cret")
    code, token, _ = run("encrypt", "--token", "--text", "via env")
    assert code == 0
    assert run("decrypt", "--token", stdin=token)[:2] == (0, b"via env")
    monkeypatch.delenv("YACE_CODEC_TOKEN")
    monkeypatch.setenv("YACE_CODEC_PASSWORD", "s3cret")  # 0.2.0 name
    assert run("decrypt", "--password", stdin=token)[:2] == (0, b"via env")
    monkeypatch.setenv("YACE_CODEC_PASSWORD", "wrong")
    code, _, err = run("decrypt", "-p", stdin=token)
    assert code == 1 and "cannot be opened" in err


def test_cli_password_prompt(run, monkeypatch):
    monkeypatch.delenv("YACE_CODEC_PASSWORD", raising=False)
    monkeypatch.delenv("YACE_CODEC_TOKEN", raising=False)
    answers = iter(["typed", "typed", "typed"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    code, token, _ = run("encrypt", "-p", "--text", "prompted")
    assert code == 0 and run("decrypt", "-p", stdin=token)[:2] == (0, b"prompted")
    answers = iter(["one", "two"])
    code, _, err = run("encrypt", "-p", "--text", "x")
    assert code == 1 and "do not match" in err


def test_cli_keys(run, tmp_path):
    run("encrypt", "--text", "x", "--key", "team")
    code, out, _ = run("keys", "list")
    assert out.decode().split() == ["team"]
    exported = tmp_path / "team.json"
    assert run("keys", "export", "team", "-o", str(exported))[0] == 0
    other = tmp_path / "other.json"
    code, _, err = run("keys", "import", str(exported), "-k", str(other))
    assert code == 1 and "--name NAME" in err
    code, _, err = run("keys", "import", str(exported), "--name", "team", "-k", str(other))
    assert code == 0 and "added: team" in err
    if os.name != "nt":
        assert oct(exported.stat().st_mode & 0o777) == "0o600"


def test_cli_max_age(run, tmp_path):
    code, token, _ = run("encrypt", "--text", "fresh")
    assert run("decrypt", "--max-age", "60", stdin=token)[:2] == (0, b"fresh")
    code, _, err = run("decrypt", "--max-age", "-1", stdin=token)
    assert code == 1 and "seconds old" in err

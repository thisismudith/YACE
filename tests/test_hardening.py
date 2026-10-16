"""Regression tests for issues found in the 0.3.0 security review."""

import io
import json
import os
import subprocess
import sys
import tracemalloc

import pytest

import yace_codec as yace
from yace_codec import sealed
from yace_codec.cli import main

KEY = bytes(range(32))
BOM_PREFIXES = [b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00"]


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    monkeypatch.setattr(sealed, "SCRYPT_N", 2**10)


# --- binary output that starts with a byte order mark ----------------------------------


@pytest.mark.parametrize("bom", BOM_PREFIXES)
def test_binary_tokens_that_start_like_a_bom_still_decrypt(bom):
    salt = (bom + os.urandom(16))[:16]
    token = sealed.seal(b"hello", text=False, key=KEY, salt=salt, output="bytes")
    assert yace.decrypt(token, keys=[KEY]) == b"hello"
    out = io.BytesIO()
    sealed.seal_stream(io.BytesIO(b"stream"), out, key=KEY, salt=salt, output="bytes", chunk_size=64)
    assert yace.decrypt(out.getvalue(), keys=[KEY]) == b"stream"
    back = io.BytesIO()
    yace.decrypt_stream(io.BytesIO(out.getvalue()), back, keys=[KEY])
    assert back.getvalue() == b"stream"


def test_random_salts_never_start_like_a_bom(monkeypatch):
    draws = iter([b"\xff\xfe" + bytes(14), b"\xef\xbb\xbf" + bytes(13), b"\x01" * 16])
    monkeypatch.setattr(sealed.secrets, "token_bytes", lambda n: next(draws))
    token = sealed.seal(b"x", text=False, key=KEY, output="bytes")
    assert token.startswith(b"\x01" * 16)


# --- wrong key or aad must not read a whole stream into memory ---------------------


def test_wrong_key_or_aad_fails_fast_on_streams(tmp_path):
    path = tmp_path / "big.yace"
    with open(path, "wb") as fh:
        yace.encrypt_stream(io.BytesIO(bytes(8 * 1024 * 1024)), fh, key=KEY, aad=b"a", output="bytes")
    for kwargs in ({"keys": [bytes(32)], "aad": b"a"}, {"keys": [KEY], "aad": b"b"}):
        tracemalloc.start()
        with open(path, "rb") as fh, pytest.raises(yace.DecryptionError):
            yace.decrypt_stream(fh, io.BytesIO(), **kwargs)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert peak < 2 * 1024 * 1024, (kwargs, peak)


def test_messages_still_decrypt_through_decrypt_stream():
    for output in ("text", "bytes"):
        token = yace.encrypt(b"m" * 100_000, key=KEY, output=output)
        blob = token.encode() if isinstance(token, str) else token
        back = io.BytesIO()
        yace.decrypt_stream(io.BytesIO(blob), back, keys=[KEY])
        assert back.getvalue() == b"m" * 100_000


# --- text streams must be valid UTF-8 ------------------------------------------------


def test_text_streams_must_be_utf8():
    with pytest.raises(yace.EncodingError, match="UTF-8"):
        yace.encrypt_stream(io.BytesIO(b"ok \xff\xfe\x80"), io.BytesIO(), key=KEY, text=True)
    with pytest.raises(yace.EncodingError, match="UTF-8"):
        yace.encrypt_stream(io.BytesIO(b"cut \xe0\xa4"), io.BytesIO(), key=KEY, text=True)
    out = io.BytesIO()
    yace.encrypt_stream(io.BytesIO("नमस्ते".encode() * 1000), out, key=KEY, text=True, chunk_size=64)
    assert yace.decrypt(out.getvalue(), keys=[KEY]) == "नमस्ते" * 1000


# --- max_age=NaN -------------------------------------------------------------------------


def test_nan_max_age_is_rejected():
    token = yace.encrypt("x", key=KEY)
    with pytest.raises(ValueError):
        yace.decrypt(token, keys=[KEY], max_age=float("nan"))
    assert yace.decrypt(token, keys=[KEY], max_age=float("inf")) == "x"


# --- command line file permissions -------------------------------------------------------


@pytest.fixture
def run(capsysbinary, monkeypatch):
    def runner(*argv, stdin=b""):
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin)))
        code = main([str(arg) for arg in argv])
        out, err = capsysbinary.readouterr()
        return code, out, err.decode("utf-8", "replace")

    return runner


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_decrypted_files_are_private_on_posix(run, tmp_path):
    (tmp_path / "plain.txt").write_text("secret")
    assert run("encrypt", tmp_path / "plain.txt", "-o", tmp_path / "enc.txt")[0] == 0
    assert run("decrypt", tmp_path / "enc.txt", "-o", tmp_path / "dec.txt")[0] == 0
    assert oct(os.stat(tmp_path / "dec.txt").st_mode & 0o777) == "0o600"
    os.chmod(tmp_path / "dec.txt", 0o640)  # an existing file keeps its mode
    assert run("decrypt", tmp_path / "enc.txt", "-o", tmp_path / "dec.txt")[0] == 0
    assert oct(os.stat(tmp_path / "dec.txt").st_mode & 0o777) == "0o640"
    umask = os.umask(0)
    os.umask(umask)
    assert os.stat(tmp_path / "enc.txt").st_mode & 0o777 == 0o666 & ~umask


def owner_only(path) -> bool:
    acl = subprocess.run(["icacls", str(path)], capture_output=True, text=True, check=True).stdout
    entries = [line for line in acl.splitlines()[:-1] if ":" in line]
    return "(I)" not in acl and len(entries) == 2


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ACLs")
def test_exported_keys_and_decrypted_files_are_private_on_windows(run, tmp_path):
    run("encrypt", "--text", "x", "--key", "team")
    assert run("keys", "export", "team", "-o", tmp_path / "team.json")[0] == 0
    assert owner_only(tmp_path / "team.json")
    code, token, _ = run("encrypt", "--text", "secret")
    (tmp_path / "enc.txt").write_bytes(token)
    assert run("decrypt", tmp_path / "enc.txt", "-o", tmp_path / "dec.txt")[0] == 0
    assert owner_only(tmp_path / "dec.txt")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_exported_keys_are_private_on_posix(run, tmp_path):
    run("encrypt", "--text", "x", "--key", "team")
    target = tmp_path / "team.json"
    target.write_text("old")
    os.chmod(target, 0o644)
    assert run("keys", "export", "team", "-o", target)[0] == 0
    assert oct(os.stat(target).st_mode & 0o777) == "0o600"
    assert "key:team" in json.loads(target.read_text())


# --- keyring backend ----------------------------------------------------------------------


def test_keyring_survives_many_rotations(memory_keyring):
    store = yace.KeyringKeyStore(service="rot")
    keys = [store.ensure_key("team")] + [store.rotate_key("team") for _ in range(60)]
    assert max(len(value) for value in memory_keyring.data.values()) < 200
    assert store.get_key("team") == keys[-1]
    assert sorted(store.decryption_keys()) == sorted(keys)
    exported = store.export_key("team")["key:team"]
    assert len(exported["retired"]) == 60 and exported["retired"][0] != exported["secret"]
    store.delete_key("team")
    assert memory_keyring.data == {("rot", "__yace_codec_key_names__:0"): "[]"}


def test_keyring_backend_errors_become_key_store_errors(memory_keyring, monkeypatch):
    store = yace.KeyringKeyStore(service="err")

    def fail(*args):
        raise RuntimeError("credential too large")

    monkeypatch.setattr(memory_keyring, "set_password", fail)
    with pytest.raises(yace.KeyStoreError, match="credential too large"):
        store.ensure_key("team")


def test_keyring_unindexed_and_stale_entries(memory_keyring):
    store = yace.KeyringKeyStore(service="idx")
    store.ensure_key("team")
    exported = store.export_key("team")
    memory_keyring.data[("idx", "__yace_codec_key_names__")] = "[]"  # lost index update
    other = {"key:team": {"secret": "A" * 43 + "="}}
    with pytest.raises(yace.KeyStoreError, match="already exist"):
        store.import_keys(other)
    assert store.import_keys(exported).unchanged == ("key:team",)
    assert store.key_names() == ["team"]  # the import repaired the index
    memory_keyring.data.pop(("idx", "key:team"))  # stale index entry
    store.delete_key("team")
    assert store.key_names() == []

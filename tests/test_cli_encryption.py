"""Command line: encrypt, decrypt, algorithms, and keys."""

import base64
import io
import json
import os
import sys
from pathlib import Path

import pytest

import yace_codec as yace
from yace_codec import sealed
from yace_codec.cli import main

VECTORS = Path(__file__).parent / "vectors"


@pytest.fixture(autouse=True)
def fast_scrypt_and_clean_env(monkeypatch):
    monkeypatch.setattr(sealed, "SCRYPT_N", 2**10)
    monkeypatch.delenv("YACE_CODEC_TOKEN", raising=False)
    monkeypatch.delenv("YACE_CODEC_PASSWORD", raising=False)


@pytest.fixture
def run(capsysbinary, monkeypatch):
    def runner(*argv, stdin=b""):
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin)))
        code = main([str(arg) for arg in argv])
        out, err = capsysbinary.readouterr()
        return code, out, err.decode("utf-8", "replace")

    return runner


def test_algorithms_command(run):
    code, out, _ = run("algorithms")
    lines = out.decode().splitlines()
    assert code == 0 and [line.split()[0] for line in lines] == [
        "aes-256-gcm", "chacha20-poly1305", "yace-hmac-sha256",
    ]
    assert "[default]" in lines[0] and "[default]" not in lines[1]


@pytest.mark.parametrize("algorithm", ["aes-256-gcm", "chacha20-poly1305", "yace-hmac-sha256"])
def test_algorithm_option(run, algorithm):
    code, token, _ = run("encrypt", "--text", "pick", "--algorithm", algorithm)
    assert code == 0 and token.strip().isalnum()
    assert run("decrypt", stdin=token)[:2] == (0, b"pick")
    with pytest.raises(SystemExit) as exit_info:
        run("encrypt", "--text", "x", "--algorithm", "rot13")
    assert exit_info.value.code == 2


def test_token_file(run, tmp_path):
    secret = tmp_path / "token.txt"
    secret.write_bytes(b"\xef\xbb\xbfmy secret\r\n")
    code, token, _ = run("encrypt", "--text", "from a file", "--token-file", secret)
    assert code == 0
    assert run("decrypt", "--token-file", secret, stdin=token)[:2] == (0, b"from a file")
    assert yace.decrypt(token.decode(), token="my secret") == "from a file"
    secret.write_bytes(b"\n")
    assert "empty" in run("encrypt", "--text", "x", "--token-file", secret)[2]


def test_token_stdin(run, tmp_path):
    source = tmp_path / "in.txt"
    source.write_bytes(b"secret file")
    code, token, _ = run("encrypt", source, "--token-stdin", stdin=b"line secret\nignored")
    assert code == 0
    (tmp_path / "enc.txt").write_bytes(token)
    assert run("decrypt", tmp_path / "enc.txt", "--token-stdin", stdin=b"line secret\n")[:2] == (
        0, b"secret file",
    )
    with pytest.raises(SystemExit) as exit_info:
        run("encrypt", "--token-stdin", stdin=b"secret\n")
    assert exit_info.value.code == 2


def test_secret_options_are_exclusive(run, tmp_path):
    (tmp_path / "t").write_text("x")
    for argv in (
        ("encrypt", "--text", "x", "--key", "a", "--token-file", tmp_path / "t"),
        ("decrypt", "--token", "--token-stdin"),
    ):
        with pytest.raises(SystemExit) as exit_info:
            run(*argv)
        assert exit_info.value.code == 2


def test_environment_variables_are_deprecated(run, monkeypatch):
    monkeypatch.setenv("YACE_CODEC_PASSWORD", "env secret")
    code, token, err = run("encrypt", "--token", "--text", "env")
    assert code == 0 and "deprecated" in err and "YACE_CODEC_PASSWORD" in err
    assert yace.decrypt(token.decode(), token="env secret") == "env"


def test_aad_option(run):
    code, token, _ = run("encrypt", "--text", "row data", "--aad", "row:1")
    assert run("decrypt", "--aad", "row:1", stdin=token)[:2] == (0, b"row data")
    code, _, err = run("decrypt", "--aad", "row:2", stdin=token)
    assert code == 1 and "cannot be opened" in err


def test_bytes_format_and_large_files(run, tmp_path):
    data = os.urandom(3 * 1024 * 1024 + 5)
    (tmp_path / "big.bin").write_bytes(data)
    assert run("encrypt", tmp_path / "big.bin", "-o", tmp_path / "big.yace", "--format", "bytes")[0] == 0
    encrypted = (tmp_path / "big.yace").read_bytes()
    assert len(data) < len(encrypted) < len(data) * 1.07
    assert run("decrypt", tmp_path / "big.yace", "-o", tmp_path / "out.bin")[0] == 0
    assert (tmp_path / "out.bin").read_bytes() == data


def test_failed_decryption_keeps_the_old_output_file(run, tmp_path):
    code, token, _ = run("encrypt", "--text", "secret")
    (tmp_path / "bad.txt").write_bytes(token[:-20])
    (tmp_path / "out.txt").write_bytes(b"keep me")
    code, _, err = run("decrypt", tmp_path / "bad.txt", "-o", tmp_path / "out.txt")
    assert code == 1
    assert (tmp_path / "out.txt").read_bytes() == b"keep me"
    assert sorted(p.name for p in tmp_path.iterdir() if p.is_file()) == ["bad.txt", "out.txt"]


def test_text_input_round_trips_as_text(run):
    code, token, _ = run("encrypt", "--text", "नमस्ते")
    assert yace.decrypt(token.decode()) == "नमस्ते"
    assert run("decrypt", "--text", token.decode().strip())[:2] == (0, "नमस्ते".encode())


def test_keys_rotate_and_delete(run):
    code, old_token, _ = run("encrypt", "--text", "old", "--key", "team")
    code, _, err = run("keys", "rotate", "team")
    assert code == 0 and "rotated" in err
    code, new_token, _ = run("encrypt", "--text", "new", "--key", "team")
    assert run("decrypt", stdin=old_token)[:2] == (0, b"old")
    assert run("decrypt", stdin=new_token)[:2] == (0, b"new")
    code, _, err = run("keys", "delete", "team")
    assert code == 1 and "--yes" in err
    assert run("keys", "delete", "team", "--yes")[0] == 0
    assert run("decrypt", stdin=old_token)[0] == 1


def test_keyring_backend(run, memory_keyring):
    code, token, _ = run("encrypt", "--text", "in keyring", "--key-backend", "keyring", "--key", "k")
    assert code == 0
    assert run("keys", "list", "--key-backend", "keyring")[1].split() == [b"k"]
    assert run("decrypt", "--key-backend", "keyring", stdin=token)[:2] == (0, b"in keyring")
    assert run("decrypt", stdin=token)[0] == 1  # not in the JSON key store


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_dpapi_backend(run, tmp_path):
    store = tmp_path / "store.json"  # -k names the key store; DPAPI keys go next to it
    code, token, _ = run("encrypt", "--text", "dpapi", "--key-backend", "dpapi", "-k", store)
    dpapi_file = tmp_path / "keys-dpapi.json"
    assert code == 0 and not store.exists() and b"secret" not in dpapi_file.read_bytes()
    assert run("decrypt", "--key-backend", "dpapi", "-k", store, stdin=token)[:2] == (0, b"dpapi")
    code, _, err = run("decrypt", "-k", store, stdin=token)
    assert code == 1 and "--key-backend" in err


def test_legacy_tokens_decrypt_from_the_command_line(run, tmp_path):
    vectors = json.loads((VECTORS / "legacy.json").read_text("utf-8"))["vectors"]
    for vector in vectors:
        if "key" not in vector or not vector["text"]:
            continue
        keys = {"key:legacy": {"secret": base64.b64encode(bytes.fromhex(vector["key"])).decode()}}
        (tmp_path / "legacy.json").write_text(json.dumps(keys))
        store = tmp_path / f"store-{vector['made_by']}.json"
        assert run("keys", "import", tmp_path / "legacy.json", "--name", "legacy", "-k", store)[0] == 0
        assert run("decrypt", "-k", store, "--text", vector["token"])[:2] == (
            0, vector["plaintext"].encode(),
        )

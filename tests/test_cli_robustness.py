"""Command line: usage errors, odd inputs and outputs, and helpful messages."""

import os
import sys

import pytest

from yace_codec.cli import main


@pytest.mark.parametrize(
    "argv",
    [
        ("encode", "-l", "1", "--text", "x"),
        ("encode", "-l", "63", "--text", "x"),
        ("encode", "-i", "0", "--text", "x"),
        ("encode", "-i", "33", "--text", "x"),
        ("decrypt", "--max-age", "nan"),
        ("decrypt", "--max-age", "-5"),
        ("encrypt", "--text", "x", "--key", "a:b"),
        ("encrypt", "--text", "x", "--key", ""),
        ("keys", "rotate", "bad-name"),
        ("keys", "import", "f.json", "--all"),  # no abbreviations
        ("keys", "list", "--key-backend", "keyring", "-k", "store.json"),
    ],
)
def test_usage_errors_exit_2(usage, argv):
    code, _ = usage(*argv)
    assert code == 2


def test_input_and_text_together_is_a_usage_error_of_the_command(usage):
    code, err = usage("encode", "-", "--text", "hi")
    assert code == 2 and "usage: yace-codec encode" in err and "not both" in err


def test_invalid_key_names_are_not_echoed(usage):
    code, err = usage("encrypt", "--text", "x", "--key", "hunter2!")
    assert code == 2 and "hunter2" not in err and "key name" in err


def test_utf16_token_files(run, tmp_path):
    utf16 = tmp_path / "t16.txt"
    utf16.write_bytes("secret-token\r\n".encode("utf-16"))
    ascii_file = tmp_path / "t8.txt"
    ascii_file.write_bytes(b"secret-token\n")
    code, token, _ = run("encrypt", "--token-file", utf16, "--text", "hi")
    assert code == 0
    assert run("decrypt", "--token-file", ascii_file, stdin=token)[:2] == (0, b"hi")


def test_output_errors_name_the_target(run, tmp_path):
    target = tmp_path / "missing" / "x.txt"
    code, _, err = run("encrypt", "--text", "x", "-o", target)
    assert code == 1 and str(target) in err and ".part" not in err


def test_output_to_the_null_device(run):
    assert run("encrypt", "--text", "x", "-o", os.devnull)[0] == 0


def test_encrypting_a_file_onto_itself(run, tmp_path):
    path = tmp_path / "same.txt"
    path.write_bytes(b"in place")
    assert run("encrypt", path, "-o", path)[0] == 0
    assert run("decrypt", path, "-o", path)[0] == 0
    assert path.read_bytes() == b"in place"


def test_no_terminal_for_the_prompt(run, monkeypatch):
    monkeypatch.setattr("yace_codec.cli._can_prompt", lambda: False)
    code, _, err = run("encrypt", "-p", "--text", "x")
    assert code == 1 and "--token-file" in err


def test_rotating_a_missing_key_is_refused(run):
    code, _, err = run("keys", "rotate", "ghost")
    assert code == 1 and "no key 'ghost'" in err and "encrypt --key ghost" in err
    assert run("keys", "list")[1] == b""


def test_powershell_text_with_a_byte_order_mark(run):
    code, token, _ = run("encode", stdin=b"\xef\xbb\xbfhello")
    assert code == 0
    assert run("decode", stdin=token)[1] == b"hello"
    code, token, _ = run("encode", stdin="hello".encode("utf-16"))
    assert code == 0 and run("decode", stdin=token)[1] == b"hello"


def test_wrong_file_kind_on_import(run, tmp_path):
    run("encrypt", "--text", "x", "--key", "team")
    run("encode", "--text", "x", "-n", "fam")
    keys_file, tables_file = tmp_path / "keys.json", tmp_path / "tables.json"
    run("keys", "export", "team", "-o", keys_file)
    run("tables", "export", "fam", "-o", tables_file)
    code, _, err = run("tables", "import", keys_file)
    assert code == 1 and "keys import" in err
    code, _, err = run("keys", "import", tables_file)
    assert code == 1 and "tables import" in err


def test_wrong_key_store_hint(run, tmp_path):
    code, token, _ = run("encrypt", "--text", "x")
    code, _, err = run("decrypt", "-k", tmp_path / "other.json", stdin=token)
    assert code == 1 and "--keystore" in err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_decoded_files_are_private(run, tmp_path):
    code, token, _ = run("encode", "--text", "plain")
    (tmp_path / "t.txt").write_bytes(token)
    assert run("decode", tmp_path / "t.txt", "-o", tmp_path / "out.txt")[0] == 0
    assert oct(os.stat(tmp_path / "out.txt").st_mode & 0o777) == "0o600"


def test_help_for_every_command(capsys):
    for argv in (["-h"], ["encrypt", "-h"], ["decrypt", "-h"], ["keys", "rotate", "-h"], ["tables", "import", "-h"]):
        with pytest.raises(SystemExit) as info:
            main(argv)
        assert info.value.code == 0
        assert "usage:" in capsys.readouterr().out


def test_a_token_file_with_a_bom_but_invalid_text(run, tmp_path):
    bad = tmp_path / "t.txt"
    bad.write_bytes(bytes([0xFF, 0xFE, 0xFD]))
    code, _, err = run("encrypt", "--token-file", bad, "--text", "x")
    assert code == 1 and str(bad) in err and "byte order mark" in err

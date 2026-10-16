import io
import json
import os
import shutil
import stat
import subprocess
import sys

import pytest

import yace_codec as yace
from yace_codec.cli import main


@pytest.fixture
def run(capsysbinary, monkeypatch):
    """Run the CLI in-process; return (exit code, stdout bytes, stderr text)."""

    def runner(*argv, stdin=b""):
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin)))
        code = main(list(argv))
        out, err = capsysbinary.readouterr()
        return code, out, err.decode("utf-8", "replace")

    return runner


def test_encode_and_decode_text(run, tmp_path):
    code, token, _ = run("encode", "--text", "Hello, CLI!", "-n", "cli", "-l", "3", "-i", "2")
    assert code == 0 and token.startswith(b"cli-3:2\n") and token.endswith(b"\n")
    code, out, _ = run("decode", stdin=token)
    assert (code, out) == (0, b"Hello, CLI!")


def test_files_and_keystore_option(run, tmp_path):
    source = tmp_path / "message.txt"
    source.write_bytes(b"line one\r\nline two\n")
    keystore = tmp_path / "keys.json"
    token_file = tmp_path / "message.yace"
    result = tmp_path / "decoded.txt"
    assert run("encode", str(source), "-o", str(token_file), "-k", str(keystore))[0] == 0
    assert keystore.exists()
    assert run("decode", str(token_file), "-o", str(result), "--keystore", str(keystore))[0] == 0
    assert result.read_bytes() == source.read_bytes()


def test_binary_round_trip(run, tmp_path):
    payload = bytes(range(256)) + "café".encode("utf-8")
    source = tmp_path / "blob.bin"
    source.write_bytes(payload)
    code, token, _ = run("encode", "--binary", str(source))
    assert code == 0
    code, out, _ = run("decode", "--binary", stdin=token)
    assert (code, out) == (0, payload)


def test_unsupported_text_suggests_binary(run):
    code, out, err = run("encode", stdin="naïve".encode("utf-8"))
    assert code == 1 and out == b""
    assert "cannot encode" in err and "--binary" in err


def test_invalid_utf8_suggests_binary(run):
    code, _, err = run("encode", stdin=b"\xff\xfe")
    assert code == 1 and "not valid UTF-8" in err and "--binary" in err


def test_decode_errors(run):
    code, _, err = run("decode", "--text", "missing-2:1\nabcd")
    assert code == 1 and "yace-codec: error: table 'missing-2:1' is not in" in err
    code, _, err = run("decode", "--text", "garbage")
    assert code == 1 and "invalid header" in err


def test_missing_input_file(run, tmp_path):
    code, _, err = run("encode", str(tmp_path / "nope.txt"))
    assert code == 1 and "nope.txt" in err


def test_input_and_text_are_exclusive(run):
    with pytest.raises(SystemExit) as info:
        run("encode", "file.txt", "--text", "x")
    assert info.value.code == 2


def test_invalid_name(run):
    code, _, err = run("encode", "--text", "x", "-n", "bad-name")
    assert code == 1 and "invalid table family name" in err


def test_tables_commands(run, tmp_path, default_keystore):
    run("encode", "--text", "one", "-n", "alpha", "-l", "2", "-i", "2")
    run("encode", "--text", "two", "-n", "beta", "-l", "3", "-i", "1")

    code, out, _ = run("tables", "path")
    assert (code, out.decode().strip()) == (0, str(default_keystore))

    code, out, _ = run("tables", "list")
    assert code == 0
    assert out.decode().splitlines() == ["NAME   LENGTH  LAYERS", "alpha  2       1,2", "beta   3       1"]

    export = tmp_path / "alpha.json"
    assert run("tables", "export", "alpha", "-o", str(export))[0] == 0
    assert sorted(json.loads(export.read_text())) == ["alpha-2:1", "alpha-2:2"]
    if os.name != "nt":
        assert stat.S_IMODE(export.stat().st_mode) == 0o600

    other = tmp_path / "other.json"
    code, _, err = run("tables", "import", str(export), "--family", "alpha", "-k", str(other))
    assert code == 0 and "2 added, 0 unchanged, 0 replaced" in err
    code, _, err = run("tables", "import", "-", "--family", "alpha", "-k", str(other), stdin=export.read_bytes())
    assert code == 0 and "0 added, 2 unchanged" in err


def test_tables_list_empty(run):
    code, out, err = run("tables", "list")
    assert code == 0 and out == b"" and "no tables" in err


def test_tables_import_conflict_and_overwrite(run, tmp_path):
    run("encode", "--text", "x", "-n", "dup", "-i", "1")
    other = yace.KeyStore(tmp_path / "other.json")
    other.ensure_tables("dup", 2, 1)
    export = tmp_path / "dup.json"
    export.write_text(json.dumps(other.export_family("dup")))
    code, _, err = run("tables", "import", str(export), "--family", "dup")
    assert code == 1 and "already exist" in err and "--overwrite" in err
    code, _, err = run("tables", "import", str(export), "--family", "dup", "--overwrite")
    assert code == 0 and "1 replaced" in err


def test_tables_import_invalid_json(run, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    code, _, err = run("tables", "import", str(bad))
    assert code == 1 and "not valid JSON" in err


def test_tables_export_unknown(run):
    code, _, err = run("tables", "export", "ghost")
    assert code == 1 and "no tables for family 'ghost'" in err


def test_version(run, capsysbinary):
    with pytest.raises(SystemExit) as info:
        run("--version")
    assert info.value.code == 0
    assert capsysbinary.readouterr().out.decode().strip() == f"yace-codec {yace.__version__}"


def test_python_dash_m(tmp_path):
    env = {**os.environ, yace.ENV_VAR: str(tmp_path / "ks.json")}
    proc = subprocess.run(
        [sys.executable, "-m", "yace_codec", "encode", "--text", "via -m"],
        capture_output=True, env=env, check=True,
    )
    back = subprocess.run(
        [sys.executable, "-m", "yace_codec", "decode"],
        input=proc.stdout, capture_output=True, env=env, check=True,
    )
    assert back.stdout == b"via -m"
    version = subprocess.run(
        [sys.executable, "-m", "yace_codec", "--version"], capture_output=True, text=True, check=True
    )
    assert version.stdout.strip() == f"yace-codec {yace.__version__}"


def test_console_script(tmp_path):
    exe = shutil.which("yace-codec", path=os.path.dirname(sys.executable)) or shutil.which(
        "yace-codec", path=os.path.join(os.path.dirname(sys.executable), "Scripts")
    )
    if exe is None:
        pytest.skip("yace-codec console script is not installed next to this interpreter")
    env = {**os.environ, yace.ENV_VAR: str(tmp_path / "ks.json")}
    out = subprocess.run([exe, "encode", "--text", "script"], capture_output=True, env=env, check=True)
    assert subprocess.run(
        [exe, "decode"], input=out.stdout, capture_output=True, env=env, check=True
    ).stdout == b"script"



# --- review regressions -------------------------------------------------------


def test_tables_import_deeply_nested_json(run, tmp_path):
    bad = tmp_path / "deep.json"
    bad.write_text("[" * 100_000 + "]" * 100_000)
    code, _, err = run("tables", "import", str(bad))
    # Python 3.14 parses deep nesting; earlier versions hit the recursion limit.
    assert code == 1 and ("not valid JSON" in err or "expected a JSON object" in err)


def test_powershell_utf16_files(run, tmp_path):
    token = run("encode", "--text", "utf-16 file", "-n", "ps", "-i", "1")[1]
    token_file = tmp_path / "token.txt"
    token_file.write_bytes(token.decode("ascii").replace("\n", "\r\n").encode("utf-16"))
    code, out, _ = run("decode", str(token_file))
    assert (code, out) == (0, b"utf-16 file")

    exported = tmp_path / "ps.json"
    run("tables", "export", "ps", "-o", str(exported))
    exported.write_bytes(exported.read_text().encode("utf-16"))
    code, _, err = run("tables", "import", str(exported), "--family", "ps", "-k", str(tmp_path / "other.json"))
    assert code == 0 and "1 added" in err


def test_directories_are_reported_clearly(run, tmp_path):
    folder = tmp_path / "adir"
    folder.mkdir()
    for argv in (["encode", str(folder)], ["encode", "--text", "x", "-o", str(folder)],
                 ["decode", str(folder)], ["tables", "import", str(folder)]):
        code, _, err = run(*argv)
        assert code == 1 and "is a directory" in err, (argv, err)


def test_text_argument_with_undecodable_bytes(run):
    code, token, _ = run("encode", "--binary", "--text", "caf\udce9")
    assert code == 0
    code, out, _ = run("decode", "--binary", stdin=token)
    assert code == 0 and out == os.fsencode("caf\udce9")
    code, _, err = run("encode", "--text", "caf\udce9")
    assert code == 1 and "--binary" in err


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_export_tightens_existing_file_mode(run, tmp_path):
    run("encode", "--text", "x", "-n", "perm", "-i", "1")
    target = tmp_path / "perm.json"
    target.write_text("old")
    os.chmod(target, 0o644)
    assert run("tables", "export", "perm", "-o", str(target))[0] == 0
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_closed_pipe_exits_quietly(tmp_path):
    source = tmp_path / "big.txt"
    source.write_text("a closed pipe should not print a traceback " * 3000)
    env = {**os.environ, yace.ENV_VAR: str(tmp_path / "ks.json")}
    proc = subprocess.Popen(
        [sys.executable, "-m", "yace_codec", "encode", str(source)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
    )
    proc.stdout.close()  # the reader goes away before the token is written
    err = proc.stderr.read()
    proc.stderr.close()
    assert proc.wait(timeout=120) == 1
    assert b"Traceback" not in err and b"Exception ignored" not in err, err


def test_import_of_several_families_needs_a_choice(run, tmp_path):
    source = yace.KeyStore.in_memory()
    source.ensure_tables("team", 2, 1)
    source.ensure_tables("default", 2, 3)
    shared = tmp_path / "shared.json"
    shared.write_text(json.dumps({**source.export_family("team"), **source.export_family("default")}))
    mine = tmp_path / "mine.json"

    code, _, err = run("tables", "import", str(shared), "-k", str(mine))
    assert code == 1 and "holds tables for: default, team" in err and "--family" in err
    assert not mine.exists()

    code, _, err = run("tables", "import", str(shared), "--family", "team", "-k", str(mine))
    assert code == 0 and "added: team-2:1" in err and "default" not in err
    assert yace.KeyStore(mine).table_names() == ["team-2:1"]

    code, _, err = run("tables", "import", str(shared), "--all-families", "-k", str(mine))
    assert code == 0 and "3 added, 1 unchanged" in err


def test_import_needs_a_family_even_for_one_family(run, tmp_path):
    source = yace.KeyStore.in_memory()
    source.ensure_tables("default", 2, 3)
    planted = tmp_path / "planted.json"
    planted.write_text(json.dumps(source.export_family("default")))
    mine = tmp_path / "mine.json"
    code, _, err = run("tables", "import", str(planted), "-k", str(mine))
    assert code == 1 and "holds tables for: default" in err
    assert not mine.exists()
    code, _, err = run("tables", "import", str(planted), "--family", "team", "-k", str(mine))
    assert code == 1 and "no tables for family 'team'" in err

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import yace_codec as yace
from yace_codec.keystore import default_keystore_path


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_default_path_from_environment(default_keystore):
    assert default_keystore_path() == default_keystore
    assert yace.KeyStore.default().path == default_keystore


def test_default_path_per_platform(monkeypatch, tmp_path):
    monkeypatch.delenv(yace.ENV_VAR)
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    path = default_keystore_path()
    assert path.parts[-2:] == ("yace-codec", "keystore.json")
    if sys.platform == "win32":
        assert path.parent.parent == tmp_path / "appdata"
    elif sys.platform != "darwin":
        assert path.parent.parent == tmp_path / "xdg"


def test_relative_xdg_data_home_is_ignored(monkeypatch):
    if sys.platform in ("win32", "darwin"):
        pytest.skip("XDG only applies on Linux and other Unix systems")
    monkeypatch.delenv(yace.ENV_VAR)
    monkeypatch.setenv("XDG_DATA_HOME", "relative/dir")
    assert default_keystore_path() == Path.home() / ".local" / "share" / "yace-codec" / "keystore.json"


def test_missing_file_is_empty_and_not_created(file_store):
    assert len(file_store) == 0
    assert file_store.find("x-2:1") is None
    assert not file_store.path.exists()


def test_tables_persist(file_store):
    tables = file_store.ensure_tables("persist", 3, 2)
    assert file_store.path.exists()
    data = read(file_store.path)
    assert sorted(data) == ["persist-3:1", "persist-3:2"]
    assert data["persist-3:1"] == tables[0].to_dict()
    reopened = yace.KeyStore(file_store.path)
    assert reopened.get("persist-3:2") == tables[1]


def test_writes_leave_no_temporary_files(file_store):
    file_store.ensure_tables("clean", 2, 3)
    file_store.ensure_tables("other", 2, 1)
    names = sorted(p.name for p in file_store.path.parent.iterdir())
    assert names == ["keystore.json", "keystore.json.lock"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_file_permissions_are_private(file_store):
    file_store.ensure_tables("private", 2, 1)
    assert stat.S_IMODE(file_store.path.stat().st_mode) == 0o600


def test_invalid_json_is_never_overwritten(tmp_path):
    path = tmp_path / "keystore.json"
    path.write_text('{"broken": ', encoding="utf-8")
    codec = yace.Codec(path)
    with pytest.raises(yace.KeyStoreError, match="not valid JSON"):
        codec.encode("abc")
    assert path.read_text(encoding="utf-8") == '{"broken": '


@pytest.mark.parametrize("content", ["[]", '"text"', "42"])
def test_non_object_json_is_rejected(tmp_path, content):
    path = tmp_path / "keystore.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(yace.KeyStoreError, match="JSON object"):
        yace.KeyStore(path).table_names()


@pytest.mark.parametrize("content", [b"", b"  \n", b"\xef\xbb\xbf{}"])
def test_empty_or_bom_files_are_accepted(tmp_path, content):
    path = tmp_path / "keystore.json"
    path.write_bytes(content)
    store = yace.KeyStore(path)
    assert len(store) == 0
    store.ensure_tables("fresh", 2, 1)
    assert list(read(path)) == ["fresh-2:1"]


def test_directory_is_rejected(tmp_path):
    with pytest.raises(yace.KeyStoreError, match="directory"):
        yace.KeyStore(tmp_path).table_names()


def test_unknown_and_invalid_entries_are_preserved(tmp_path):
    path = tmp_path / "keystore.json"
    path.write_text(json.dumps({"notes": {"owner": "me"}, "broken-2:1": {"a": "b"}}), encoding="utf-8")
    store = yace.KeyStore(path)
    with pytest.raises(yace.KeyStoreError, match="'broken-2:1' is invalid"):
        store.get("broken-2:1")
    store.ensure_tables("good", 2, 1)
    data = read(path)
    assert data["notes"] == {"owner": "me"} and data["broken-2:1"] == {"a": "b"}
    assert "good-2:1" in data


def test_other_instances_see_new_tables(file_store):
    other = yace.KeyStore(file_store.path)
    assert other.find("seen-2:1") is None
    file_store.ensure_tables("seen", 2, 1)
    assert other.get("seen-2:1") == file_store.get("seen-2:1")


def test_existing_tables_are_never_regenerated(file_store):
    first = file_store.ensure_tables("stable", 2, 1)[0]
    again = yace.KeyStore(file_store.path).ensure_tables("stable", 2, 2)
    assert again[0] == first


WORKER = """
import sys
import yace_codec as yace
store = yace.KeyStore(sys.argv[1])
for i in range(5):
    store.ensure_tables(sys.argv[2] + "_" + "abcde"[i], 2, 2)
"""


def test_concurrent_processes_do_not_lose_tables(file_store):
    families = [f"proc_{c}" for c in "abcdefgh"]
    procs = [
        subprocess.Popen([sys.executable, "-c", WORKER, str(file_store.path), family])
        for family in families
    ]
    assert [p.wait(timeout=120) for p in procs] == [0] * len(procs)
    expected = {f"{f}_{c}-2:{layer}" for f in families for c in "abcde" for layer in (1, 2)}
    assert set(read(file_store.path)) == expected


def test_families(store):
    store.ensure_tables("beta", 3, 2)
    store.ensure_tables("alpha", 2, 1)
    store.ensure_tables("alpha", 4, 3)
    assert store.families() == [
        yace.Family("alpha", 2, (1,)),
        yace.Family("alpha", 4, (1, 2, 3)),
        yace.Family("beta", 3, (1, 2)),
    ]
    assert "beta-3:2" in store and "beta-3:3" not in store
    assert store.table_names()[0] == "alpha-2:1"


def test_export_and_import(file_store, tmp_path):
    file_store.ensure_tables("share", 3, 2)
    file_store.ensure_tables("private", 3, 1)
    exported = file_store.export_family("share")
    assert sorted(exported) == ["share-3:1", "share-3:2"]

    other = yace.KeyStore(tmp_path / "other.json")
    result = other.import_tables(json.loads(json.dumps(exported)))
    assert result == yace.ImportResult(("share-3:1", "share-3:2"), (), ())
    assert other.import_tables(exported) == yace.ImportResult((), ("share-3:1", "share-3:2"), ())
    assert other.table_names() == ["share-3:1", "share-3:2"]

    token = yace.Codec(file_store).encode("shared secret-ish", "share", length=3, iterations=2)
    assert yace.Codec(other).decode(token) == "shared secret-ish"


def test_import_conflicts_need_overwrite(store):
    store.ensure_tables("clash", 2, 1)
    original = store.get("clash-2:1")
    replacement = yace.KeyStore.in_memory()
    replacement.ensure_tables("clash", 2, 1)
    replacement.ensure_tables("extra", 2, 1)
    incoming = {**replacement.export_family("clash"), **replacement.export_family("extra")}

    with pytest.raises(yace.KeyStoreError, match="already exist"):
        store.import_tables(incoming)
    assert store.get("clash-2:1") == original
    assert "extra-2:1" not in store, "a failed import must not write anything"

    result = store.import_tables(incoming, overwrite=True)
    assert result == yace.ImportResult(("extra-2:1",), (), ("clash-2:1",))
    assert store.get("clash-2:1") == replacement.get("clash-2:1")


def test_import_validates_everything_first(file_store):
    good = yace.KeyStore.in_memory()
    good.ensure_tables("good", 2, 1)
    payload = {**good.export_family("good"), "bad-2:1": {"a": "b"}}
    with pytest.raises(yace.KeyStoreError, match="'bad-2:1' is invalid"):
        file_store.import_tables(payload)
    assert not file_store.path.exists()
    with pytest.raises(yace.KeyStoreError):
        file_store.import_tables(["not", "a", "mapping"])


def test_export_unknown_family(store):
    with pytest.raises(yace.TableNotFoundError) as info:
        store.export_family("ghost")
    assert info.value.table_name == "ghost"


def test_in_memory_store(store):
    assert store.path is None
    assert repr(store) == "KeyStore.in_memory()"
    store.ensure_tables("mem", 2, 1)
    store.reload()
    assert "mem-2:1" in store


def test_repr_of_file_store(file_store):
    assert repr(file_store) == f"KeyStore({str(file_store.path)!r})"


def test_ensure_tables_validates_family(store):
    with pytest.raises(yace.InvalidNameError):
        store.ensure_tables("bad-name", 2, 1)



# --- review regressions -------------------------------------------------------


def test_deeply_nested_json_is_rejected(tmp_path):
    path = tmp_path / "keystore.json"
    path.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    # Python 3.14 parses deep nesting; earlier versions hit the recursion limit.
    with pytest.raises(yace.KeyStoreError, match="not valid JSON|must contain a JSON object"):
        yace.KeyStore(path).table_names()


def test_utf16_key_store_is_readable(tmp_path):
    path = tmp_path / "keystore.json"
    source = yace.KeyStore.in_memory()
    source.ensure_tables("wide", 2, 1)
    path.write_bytes(json.dumps(source.export_family("wide")).encode("utf-16"))
    assert yace.KeyStore(path).get("wide-2:1") == source.get("wide-2:1")


def test_relative_path_is_anchored_when_created(tmp_path, monkeypatch):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    monkeypatch.chdir(tmp_path / "a")
    store = yace.KeyStore("keys.json")
    assert store.path == tmp_path / "a" / "keys.json"
    monkeypatch.chdir(tmp_path / "b")
    store.ensure_tables("anchored", 2, 1)
    assert (tmp_path / "a" / "keys.json").exists()
    assert not (tmp_path / "b" / "keys.json").exists()


def test_relative_environment_path_is_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(yace.ENV_VAR, "rel/ks.json")
    assert default_keystore_path() == tmp_path / "rel" / "ks.json"


def test_unexpandable_home_is_a_keystore_error(monkeypatch):
    if sys.platform == "win32":
        pytest.skip("'~user' expansion only fails like this on POSIX")
    with pytest.raises(yace.KeyStoreError, match="cannot expand"):
        yace.KeyStore("~no_such_user_for_yace_tests/ks.json")


def test_null_table_is_reported_as_invalid(tmp_path):
    path = tmp_path / "keystore.json"
    path.write_text('{"fam-2:1": null}', encoding="utf-8")
    store = yace.KeyStore(path)
    with pytest.raises(yace.KeyStoreError, match="is invalid"):
        store.get("fam-2:1")
    with pytest.raises(yace.KeyStoreError, match="is invalid"):
        yace.Codec(store).encode("hi", "fam", iterations=1)


def test_no_op_import_does_not_lock_or_write(tmp_path):
    source = yace.KeyStore.in_memory()
    source.ensure_tables("same", 2, 1)
    path = tmp_path / "keystore.json"
    path.write_text(json.dumps(source.export_family("same")), encoding="utf-8")
    before = path.read_bytes()
    result = yace.KeyStore(path).import_tables(source.export_family("same"))
    assert result == yace.ImportResult((), ("same-2:1",), ())
    assert path.read_bytes() == before
    assert not (tmp_path / "keystore.json.lock").exists()


def test_hard_linked_key_store_is_not_split(tmp_path):
    path = tmp_path / "keystore.json"
    store = yace.KeyStore(path)
    store.ensure_tables("first", 2, 1)
    try:
        os.link(path, tmp_path / "other-link.json")
    except (OSError, NotImplementedError):
        pytest.skip("cannot create hard links here")
    with pytest.raises(yace.KeyStoreError, match="hard links"):
        store.ensure_tables("second", 2, 1)


def test_symlinked_keystore_stays_a_link(tmp_path):
    real = tmp_path / "real.json"
    link = tmp_path / "link.json"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symbolic links here")
    yace.KeyStore(link).ensure_tables("linked", 2, 1)
    assert link.is_symlink()
    assert "linked-2:1" in read(real)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_existing_file_mode_is_kept(file_store):
    file_store.ensure_tables("first", 2, 1)
    os.chmod(file_store.path, 0o640)
    file_store.ensure_tables("second", 2, 1)
    assert stat.S_IMODE(file_store.path.stat().st_mode) == 0o640


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ACLs")
def test_existing_file_acl_is_kept_on_windows(file_store):
    file_store.ensure_tables("first", 2, 1)
    user = os.environ.get("USERNAME")
    if not user or shutil.which("icacls") is None:
        pytest.skip("icacls or USERNAME not available")
    target = str(file_store.path)
    subprocess.run(["icacls", target, "/inheritance:r", "/grant:r", f"{user}:F"], check=True,
                   capture_output=True)
    file_store.ensure_tables("second", 2, 1)
    acl = subprocess.run(["icacls", target], check=True, capture_output=True, text=True).stdout
    assert "(I)" not in acl, acl  # nothing inherited from the folder again
    assert "second-2:1" in read(file_store.path)


def test_import_can_be_limited_to_one_family(store):
    source = yace.KeyStore.in_memory()
    source.ensure_tables("team", 2, 1)
    source.ensure_tables("default", 2, 2)
    data = {**source.export_family("team"), **source.export_family("default")}
    result = store.import_tables(data, family="team")
    assert result.added == ("team-2:1",)
    assert store.table_names() == ["team-2:1"]
    with pytest.raises(yace.KeyStoreError, match="no tables for family 'ghost'"):
        store.import_tables(data, family="ghost")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_lock_file_follows_key_store_permissions(file_store):
    file_store.ensure_tables("first", 2, 1)
    os.chmod(file_store.path, 0o660)
    lock = Path(f"{file_store.path}.lock")
    os.chmod(lock, 0o600)
    file_store.ensure_tables("second", 2, 1)
    assert stat.S_IMODE(lock.stat().st_mode) == 0o660

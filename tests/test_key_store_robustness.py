"""Key stores and backends under concurrency, partial failures, and odd contents."""

import json
import os
import sys
import threading
import time

import pytest

import yace_codec as yace
from yace_codec import keystore as keystore_module

WINDOWS = sys.platform == "win32"


# --- JSON key store ------------------------------------------------------------------------


def test_readers_wait_out_a_replacement(tmp_path):
    """A reader that finds the file missing while a writer replaces it waits for the writer."""
    path = tmp_path / "keys.json"
    writer = yace.KeyStore(path)
    key = writer.ensure_key("team")
    reader = yace.KeyStore(path)
    assert reader.get_key("team") == key
    target = keystore_module._resolve_link(path)
    moved = threading.Event()

    def replace_slowly():
        with keystore_module._file_lock(target):
            os.replace(path, tmp_path / "aside.json")
            moved.set()
            time.sleep(0.3)
            os.replace(tmp_path / "aside.json", path)

    thread = threading.Thread(target=replace_slowly)
    thread.start()
    moved.wait()
    assert reader.decryption_keys() == [key]
    thread.join()


def test_a_bad_key_entry_does_not_block_the_others(tmp_path):
    path = tmp_path / "keys.json"
    store = yace.KeyStore(path)
    good = store.ensure_key("good")
    data = json.loads(path.read_text())
    data["key:broken"] = {"secret": "not base64!"}
    path.write_text(json.dumps(data))
    with pytest.warns(RuntimeWarning, match="broken"):
        assert yace.KeyStore(path).decryption_keys() == [good]
    data = {"key:broken": {"secret": "x"}}
    path.write_text(json.dumps(data))
    with pytest.raises(yace.KeyStoreError):
        yace.KeyStore(path).decryption_keys()


def test_a_dpapi_entry_in_a_json_store_explains_itself(tmp_path):
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"key:team": {"dpapi": "AAAA"}}))
    with pytest.raises(yace.KeyStoreError, match="dpapi"):
        yace.KeyStore(path).get_key("team")


def test_key_entries_are_not_tables(tmp_path):
    store = yace.KeyStore(tmp_path / "keys.json")
    store.ensure_key("team")
    assert "key:team" not in store and store.find("key:team") is None and len(store) == 0


def test_missing_keys_raise_key_not_found(store):
    with pytest.raises(yace.KeyNotFoundError) as info:
        store.get_key("ghost")
    assert info.value.key_name == "ghost" and isinstance(info.value, yace.TableNotFoundError)
    for call in (store.delete_key, store.export_key):
        with pytest.raises(yace.KeyNotFoundError):
            call("ghost")


def test_invalid_key_names_in_imports_are_not_echoed(store):
    secretish = "Hunter2Password" + "x" * 60
    with pytest.raises(yace.KeyStoreError) as info:
        store.import_keys({f"key:{secretish}": {"secret": "A" * 43 + "="}})
    assert secretish not in str(info.value)


# --- DPAPI -------------------------------------------------------------------------------


@pytest.mark.skipif(not WINDOWS, reason="Windows only")
def test_dpapi_store_holds_keys_only(tmp_path):
    store = yace.DpapiKeyStore(tmp_path / "dpapi.json")
    with pytest.raises(yace.KeyStoreError, match="keys only"):
        store.ensure_tables("fam", 2, 1)
    with pytest.raises(yace.KeyStoreError, match="keys only"):
        store.import_tables({})


@pytest.mark.skipif(not WINDOWS, reason="Windows only")
def test_dpapi_keys_are_unprotected_once(tmp_path, monkeypatch):
    store = yace.DpapiKeyStore(tmp_path / "dpapi.json")
    for name in ("a", "b", "c"):
        store.ensure_key(name)
    calls = []
    real = yace.keybackends._winsec.unprotect
    monkeypatch.setattr(yace.keybackends._winsec, "unprotect", lambda blob: calls.append(1) or real(blob))
    fresh = yace.DpapiKeyStore(tmp_path / "dpapi.json")
    for _ in range(5):
        assert len(fresh.decryption_keys()) == 3
    assert len(calls) == 3


@pytest.mark.skipif(WINDOWS, reason="DPAPI exists on Windows")
def test_dpapi_store_fails_early_elsewhere(tmp_path):
    with pytest.raises(yace.KeyStoreError, match="Windows"):
        yace.DpapiKeyStore(tmp_path / "dpapi.json")


# --- keyring ---------------------------------------------------------------------------


def test_keyring_writers_do_not_lose_keys(memory_keyring, monkeypatch):
    real_set = memory_keyring.set_password

    def slow_set(service, username, password):  # widen the race window
        time.sleep(0.002)
        real_set(service, username, password)

    monkeypatch.setattr(memory_keyring, "set_password", slow_set)
    results = {}

    def worker(n):
        store = yace.KeyringKeyStore(service="race")
        results[f"new{n}"] = store.ensure_key(f"name_{chr(97 + n)}")
        results[f"shared{n}"] = store.ensure_key("shared")
        results[f"rotated{n}"] = store.rotate_key("rotating")

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    store = yace.KeyringKeyStore(service="race")
    assert store.key_names() == sorted({"shared", "rotating"} | {f"name_{chr(97 + n)}" for n in range(6)})
    assert len({results[f"shared{n}"] for n in range(6)}) == 1
    every_key = set(store.decryption_keys())
    assert {results[f"rotated{n}"] for n in range(6)} <= every_key
    assert {results[f"new{n}"] for n in range(6)} <= every_key


def test_keyring_failure_part_way_loses_nothing(memory_keyring, monkeypatch):
    store = yace.KeyringKeyStore(service="fail")
    store.ensure_key("team")
    for _ in range(3):
        store.rotate_key("team")
    before = store.export_key("team")
    replacement = {"key:team": {"secret": "A" * 43 + "=", "retired": ["B" * 43 + "="]}}
    real_set = memory_keyring.set_password

    def fail_on_main(service, user, value):
        if user == "key:team":
            raise RuntimeError("disk full")
        real_set(service, user, value)

    monkeypatch.setattr(memory_keyring, "set_password", fail_on_main)
    with pytest.raises(yace.KeyStoreError, match="disk full"):
        store.import_keys(replacement, overwrite=True)
    with pytest.raises(yace.KeyStoreError):
        store.rotate_key("team")
    monkeypatch.setattr(memory_keyring, "set_password", real_set)
    assert store.export_key("team") == before


def test_keyring_delete_failures_are_reported(memory_keyring, monkeypatch):
    store = yace.KeyringKeyStore(service="del")
    store.ensure_key("team")

    def fail(service, user):
        raise RuntimeError("locked")

    monkeypatch.setattr(memory_keyring, "delete_password", fail)
    with pytest.raises(yace.KeyStoreError, match="locked"):
        store.delete_key("team")


def test_keyring_index_stays_small(memory_keyring):
    store = yace.KeyringKeyStore(service="many")
    names = [("n" * 60) + "_" + "".join(chr(97 + (i // 26 ** k) % 26) for k in range(3)) for i in range(120)]
    for name in names:
        store.ensure_key(name)
    assert store.key_names() == sorted(names)
    assert max(len(value) for value in memory_keyring.data.values()) <= 1000
    for name in names[:100]:
        store.delete_key(name)
    assert store.key_names() == sorted(names[100:])


def test_open_key_backend_rejects_arguments_it_would_ignore(memory_keyring, tmp_path):
    with pytest.raises(TypeError):
        yace.open_key_backend("keyring", path=tmp_path / "x.json")
    with pytest.raises(TypeError):
        yace.open_key_backend("json", service="svc")
    assert yace.open_key_backend("keyring", service="svc").service == "svc"

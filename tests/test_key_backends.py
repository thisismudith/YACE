"""Key store backends: JSON file, Windows DPAPI, and the system keyring."""

import base64
import io
import json
import os
import subprocess
import sys

import pytest

import yace_codec as yace
from yace_codec import keybackends

pytest.importorskip("keyring")

WINDOWS = sys.platform == "win32"


def json_backend(tmp_path):
    return yace.KeyStore(tmp_path / "keys.json")


def dpapi_backend(tmp_path):
    return yace.DpapiKeyStore(tmp_path / "keys-dpapi.json")


def keyring_backend(tmp_path):
    return yace.KeyringKeyStore(service=f"yace-codec-test-{tmp_path.name}")


BACKENDS = [
    pytest.param(json_backend, id="json"),
    pytest.param(dpapi_backend, id="dpapi", marks=pytest.mark.skipif(not WINDOWS, reason="Windows only")),
    pytest.param(keyring_backend, id="keyring"),
]


@pytest.fixture(params=BACKENDS)
def make_backend(request, tmp_path, memory_keyring):
    return lambda: request.param(tmp_path)


def test_backends_implement_the_protocol(make_backend):
    assert isinstance(make_backend(), yace.KeyBackend)
    assert isinstance(yace.KeyStore.in_memory(), yace.KeyBackend)


def test_create_and_load(make_backend):
    backend = make_backend()
    assert backend.key_names() == [] and backend.find_key("team") is None
    key = backend.ensure_key("team")
    assert len(key) == 32 and backend.ensure_key("team") == key
    reopened = make_backend()
    assert reopened.key_names() == ["team"] and reopened.get_key("team") == key
    assert reopened.decryption_keys() == [key]


def test_rotate_keeps_old_tokens_readable(make_backend):
    backend = make_backend()
    codec = yace.Codec(yace.KeyStore.in_memory(), key_backend=backend)
    old_token = codec.encrypt("before", "team")
    old_key = backend.get_key("team")
    new_key = backend.rotate_key("team")
    assert new_key != old_key and backend.get_key("team") == new_key
    assert backend.key_names() == ["team"]
    assert sorted(backend.decryption_keys()) == sorted([old_key, new_key])
    new_token = codec.encrypt("after", "team")
    assert yace.decrypt(new_token, keys=[new_key]) == "after"
    reopened = yace.Codec(yace.KeyStore.in_memory(), key_backend=make_backend())
    assert reopened.decrypt(old_token) == "before" and reopened.decrypt(new_token) == "after"


def test_export_import_carries_retired_keys(make_backend):
    backend = make_backend()
    codec = yace.Codec(yace.KeyStore.in_memory(), key_backend=backend)
    old_token = codec.encrypt("old", "team")
    backend.rotate_key("team")
    exported = json.loads(json.dumps(backend.export_key("team")))
    assert set(exported["key:team"]) == {"secret", "retired"}
    other = yace.KeyStore.in_memory()
    assert other.import_keys(exported, name="team").added == ("key:team",)
    assert yace.Codec(other).decrypt(old_token) == "old"
    assert backend.import_keys(exported).unchanged == ("key:team",)


def test_delete(make_backend):
    backend = make_backend()
    backend.ensure_key("gone")
    backend.delete_key("gone")
    assert backend.key_names() == [] and make_backend().find_key("gone") is None
    with pytest.raises(yace.TableNotFoundError):
        backend.delete_key("gone")


def test_rotate_creates_a_missing_key(make_backend):
    backend = make_backend()
    key = backend.rotate_key("fresh")
    assert backend.get_key("fresh") == key and backend.decryption_keys() == [key]


def test_module_functions_take_a_backend(make_backend):
    backend = make_backend()
    token = yace.encrypt("via backend", "team", key_backend=backend)
    assert yace.decrypt(token, key_backend=backend) == "via backend"
    sink, back = io.BytesIO(), io.BytesIO()
    assert yace.encrypt_stream(io.BytesIO(b"s"), sink, "team", key_backend=backend) > 0
    yace.decrypt_stream(io.BytesIO(sink.getvalue()), back, key_backend=backend)
    assert back.getvalue() == b"s"


def test_json_store_stays_readable_by_0_2(tmp_path):
    store = json_backend(tmp_path)
    store.ensure_key("team")
    current = store.rotate_key("team")
    raw = json.loads((tmp_path / "keys.json").read_text())
    assert base64.b64decode(raw["key:team"]["secret"]) == current  # what 0.2.x reads


@pytest.mark.skipif(not WINDOWS, reason="Windows only")
def test_dpapi_file_holds_no_plaintext_keys(tmp_path):
    store = dpapi_backend(tmp_path)
    key = store.ensure_key("team")
    store.rotate_key("team")
    content = (tmp_path / "keys-dpapi.json").read_bytes()
    assert base64.b64encode(key) not in content and key.hex().encode() not in content
    assert "secret" not in json.loads(content)["key:team"]


@pytest.mark.skipif(not WINDOWS, reason="Windows only")
def test_new_files_are_owner_only_on_windows(tmp_path):
    for store in (json_backend(tmp_path), dpapi_backend(tmp_path)):
        store.ensure_key("team")
        acl = subprocess.run(
            ["icacls", str(store.path)], capture_output=True, text=True, check=True
        ).stdout
        entries = [line.strip() for line in acl.splitlines()[:-1] if ":" in line]
        assert "(I)" not in acl  # no inherited entries
        assert len(entries) == 2 and any("SYSTEM" in entry for entry in entries), acl


@pytest.mark.skipif(WINDOWS, reason="POSIX only")
def test_new_files_are_owner_only_on_posix(tmp_path):
    store = json_backend(tmp_path)
    store.ensure_key("team")
    assert oct(os.stat(store.path).st_mode & 0o777) == "0o600"


@pytest.mark.skipif(WINDOWS, reason="DPAPI is available on Windows")
def test_dpapi_is_windows_only(tmp_path):
    with pytest.raises(yace.KeyStoreError, match="Windows"):
        dpapi_backend(tmp_path).ensure_key("x")


def test_open_key_backend(tmp_path, memory_keyring):
    assert isinstance(yace.open_key_backend("json", path=tmp_path / "a.json"), yace.KeyStore)
    assert isinstance(yace.open_key_backend("keyring"), yace.KeyringKeyStore)
    with pytest.raises(ValueError, match="json, dpapi, keyring"):
        yace.open_key_backend("vault")


def test_no_secrets_in_repr(make_backend):
    backend = make_backend()
    key = backend.ensure_key("team")
    text = repr(backend) + repr(yace.Codec(yace.KeyStore.in_memory(), key_backend=backend))
    assert base64.b64encode(key).decode() not in text and key.hex() not in text


def test_keyring_index_survives_reopen(memory_keyring):
    first = yace.KeyringKeyStore(service="svc")
    first.ensure_key("a")
    first.ensure_key("b")
    assert yace.KeyringKeyStore(service="svc").key_names() == ["a", "b"]
    assert yace.KeyringKeyStore(service="other").key_names() == []


def test_keybackends_module_exports():
    assert keybackends.KeyBackend is yace.KeyBackend

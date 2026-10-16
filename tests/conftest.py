"""Shared fixtures. Every test runs isolated from the user's real key store and keyring."""

import io
import json
import os
import sys
from pathlib import Path

import pytest
from hypothesis import settings

import yace_codec as yace
from yace_codec import sealed
from yace_codec.cli import main

FIXTURES = Path(__file__).parent / "fixtures"

# Deterministic property tests in CI (CI=true), so a failure can be reproduced.
settings.register_profile("ci", derandomize=True, deadline=None, print_blob=True)
if os.environ.get("CI"):
    settings.load_profile("ci")


@pytest.fixture(autouse=True)
def default_keystore(tmp_path, monkeypatch):
    """Point the default key store at a temporary file so tests never touch the real one."""
    path = tmp_path / "default" / "keystore.json"
    monkeypatch.setenv(yace.ENV_VAR, str(path))
    return path


@pytest.fixture(autouse=True)
def isolated_secrets(request, monkeypatch):
    """Cheap scrypt, no secret tokens from the environment, and no real keyring."""
    if request.node.get_closest_marker("real_scrypt") is None:
        monkeypatch.setattr(sealed, "SCRYPT_N", 2**10)
    monkeypatch.delenv("YACE_CODEC_TOKEN", raising=False)
    monkeypatch.delenv("YACE_CODEC_PASSWORD", raising=False)
    # A stray call to the system keyring fails instead of touching it.
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")


@pytest.fixture
def store():
    return yace.KeyStore.in_memory()


@pytest.fixture
def codec(store):
    return yace.Codec(store)


@pytest.fixture
def file_store(tmp_path):
    return yace.KeyStore(tmp_path / "store" / "keystore.json")


@pytest.fixture
def run(capsysbinary, monkeypatch):
    """Run the CLI in-process; return (exit code, stdout bytes, stderr text)."""

    def runner(*argv, stdin=b""):
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin)))
        code = main([str(arg) for arg in argv])
        out, err = capsysbinary.readouterr()
        return code, out, err.decode("utf-8", "replace")

    return runner


@pytest.fixture
def usage(run, capsysbinary):
    """Run the CLI expecting a usage error; return (exit code, stderr text)."""

    def runner(*argv, stdin=b""):
        with pytest.raises(SystemExit) as info:
            run(*argv, stdin=stdin)
        err = capsysbinary.readouterr().err.decode("utf-8", "replace")
        return info.value.code, err

    return runner


@pytest.fixture(scope="session")
def legacy_tables():
    return json.loads((FIXTURES / "legacy_keystore.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def legacy_vectors():
    return json.loads((FIXTURES / "legacy_tokens.json").read_text(encoding="utf-8"))["vectors"]


@pytest.fixture
def memory_keyring():
    """Replace the system keyring with an in-memory one for the test."""
    keyring = pytest.importorskip("keyring")
    from keyring.backend import KeyringBackend
    from keyring.errors import PasswordDeleteError

    class MemoryKeyring(KeyringBackend):
        priority = 1

        def __init__(self) -> None:
            super().__init__()
            self.data = {}

        def get_password(self, service, username):
            return self.data.get((service, username))

        def set_password(self, service, username, password):
            self.data[(service, username)] = password

        def delete_password(self, service, username):
            if self.data.pop((service, username), None) is None:
                raise PasswordDeleteError(username)

    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(previous)

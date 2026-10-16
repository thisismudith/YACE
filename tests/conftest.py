import json
from pathlib import Path

import pytest

import yace_codec as yace

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def default_keystore(tmp_path, monkeypatch):
    """Point the default key store at a temporary file so tests never touch the real one."""
    path = tmp_path / "default" / "keystore.json"
    monkeypatch.setenv(yace.ENV_VAR, str(path))
    return path


@pytest.fixture
def store():
    return yace.KeyStore.in_memory()


@pytest.fixture
def codec(store):
    return yace.Codec(store)


@pytest.fixture
def file_store(tmp_path):
    return yace.KeyStore(tmp_path / "store" / "keystore.json")


@pytest.fixture(scope="session")
def legacy_tables():
    return json.loads((FIXTURES / "legacy_keystore.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def legacy_vectors():
    return json.loads((FIXTURES / "legacy_tokens.json").read_text(encoding="utf-8"))["vectors"]

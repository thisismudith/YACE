"""Published test vectors: fixed inputs must give these exact tokens, and decrypt back."""

import io
import json
from pathlib import Path

import pytest

from yace_codec import _algorithms, sealed

# Secret-token vectors use the real scrypt cost that the format defines.
pytestmark = pytest.mark.real_scrypt

VECTORS = json.loads((Path(__file__).parent / "vectors" / "v3.json").read_text(encoding="utf-8"))["vectors"]


def plaintext(vector) -> bytes:
    return vector["plaintext"].encode() if "plaintext" in vector else bytes.fromhex(vector["plaintext_hex"])


def secret_args(vector) -> dict:
    if "key" in vector:
        return {"key": bytes.fromhex(vector["key"])}
    return {"secret": vector["secret_token"]}


def label(vector) -> str:
    who = "key" if "key" in vector else "token"
    return f"v{vector['format']}-{vector['algorithm']}-{who}-{vector['output']}-{vector['salt'][:4]}"


def test_vectors_cover_every_algorithm_and_format():
    assert {(v["format"], v["algorithm"]) for v in VECTORS} == {
        (version, alg.name) for version in (3, 4) for alg in _algorithms.algorithms()
    }
    assert {v["output"] for v in VECTORS if v["format"] == 3} == {"text", "bytes"}


@pytest.mark.parametrize("vector", VECTORS, ids=label)
def test_vector(vector):
    if "scrypt" in vector:
        assert vector["scrypt"] == {"n": sealed.SCRYPT_N, "r": sealed.SCRYPT_R, "p": sealed.SCRYPT_P}
    data, aad = plaintext(vector), vector["aad"].encode()
    salt = bytes.fromhex(vector["salt"])
    expected = vector["expected"] if vector["output"] == "text" else bytes.fromhex(vector["expected"])
    if vector["format"] == 3:
        made = sealed.seal(
            data, text=vector["text"], aad=aad, algorithm=vector["algorithm"],
            now=vector["created"], salt=salt, output=vector["output"], **secret_args(vector),
        )
        assert made == expected
        keys = {"keys": [secret_args(vector)["key"]]} if "key" in vector else {"secret": vector["secret_token"]}
        assert sealed.unseal(expected, aad=aad, **keys) == (data, vector["text"])
    else:
        out = io.BytesIO()
        sealed.seal_stream(
            io.BytesIO(data), out, aad=aad, algorithm=vector["algorithm"], output="bytes",
            chunk_size=vector["chunk_size"], now=vector["created"], salt=salt, **secret_args(vector),
        )
        assert out.getvalue() == expected
        back = io.BytesIO()
        info = sealed.unseal_stream(io.BytesIO(expected), back, keys=[secret_args(vector)["key"]], aad=aad)
        assert back.getvalue() == data and info.text is vector["text"]
    if "key" in vector:
        prk = sealed._extract(salt, bytes.fromhex(vector["key"]))
        assert prk.hex() == vector["prk"] and sealed._mask(prk).hex() == vector["header_mask"]
        alg = _algorithms.by_name(vector["algorithm"])
        if "nonce" in vector:
            nonce = _algorithms.hkdf_expand(prk, alg.info(b" nonce", vector["format"]), 12)
            assert nonce.hex() == vector["nonce"]

"""Property-based tests (hypothesis) for encrypt() and decrypt()."""

import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import yace_codec as yace

KEY = bytes(range(32))
ALGORITHMS = st.sampled_from(["aes-256-gcm", "chacha20-poly1305", "yace-hmac-sha256"])
OUTPUTS = st.sampled_from(["text", "bytes"])
# Any Unicode text, with Devanagari always in the mix.
TEXT = st.one_of(
    st.text(),
    st.text(alphabet=st.characters(min_codepoint=0x0900, max_codepoint=0x097F)),
    st.text(alphabet=st.characters(blacklist_categories=("Cs",))),
)


@settings(max_examples=150, deadline=None)
@given(data=TEXT, algorithm=ALGORITHMS, output=OUTPUTS, aad=st.binary(max_size=64))
def test_text_round_trip(data, algorithm, output, aad):
    token = yace.encrypt(data, key=KEY, algorithm=algorithm, output=output, aad=aad)
    assert yace.decrypt(token, keys=[KEY], aad=aad) == data


@settings(max_examples=150, deadline=None)
@given(data=st.binary(max_size=4096), algorithm=ALGORITHMS, output=OUTPUTS)
def test_bytes_round_trip(data, algorithm, output):
    token = yace.encrypt(data, key=KEY, algorithm=algorithm, output=output)
    result = yace.decrypt(token, keys=[KEY])
    assert result == data and isinstance(result, bytes)


@settings(max_examples=200, deadline=None)
@given(data=st.binary(max_size=200), algorithm=ALGORITHMS, position=st.floats(0, 1, exclude_max=True), bit=st.integers(0, 7))
def test_any_flipped_bit_fails(data, algorithm, position, bit):
    token = bytearray(yace.encrypt(data, key=KEY, algorithm=algorithm, output="bytes"))
    token[int(position * len(token))] ^= 1 << bit
    with pytest.raises(yace.DecodingError):
        yace.decrypt(bytes(token), keys=[KEY])


@settings(max_examples=100, deadline=None)
@given(aad=st.binary(max_size=32), other=st.binary(max_size=32))
def test_different_aad_fails(aad, other):
    token = yace.encrypt(b"row", key=KEY, aad=aad)
    if aad == other:
        assert yace.decrypt(token, keys=[KEY], aad=other) == b"row"
    else:
        with pytest.raises(yace.DecryptionError):
            yace.decrypt(token, keys=[KEY], aad=other)


@pytest.mark.parametrize("algorithm", ["aes-256-gcm", "chacha20-poly1305", "yace-hmac-sha256"])
def test_large_data(algorithm):
    data = os.urandom(4 * 1024 * 1024 + 3)
    token = yace.encrypt(data, key=KEY, algorithm=algorithm, output="bytes")
    assert yace.decrypt(token, keys=[KEY]) == data

"""output="text" (YACE62, the default) and output="bytes" (raw, no expansion)."""



import codecs

import io

import os



import pytest



import yace_codec as yace

from yace_codec import sealed



KEY = bytes(range(32))

BOM_PREFIXES = [b'\xef\xbb\xbf', b'\xff\xfe', b'\xfe\xff', b'\x00\x00\xfe\xff', b'\xff\xfe\x00\x00']




def test_text_is_the_default():

    token = yace.encrypt("x", key=KEY)

    assert isinstance(token, str) and token == token.strip() and token.isalnum()

    assert isinstance(yace.encrypt("x", key=KEY, output="text"), str)





@pytest.mark.parametrize("algorithm", ["aes-256-gcm", "chacha20-poly1305", "yace-hmac-sha256"])

@pytest.mark.parametrize("data", ["", "नमस्ते", b"\x00" * 1000])

def test_bytes_round_trip(algorithm, data):

    token = yace.encrypt(data, key=KEY, output="bytes", algorithm=algorithm)

    assert isinstance(token, bytes)

    assert yace.decrypt(token, keys=[KEY]) == data

    assert yace.decrypt(bytearray(token), keys=[KEY]) == data

    assert yace.decrypt(memoryview(token), keys=[KEY]) == data





def test_bytes_output_has_no_expansion():

    for size in (0, 100, 10_000):

        raw = yace.encrypt(b"x" * size, key=KEY, output="bytes")

        text = yace.encrypt(b"x" * size, key=KEY)

        tag = 16

        assert len(raw) == 16 + 6 + sealed.padme(17 + size) + tag

        assert len(sealed.yace62_decode(text)) == len(raw)

        assert len(text) > len(raw)





def test_text_and_bytes_forms_are_interchangeable():

    raw = yace.encrypt("same", key=KEY, output="bytes")

    assert yace.decrypt(sealed.yace62_encode(raw), keys=[KEY]) == "same"

    text = yace.encrypt("same", key=KEY)

    assert yace.decrypt(sealed.yace62_decode(text), keys=[KEY]) == "same"





def test_text_tokens_given_as_bytes_still_work():

    token = yace.encrypt("as bytes", key=KEY)

    assert yace.decrypt(token.encode("ascii"), keys=[KEY]) == "as bytes"

    assert yace.decrypt(codecs.BOM_UTF8 + token.encode(), keys=[KEY]) == "as bytes"

    assert yace.decrypt(token.encode("utf-16"), keys=[KEY]) == "as bytes"

    assert yace.decrypt((token[:40] + "\r\n" + token[40:]).encode(), keys=[KEY]) == "as bytes"





def test_every_byte_of_a_binary_token_is_authenticated():

    token = yace.encrypt(b"flip", key=KEY, output="bytes")

    for index in range(len(token)):

        for bit in (0, 7):

            changed = bytearray(token)

            changed[index] ^= 1 << bit

            with pytest.raises(yace.DecodingError):

                yace.decrypt(bytes(changed), keys=[KEY])





@pytest.mark.parametrize("bad", ["base64", "", None, 1])

def test_invalid_output_is_rejected(bad):

    with pytest.raises((ValueError, TypeError)):

        yace.encrypt("x", key=KEY, output=bad)





def test_codec_output_bytes(codec):

    token = codec.encrypt("stored key", output="bytes")

    assert isinstance(token, bytes) and codec.decrypt(token) == "stored key"





# --- binary output that starts like a byte order mark ------------------------------------





@pytest.mark.parametrize("bom", BOM_PREFIXES)

def test_binary_tokens_that_start_like_a_bom_still_decrypt(bom):

    salt = (bom + os.urandom(16))[:16]

    token = sealed.seal(b"hello", text=False, key=KEY, salt=salt, output="bytes")

    assert yace.decrypt(token, keys=[KEY]) == b"hello"

    out = io.BytesIO()

    sealed.seal_stream(io.BytesIO(b"stream"), out, key=KEY, salt=salt, output="bytes", chunk_size=64)

    assert yace.decrypt(out.getvalue(), keys=[KEY]) == b"stream"

    back = io.BytesIO()

    yace.decrypt_stream(io.BytesIO(out.getvalue()), back, keys=[KEY])

    assert back.getvalue() == b"stream"





def test_random_salts_never_start_like_a_bom(monkeypatch):

    draws = iter([b"\xff\xfe" + bytes(14), b"\xef\xbb\xbf" + bytes(13), b"\x01" * 16])

    monkeypatch.setattr(sealed.secrets, "token_bytes", lambda n: next(draws))

    token = sealed.seal(b"x", text=False, key=KEY, output="bytes")

    assert token.startswith(b"\x01" * 16)


import codecs
import json
import os
import random
import string

import pytest

import yace_codec as yace
from yace_codec.codec import _bins_inserted, _swap_chunks
from yace_codec.tables import Table

from legacy_reference import original_decode, original_misorder

ALNUM = set(string.ascii_letters + string.digits)

TEXTS = [
    "",
    "a",
    " ",
    "Hello, World!",
    "  spaced  out  ",
    "line one\nline two\r\n\ttabbed\x0b\x0c",
    string.printable * 2,
    "x" * 500,
]


def chunks_after(text_len, length, iterations):
    data_chunks = text_len * length ** (iterations - 1)
    return data_chunks + -(-data_chunks // 4)


@pytest.mark.parametrize("text", TEXTS)
@pytest.mark.parametrize("length", [2, 3, 5, 8])
@pytest.mark.parametrize("iterations", [1, 2, 3])
def test_round_trip(codec, text, length, iterations):
    if len(text) * length**iterations > 100_000:
        pytest.skip("too large for a unit test")
    token = codec.encode(text, "rt", length=length, iterations=iterations)
    assert codec.decode(token) == text


def test_random_round_trips(codec):
    rng = random.Random(1234)
    for _ in range(300):
        text = "".join(rng.choice(string.printable) for _ in range(rng.randrange(0, 120)))
        length, iterations = rng.randint(2, 6), rng.randint(1, 3)
        token = codec.encode(text, "fuzz", length=length, iterations=iterations)
        assert codec.decode(token) == text


def test_token_layout(codec):
    text = "Hello World"
    token = codec.encode(text, "demo", length=3, iterations=2)
    header, body = token.split("\n")
    assert header == "demo-3:2"
    assert set(body) <= ALNUM
    # 11 chars -> 33 chars -> 99 chars = 33 chunks, plus ceil(33 / 4) = 9 bins.
    assert len(body) == 3 * chunks_after(len(text), 3, 2) == 126


def test_defaults(codec):
    token = codec.encode("abc")
    assert yace.parse_header(token) == ("default", 2, 3)
    assert yace.DEFAULT_FAMILY == "default"
    assert (yace.DEFAULT_LENGTH, yace.DEFAULT_ITERATIONS) == (2, 3)


def test_empty_text(codec):
    token = codec.encode("", "empty", length=2, iterations=2)
    assert token == "empty-2:2\n"
    assert codec.decode(token) == ""


def test_tables_are_reused(codec, store):
    first = codec.encode("same tables", "reuse", length=3, iterations=2)
    names = store.table_names()
    second = codec.encode("same tables", "reuse", length=3, iterations=2)
    assert store.table_names() == names == ["reuse-3:1", "reuse-3:2"]
    assert codec.decode(first) == codec.decode(second) == "same tables"


def test_tokens_are_randomised(codec):
    text = "the same text encoded twice gives different tokens " * 3
    tokens = {codec.encode(text, "rand", length=3, iterations=1) for _ in range(5)}
    assert len(tokens) == 5
    assert {codec.decode(t) for t in tokens} == {text}


def test_seeded_rng_is_reproducible():
    def run():
        codec = yace.Codec(yace.KeyStore.in_memory(), rng=random.Random(7))
        return codec.encode("reproducible", "seeded", length=3, iterations=2)

    assert run() == run()


def test_more_layers_extend_a_family(codec, store):
    codec.encode("abc", "grow", length=2, iterations=1)
    before = store.get("grow-2:1")
    token = codec.encode("abc", "grow", length=2, iterations=3)
    assert store.get("grow-2:1") == before
    assert store.table_names() == ["grow-2:1", "grow-2:2", "grow-2:3"]
    assert codec.decode(token) == "abc"


def test_no_shared_codes_in_tokens(codec, store):
    codec.encode("x", "fresh", length=2, iterations=1)
    table = store.get("fresh-2:1")
    assert table.usable_space_codes == table.space_codes
    assert table.usable_bin_codes == table.bin_codes


# --- invalid input ---------------------------------------------------------


@pytest.mark.parametrize("text", ["café", "emoji 😀", "\x00", " "])
def test_unsupported_characters(codec, store, text):
    with pytest.raises(yace.UnsupportedCharacterError) as info:
        codec.encode(text, "uni")
    assert info.value.table_name == "uni-2:1"
    assert set(info.value.characters) == set(text) - yace.SUPPORTED_CHARACTERS
    assert isinstance(info.value, ValueError)
    assert len(store) == 0, "invalid input must not create tables"


def test_unsupported_characters_message_is_capped(codec):
    text = "".join(chr(0x4E00 + i) for i in range(15))
    with pytest.raises(yace.UnsupportedCharacterError, match="and 5 more"):
        codec.encode(text)


@pytest.mark.parametrize("name", ["", "a-b", "a:b", "a1", "two words", "x" * 65, "é", 42, None])
def test_invalid_family_names(codec, name):
    with pytest.raises(yace.InvalidNameError):
        codec.encode("abc", name)


@pytest.mark.parametrize("name", ["a", "jmd", "My_Family", "x" * 64])
def test_valid_family_names(codec, name):
    assert codec.decode(codec.encode("ok", name, length=2, iterations=1)) == "ok"


@pytest.mark.parametrize(
    "length, iterations",
    [(1, 1), (63, 1), (True, 1), (2.0, 1), ("3", 1), (2, 0), (2, 33), (2, True), (2, None)],
)
def test_invalid_settings(codec, store, length, iterations):
    with pytest.raises(yace.EncodingError):
        codec.encode("abc", "bad", length=length, iterations=iterations)
    assert len(store) == 0


def test_output_size_guard(codec, store):
    with pytest.raises(yace.EncodingError, match="exceed"):
        codec.encode("a" * 10, "huge", length=62, iterations=8)
    assert len(store) == 0


@pytest.mark.parametrize("value", [b"bytes", 123, None, ["a"]])
def test_encode_rejects_non_text(codec, value):
    with pytest.raises(TypeError):
        codec.encode(value)


# --- decoding --------------------------------------------------------------


def test_decode_accepts_bytes(codec):
    token = codec.encode("bytes token", "bt", length=3, iterations=1)
    assert codec.decode(token.encode("ascii")) == "bytes token"
    assert codec.decode(bytearray(token, "ascii")) == "bytes token"


def test_decode_tolerates_whitespace(codec):
    token = codec.encode("wrap me", "ws", length=2, iterations=2)
    header, body = token.split("\n")
    wrapped = "\n".join(body[i : i + 10] for i in range(0, len(body), 10))
    variants = [
        f"\n\n  {header}\n{body}\n",
        f"{header}\r\n{body}\r\n",
        f"{header}\n{wrapped}",
        f"{header} {body}",
        f"\t{header}\t\n  {body}  ",
    ]
    for variant in variants:
        assert codec.decode(variant) == "wrap me"


@pytest.mark.parametrize(
    "token",
    ["", "   \n\n", "hello", "abc-2", "abc-x:1", "-2:1", "abc-1:1", "abc-63:1", "abc-2:0", "abc-²:1",
     "abc-99999:1", "a" * 200 + "-2:1"],
)
def test_invalid_headers(codec, token):
    with pytest.raises(yace.DecodingError):
        codec.decode(token)


def test_invalid_body_characters(codec):
    token = codec.encode("abc", "chars", length=2, iterations=1)
    with pytest.raises(yace.DecodingError, match="never produces"):
        codec.decode(token + "!!")


def test_truncated_token(codec):
    token = codec.encode("truncate me", "trunc", length=3, iterations=2)
    with pytest.raises(yace.DecodingError, match="multiple"):
        codec.decode(token[:-1])


def test_corrupted_token(codec):
    token = codec.encode("corrupt me please", "bad", length=3, iterations=1)
    header, body = token.split("\n")
    with pytest.raises(yace.DecodingError, match="not a valid code"):
        codec.decode(f"{header}\n{'zzz' * (len(body) // 3)}")


def test_wrong_tables(codec):
    token = codec.encode("encoded with other tables " * 4, "shared", length=2, iterations=1)
    other = yace.Codec(yace.KeyStore.in_memory())
    other.encode("x", "shared", length=2, iterations=1)  # same name, different random tables
    with pytest.raises(yace.DecodingError):
        other.decode(token)


def test_missing_table(codec):
    with pytest.raises(yace.TableNotFoundError) as info:
        codec.decode("nothere-2:1\nabcd")
    assert info.value.table_name == "nothere-2:1"
    assert isinstance(info.value, LookupError)


@pytest.mark.parametrize("token", [b"bad-2:1\nab\xc3\x28cd", b"\xc3\x28", "x-2:1\nabéd"])
def test_invalid_text_tokens(codec, token):
    with pytest.raises(yace.DecodingError):
        codec.decode(token)


def test_non_ascii_family_names_from_the_original_scripts_parse():
    # The original scripts allowed any family name without digits, '-' or ':'.
    assert yace.parse_header("café-2:1\nabcd".encode("utf-8")).family == "café"


@pytest.mark.parametrize("token", [None, 12, ["x-2:1"]])
def test_decode_rejects_other_types(codec, token):
    with pytest.raises(TypeError):
        codec.decode(token)


def test_parse_header():
    header = yace.parse_header("\n  jmd-3:2\nabcdef")
    assert header == yace.Header("jmd", 3, 2)
    assert header.table_names == ("jmd-3:1", "jmd-3:2")
    assert str(header) == "jmd-3:2"
    # Decoding accepts family names the original scripts allowed, e.g. with punctuation.
    assert yace.parse_header("my.key-2:1\n").family == "my.key"


# --- bytes -----------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, 2, 3, 100, 1000])
def test_bytes_round_trip(codec, size):
    data = os.urandom(size)
    token = codec.encode_bytes(data, "bin", length=3, iterations=1)
    assert codec.decode_bytes(token) == data


def test_unicode_text_via_bytes(codec):
    text = "café ☕ naïve 日本語 😀\ttab"
    token = codec.encode_bytes(text.encode("utf-8"), "utf", length=2, iterations=2)
    assert codec.decode_bytes(token).decode("utf-8") == text


def test_encode_bytes_accepts_bytes_like(codec):
    for data in (bytearray(b"abc"), memoryview(b"abc")):
        assert codec.decode_bytes(codec.encode_bytes(data)) == b"abc"
    with pytest.raises(TypeError):
        codec.encode_bytes("text")


def test_decode_bytes_rejects_text_tokens(codec):
    token = codec.encode("Hello World!", "txt", length=2, iterations=1)
    with pytest.raises(yace.DecodingError, match="base64"):
        codec.decode_bytes(token)


# --- module-level shortcuts and the default key store -------------------------


def test_module_functions_use_default_keystore(default_keystore):
    token = yace.encode("via default store", "mod", length=3, iterations=1)
    assert default_keystore.exists()
    assert yace.decode(token) == "via default store"
    data = yace.encode_bytes(b"\x00\xff", "mod", length=3, iterations=1)
    assert yace.decode_bytes(data) == b"\x00\xff"


def test_module_functions_accept_keystore(tmp_path):
    path = tmp_path / "explicit.json"
    token = yace.encode("explicit", keystore=path)
    assert yace.decode(token, keystore=str(path)) == "explicit"
    assert yace.decode(token, keystore=yace.KeyStore(path)) == "explicit"


def test_codec_rejects_bad_keystore():
    with pytest.raises(TypeError):
        yace.Codec(keystore=42)


# --- algorithm details -------------------------------------------------------


@pytest.mark.parametrize("length", range(2, 8))
def test_swap_chunks_is_an_involution_matching_the_original(length):
    for n in range(0, 120):
        chunks = [f"{i:0{length}d}"[-length:] for i in range(n)]
        data = "".join(chunks).encode("ascii")
        swapped = _swap_chunks(data, length)
        assert _swap_chunks(swapped, length) == data
        assert swapped.decode("ascii") == "".join(original_misorder(chunks, length))


def test_bin_count_is_recoverable_from_token_size():
    images = {}
    for m in range(0, 5000):
        bins = -(-m // 4)
        images[m + bins] = bins
    for total in range(0, max(images) + 1):
        assert _bins_inserted(total) == images.get(total)


# --- compatibility with the original scripts ----------------------------------


@pytest.mark.parametrize("length, iterations", [(2, 1), (2, 3), (3, 2), (4, 1)])
def test_new_tokens_decode_with_original_decoder(codec, store, length, iterations):
    rng = random.Random(length * 10 + iterations)
    alphabet = string.punctuation + string.ascii_letters + string.digits + "\n "
    for _ in range(15):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 25)))
        token = codec.encode(text, "orig", length=length, iterations=iterations)
        tables = {name: store.get(name).to_dict() for name in store.table_names()}
        assert original_decode(token, tables) == text


def test_legacy_tokens_decode(legacy_tables, legacy_vectors):
    store = yace.KeyStore.in_memory()
    store.import_tables(legacy_tables)
    codec = yace.Codec(store)
    for vector in legacy_vectors:
        assert codec.decode(vector["token"]) == vector["text"]


def test_legacy_tokens_include_ones_the_original_decoder_lost(legacy_tables, legacy_vectors):
    lost = [v for v in legacy_vectors if not v["original_decoder_ok"]]
    assert lost, "fixture should cover tokens the original decoder could not decode"
    for vector in lost:
        assert original_decode(vector["token"], legacy_tables) != vector["text"]


def test_legacy_keystore_file_is_usable_directly(tmp_path, legacy_tables, legacy_vectors):
    path = tmp_path / "encodings.json"
    path.write_text(json.dumps(legacy_tables), encoding="utf-8")
    codec = yace.Codec(path)
    vector = legacy_vectors[0]
    assert codec.decode(vector["token"]) == vector["text"]


@pytest.mark.parametrize("family, length, iterations", [("clash", 3, 1), ("clash", 3, 2), ("short", 2, 3)])
def test_new_tokens_with_legacy_tables_avoid_shared_codes(legacy_tables, family, length, iterations):
    store = yace.KeyStore.in_memory()
    store.import_tables(legacy_tables)
    codec = yace.Codec(store)
    text = "Spaces and bins share codes in these tables. " * 3
    for _ in range(30):
        token = codec.encode(text, family, length=length, iterations=iterations)
        assert codec.decode(token) == text
        assert original_decode(token, legacy_tables) == text


def test_legacy_tables_reject_new_characters(legacy_tables):
    store = yace.KeyStore.in_memory()
    store.import_tables(legacy_tables)
    codec = yace.Codec(store)
    with pytest.raises(yace.UnsupportedCharacterError):
        codec.encode("tab\there", "legacy", length=3, iterations=2)
    assert codec.decode_bytes(codec.encode_bytes(b"tab\there", "legacy", length=3, iterations=2)) == b"tab\there"



# --- review regressions -------------------------------------------------------


def test_header_with_space_from_original_scripts(legacy_tables, legacy_vectors):
    store = yace.KeyStore.in_memory()
    store.import_tables(legacy_tables)
    spaced = [v for v in legacy_vectors if v["token"].startswith("big fun-")]
    assert spaced, "fixture should hold tokens whose family name contains a space"
    for vector in spaced:
        assert yace.parse_header(vector["token"]).family == "big fun"
        assert yace.Codec(store).decode(vector["token"]) == vector["text"]


@pytest.mark.parametrize(
    "encode",
    [
        lambda token: "\ufeff" + token,
        lambda token: codecs.BOM_UTF8 + token.encode("ascii"),
        lambda token: token.replace("\n", "\r\n").encode("utf-16"),
        lambda token: codecs.BOM_UTF16_BE + token.encode("utf-16-be"),
        lambda token: token.encode("utf-32"),
    ],
    ids=["str-bom", "utf8-bom", "utf16-le-crlf", "utf16-be", "utf32"],
)
def test_tokens_with_byte_order_marks(codec, encode):
    token = codec.encode("saved by PowerShell", "bom", length=2, iterations=2)
    assert codec.decode(encode(token)) == "saved by PowerShell"


def test_removing_any_bin_chunk_is_detected(codec, store):
    token = codec.encode("detect truncation of the noise " * 3, "trunc", length=2, iterations=1)
    header, body = token.split("\n")
    bins = set(store.get("trunc-2:1").bin_codes)
    chunks = [body[i : i + 2] for i in range(0, len(body), 2)]
    removed = 0
    for i, chunk in enumerate(chunks):
        if chunk in bins:
            damaged = header + "\n" + "".join(chunks[:i] + chunks[i + 1 :])
            with pytest.raises(yace.DecodingError, match="noise chunks"):
                codec.decode(damaged)
            removed += 1
    assert removed


def test_table_without_usable_bins_is_refused():
    data = Table.generate("nobins-2:1", random.Random(3)).to_dict()
    data["bin"] = [data["x"], data[" "][0]]
    store = yace.KeyStore.in_memory()
    store.import_tables({"nobins-2:1": data})
    with pytest.raises(yace.EncodingError, match="bin code"):
        yace.Codec(store).encode("fox", "nobins", length=2, iterations=1)


def test_shared_bins_follow_the_original_decoder_first():
    data = Table.generate("leg-2:1", random.Random(11)).to_dict()
    for ch in "\t\r\x0b\x0c":
        del data[ch]
    data["bin"][0], data["bin"][1] = data["x"], data["y"]
    text = "xabcdefg"
    chunks = [data[ch] for ch in text]
    # Like the original encoder: 8 chunks get 2 bins, here at positions 0 and 2.
    chunks = [data["bin"][0], chunks[0], data["bin"][1]] + chunks[1:]
    body = _swap_chunks("".join(chunks).encode("ascii"), 2).decode("ascii")
    token = "leg-2:1\n" + body
    tables = {"leg-2:1": data}
    assert original_decode(token, tables) == text
    store = yace.KeyStore.in_memory()
    store.import_tables(tables)
    assert yace.Codec(store).decode(token) == text

import random
import string

import pytest

import yace_codec as yace
from yace_codec.tables import (
    BIN_KEY,
    CODE_ALPHABET,
    SPACE_KEY,
    TABLE_CHARACTERS,
    Table,
    parse_table_name,
    table_name,
    validate_family,
)


def make_table(name="demo-3:1", seed=0):
    return Table.generate(name, random.Random(seed))


def test_generated_table_shape():
    table = make_table("demo-3:1")
    assert table.name == "demo-3:1" and table.length == 3
    assert set(table.codes) == set(TABLE_CHARACTERS)
    assert len(table.space_codes) == 10 and len(table.bin_codes) == 26
    assert table.characters == yace.SUPPORTED_CHARACTERS == frozenset(string.printable)
    every = list(table.codes.values()) + list(table.space_codes) + list(table.bin_codes)
    assert len(every) == len(set(every)), "codes must be unique across the whole table"
    for code in every:
        assert len(code) == 3 and set(code) <= set(CODE_ALPHABET)
        assert len(set(code)) == 3, "codes never repeat a character"


@pytest.mark.parametrize("length", [2, 10, 62])
def test_generate_lengths(length):
    table = make_table(f"x-{length}:1")
    assert all(len(code) == length for code in table.codes.values())


@pytest.mark.parametrize("name", ["x-1:1", "x-63:1", "nonsense", "x-2"])
def test_generate_rejects_bad_names(name):
    with pytest.raises(ValueError):
        make_table(name)


def test_dict_round_trip():
    table = make_table()
    data = table.to_dict()
    assert list(data)[-2:] == [SPACE_KEY, BIN_KEY]
    assert Table.from_dict(table.name, data) == table
    assert Table.from_dict(table.name, data) != make_table(seed=1)
    assert repr(table) == "Table(name='demo-3:1', length=3, characters=100)"


def test_tables_are_read_only():
    table = make_table()
    with pytest.raises(AttributeError):
        table.length = 4
    with pytest.raises(TypeError):
        hash(table)


def corrupt(mutator):
    data = make_table().to_dict()
    mutator(data)
    return data


@pytest.mark.parametrize(
    "name, data, message",
    [
        ("demo-3:1", [], "JSON object"),
        ("demo-3:1", corrupt(lambda d: d.pop(SPACE_KEY)), "lists of codes"),
        ("demo-3:1", corrupt(lambda d: d.update({BIN_KEY: "abc"})), "lists of codes"),
        ("demo-3:1", corrupt(lambda d: d.update({"ab": "xyz"})), "single character"),
        ("demo-3:1", corrupt(lambda d: d.update({"a": "xy"})), "is not 3"),
        ("demo-3:1", corrupt(lambda d: d.update({"a": "x!y"})), "is not 3"),
        ("demo-3:1", corrupt(lambda d: d.update({"a": 123})), "is not 3"),
        ("demo-3:1", corrupt(lambda d: d.update({"a": d["b"]})), "share the same code"),
        ("demo-3:1", corrupt(lambda d: d.pop("Q")), "no code for 'Q'"),
        ("demo-3:1", corrupt(lambda d: d[SPACE_KEY].append("toolong")), "is not 3"),
        ("demo-1:1", {}, "code length"),
        ("bad name", {}, "invalid table name"),
        (42, {}, "invalid table name"),
    ],
)
def test_from_dict_validation(name, data, message):
    with pytest.raises(yace.KeyStoreError, match=message):
        Table.from_dict(name, data)


def test_legacy_tables_without_new_characters_are_valid():
    data = make_table().to_dict()
    for ch in "\t\r\x0b\x0c":
        del data[ch]
    table = Table.from_dict("demo-3:1", data)
    assert "\t" not in table.characters and "a" in table.characters


def shared_code_table():
    """A legacy-style table: a space code doubles as a bin code and a bin code as 'x'."""
    data = make_table("old-3:1").to_dict()
    data[BIN_KEY][0] = data[SPACE_KEY][0]
    data[BIN_KEY][1] = data["x"]
    return Table.from_dict("old-3:1", data)


def test_shared_codes_are_never_emitted():
    table = shared_code_table()
    assert table.space_codes[0] not in table.usable_space_codes
    assert table.space_codes[0] not in table.usable_bin_codes
    assert table.codes["x"] not in table.usable_bin_codes
    assert len(table.usable_space_codes) == 9 and len(table.usable_bin_codes) == 24


def test_reverse_map_priorities():
    table = shared_code_table()
    plain_outer = table.reverse_map(plaintext=True, outermost=True)
    assert plain_outer[table.codes["x"]] == "x"  # characters beat bins
    assert plain_outer[table.space_codes[0]] == " "  # spaces beat bins
    assert plain_outer[table.bin_codes[5]] is None
    inner = table.reverse_map(plaintext=False, outermost=True)
    # Inner layers only decode to letters and digits; spaces cannot occur there.
    assert inner[table.space_codes[0]] is None
    assert table.codes["!"] not in inner and inner[table.codes["x"]] == "x"
    middle = table.reverse_map(plaintext=False, outermost=False)
    assert table.bin_codes[5] not in middle


def test_round_trip_with_shared_code_table():
    store = yace.KeyStore.in_memory()
    store.import_tables({"old-3:1": shared_code_table().to_dict()})
    codec = yace.Codec(store)
    text = "x marks the spot, xx and xxx and many spaces   between words " * 2
    for _ in range(50):
        assert codec.decode(codec.encode(text, "old", length=3, iterations=1)) == text


def test_table_names():
    assert table_name("jmd", 3, 2) == "jmd-3:2"
    assert parse_table_name("jmd-3:2") == ("jmd", 3, 2)
    assert parse_table_name("a-b-3:2") == ("a-b", 3, 2)
    for bad in ["jmd", "jmd-3", "jmd-:2", "-3:2", "jmd-3:", "jmd-x:2", "jmd-3:²", "jmd-12345:1"]:
        assert parse_table_name(bad) is None


def test_validate_family():
    assert validate_family("Abc_def") == "Abc_def"
    for bad in ["", "a1", "a-b", "a:b", "a b", "ü", "x" * 65, None]:
        with pytest.raises(yace.InvalidNameError):
            validate_family(bad)



@pytest.mark.parametrize("name", ["evil\x1b[2J-2:1", "tab\there-2:1", "line\nbreak-2:1", "x" * 130 + "-2:1"])
def test_unprintable_or_long_names_are_rejected(name):
    assert parse_table_name(name) is None
    with pytest.raises(yace.KeyStoreError, match="invalid table name"):
        Table.from_dict(name, make_table().to_dict())


def test_names_with_spaces_are_accepted_for_legacy_tables():
    assert parse_table_name("big fun-2:1") == ("big fun", 2, 1)
    assert Table.from_dict("big fun-3:1", make_table().to_dict()).name == "big fun-3:1"


def test_constructor_validates():
    with pytest.raises(yace.KeyStoreError, match="no code for"):
        Table("x-2:1", 2, {}, [], [])
    with pytest.raises(yace.KeyStoreError, match="does not match"):
        Table("x-2:1", 3, make_table("x-3:1").codes, [], [])
    data = make_table().to_dict()
    codes = {k: v for k, v in data.items() if k not in (SPACE_KEY, BIN_KEY)}
    with pytest.raises(yace.KeyStoreError, match="list of space codes"):
        Table("demo-3:1", 3, {**codes, " ": data[SPACE_KEY][0]}, [], [])


def test_codes_mapping_is_read_only():
    table = make_table()
    with pytest.raises(TypeError):
        table.codes["a"] = "ZZZ"


def test_space_and_bin_lists_are_capped():
    data = make_table().to_dict()
    data[BIN_KEY] = data[BIN_KEY] * 50  # 1300 codes
    with pytest.raises(yace.KeyStoreError, match="more than 1000"):
        Table.from_dict("demo-3:1", data)


@pytest.mark.parametrize("key", ["\x1b", "\x07", "\x9b", "\ud800", "\x00"])
def test_unprintable_keys_are_rejected(key):
    data = make_table().to_dict()
    data[key] = "Zq9"
    with pytest.raises(yace.KeyStoreError, match="not a printable character"):
        Table.from_dict("demo-3:1", data)

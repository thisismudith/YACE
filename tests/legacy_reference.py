"""The original YACE decoder as a pure function, used as a test oracle.

This is ``Decoder.decode_string`` from ``encoder/decoder.py`` at commit 01d44a2
(the last version before packaging). Only the ``encodings.json`` access and the
``print``/``exit()`` calls were replaced, so the tests can check that tokens
from the package still decode with the original algorithm.
"""


def separate_string(string, number):
    return [str(string)[i : i + number] for i in range(0, len(str(string)), number)]


def original_decode(data, hash_info, hash_name=None):
    ignore_bins, ignore_spaces = False, False
    i = 0
    while i <= 10:  # Fetching the hash key in data until 10 iterations
        if hash_name is None or hash_name not in hash_info.keys():
            hash_name = data.split("\n")[i]
        if hash_name not in ["", " ", "\n"]:
            break
        i += 1
    else:
        raise ValueError("There is no hash key!")
    if hash_info == {}:
        raise ValueError("There is no hash key!")
    if hash_name not in hash_info.keys():
        raise KeyError(hash_name)
    if "bin" not in hash_info[hash_name]:
        ignore_bins = True
    else:
        bins = hash_info[hash_name]["bin"]
    if " " not in hash_info[hash_name].keys():
        ignore_spaces = True
    hash_length = int("".join(hash_name.split("-")[-1]).split(":")[0])
    hash_iteration = int(hash_name.split(":")[-1])
    hashed_data = separate_string("".join(data.split("\n")[i + 1 :]), hash_length)
    original_data = separate_string("".join(hashed_data), hash_length)
    for x in range(0, len(hashed_data), hash_length):  # Reordering the data
        if x > 0:
            original_data[x - 1] = hashed_data[-x]
            original_data[-x] = hashed_data[x - 1]
    for bin in bins:
        if bin in original_data:
            original_data.remove(bin)  # Removing Bins
    for hash_iteration in range(hash_iteration, 0, -1):
        if hash_name in hash_info.keys():
            hash_name = f"{hash_name.split('-')[0]}-{hash_length}:{hash_iteration}"
            hashing_alg = hash_info[hash_name]
            for key, value in hashing_alg.items():
                if type(value) == list:  # If it is space or bin
                    for v in value:
                        while v in original_data:
                            if key != "bin" and not ignore_spaces:  # If space
                                original_data[original_data.index(v)] = key
                            elif key == "bin" and not ignore_bins:  # If bin
                                original_data.remove(v)
                            else:
                                break
                else:
                    while value in original_data:  # Normal Replacing unless over
                        original_data[original_data.index(value)] = key
            original_data = separate_string("".join(original_data), hash_length)
    return "".join(original_data)


def original_misorder(chunks, step):
    """The "Misordering the data" loop of the original ``Encoder.encoding_loop``."""
    final_data = list(chunks)
    for x in range(0, len(chunks), step):
        if x > 0:
            final_data[x - 1] = chunks[-x]
            final_data[-x] = chunks[x - 1]
    return final_data

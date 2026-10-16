"""Encryption throughput in MB/s for each algorithm (not a CI gate).

    python benchmarks/bench.py [--size MB]

"message" is encrypt()/decrypt() with output="bytes"; "stream" is
encrypt_stream()/decrypt_stream() with output="bytes" (constant memory);
"text" is encrypt() with the default YACE62 text output, whose pure-Python
encoding limits the speed of every algorithm.
"""

from __future__ import annotations

import argparse
import io
import os
import platform
import time
from typing import Callable

import yace_codec as yace

KEY = yace.generate_key()


class Sink(io.RawIOBase):
    def writable(self) -> bool:
        return True

    def write(self, data) -> int:  # type: ignore[no-untyped-def]
        return len(data)


def rate(size: int, work: Callable[[], object], repeat: int = 3) -> float:
    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        work()
        best = min(best, time.perf_counter() - start)
    return size / best / 1e6


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--size", type=int, default=32, help="megabytes per run (default: 32)")
    args = parser.parse_args()
    size = args.size * 1_000_000
    data = os.urandom(size)
    text_size = min(size, 4_000_000)
    print(f"yace-codec {yace.__version__}, Python {platform.python_version()}, {platform.machine()}")
    print(f"{'algorithm':<20}{'operation':<22}{'MB/s':>10}")
    for info in yace.algorithms():
        alg = info.name
        token = yace.encrypt(data, key=KEY, algorithm=alg, output="bytes")
        stream = io.BytesIO()
        yace.encrypt_stream(io.BytesIO(data), stream, key=KEY, algorithm=alg, output="bytes")
        rows = [
            ("message encrypt", size, lambda: yace.encrypt(data, key=KEY, algorithm=alg, output="bytes")),
            ("message decrypt", size, lambda: yace.decrypt(token, keys=[KEY])),
            ("stream encrypt", size, lambda: yace.encrypt_stream(
                io.BytesIO(data), Sink(), key=KEY, algorithm=alg, output="bytes")),
            ("stream decrypt", size, lambda: yace.decrypt_stream(
                io.BytesIO(stream.getvalue()), Sink(), keys=[KEY])),
            ("text encrypt", text_size, lambda: yace.encrypt(data[:text_size], key=KEY, algorithm=alg)),
        ]
        for name, amount, work in rows:
            print(f"{alg:<20}{name:<22}{rate(amount, work):>10.1f}", flush=True)


if __name__ == "__main__":
    main()

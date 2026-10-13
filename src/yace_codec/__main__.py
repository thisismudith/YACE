"""Allow ``python -m yace_codec``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())

"""Share one table family so someone else can decode your tokens.

Alice and Bob each have their own key store file. Alice exports the "team"
family, Bob imports it, and Bob can then decode Alice's tokens.

Run with:  python examples/share_tables.py
"""

import json
import tempfile
from pathlib import Path

import yace_codec as yace

with tempfile.TemporaryDirectory() as workdir:
    work = Path(workdir)
    alice = yace.Codec(work / "alice.json")
    bob = yace.Codec(work / "bob.json")

    token = alice.encode("The build is green, ship it.", "team", length=3, iterations=1)

    # Alice exports only the "team" tables; her other families stay private.
    export_file = work / "team-tables.json"
    export_file.write_text(json.dumps(alice.keystore.export_family("team")), encoding="utf-8")

    # Bob imports only the family he expects, so a file cannot slip in tables for
    # families he uses (CLI equivalent:
    # yace-codec tables import team-tables.json --family team).
    tables = json.loads(export_file.read_text(encoding="utf-8"))
    result = bob.keystore.import_tables(tables, family="team")
    print("Bob imported:", ", ".join(result.added))
    print("Bob decodes:", bob.decode(token))

    assert bob.decode(token) == alice.decode(token)

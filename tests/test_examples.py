import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import yace_codec as yace

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = sorted((ROOT / "examples").glob("*.py"))
README = ROOT / "README.md"


@pytest.mark.parametrize("script", EXAMPLES, ids=lambda p: p.name)
def test_example_runs(script, tmp_path):
    env = {**os.environ, yace.ENV_VAR: str(tmp_path / "keystore.json")}
    proc = subprocess.run(
        [sys.executable, str(script)], cwd=tmp_path, env=env, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr


def readme_python_blocks():
    if not README.exists():
        return []
    return re.findall(r"```python\n(.*?)```", README.read_text(encoding="utf-8"), re.S)


@pytest.mark.skipif(not README.exists(), reason="README.md not available")
def test_readme_python_examples_run(tmp_path, monkeypatch):
    blocks = readme_python_blocks()
    assert blocks, "README.md should contain python examples"
    monkeypatch.chdir(tmp_path)
    namespace = {"__name__": "__readme__"}
    for block in blocks:  # blocks share one namespace, like a reader following along
        exec(compile(block, "README.md", "exec"), namespace)

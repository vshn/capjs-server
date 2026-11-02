"""The package version has one source: pyproject.toml.

__version__ said 0.2.0 while pyproject.toml said 0.2.1, and only v0.2.0
was ever tagged. The publish job checks the tag against pyproject.toml;
this checks __version__ against it.
"""

import re
from pathlib import Path

import capjs_server

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _pyproject_version() -> str:
    # tomllib is 3.11+, and the package supports 3.10.
    match = re.search(r'^version = "([^"]+)"$', PYPROJECT.read_text(), re.M)
    assert match, "no version in pyproject.toml"
    return match.group(1)


def test_dunder_version_matches_pyproject():
    assert capjs_server.__version__ == _pyproject_version()

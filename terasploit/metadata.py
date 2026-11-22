import tomllib
from pathlib import Path


# Read the version from pyproject.toml file.
# This makes the framework dependent to the pyproject.toml, so never delete pyproject.toml.
# Treat `pyproject.toml` as part of the terasploit. We use it as a single source of truth.

pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"

with open(pyproject_path, "rb") as f:
    pyproject_data = tomllib.load(f)

# Framework version
VERSION = pyproject_data.get("project", {}).get("version")

# Framework license
LICENSE = "BSD-3-Clause"

# Framework author
AUTHOR = "0x4steroth"

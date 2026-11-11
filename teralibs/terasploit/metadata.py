import os
import tomllib  # Use 'toml_w' or 'toml' for writing, tomllib is read-only


# Read the version from pyproject.toml file.
# This makes the framework dependent to the pyproject.toml, so never delete pyproject.toml.
# Treat `pyproject.toml` as part of the framework. We use it as a single source of truth.

pyproject_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "pyproject.toml")

with open(pyproject_path, "rb") as f:
    pyproject_data = tomllib.load(f)

# Framework version
VERSION = pyproject_data.get("project", {}).get("version")

# Framework license
LICENSE = "BSD-3-Clause"

# Framework author
AUTHOR = "0x4steroth"

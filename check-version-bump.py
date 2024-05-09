from packaging.version import Version
import requests
import tomllib
import sys

PYPI_URL = "https://pypi.org/pypi/microperf/json"
CRATES_IO_URL = "https://crates.io/api/v1/crates/microperf"

latest_pypi = requests.get(PYPI_URL).json()["info"]["version"]
latest_crates_io = requests.get(CRATES_IO_URL).json()["crate"]["newest_version"]

status = 0

current_versions = []
with open("pyproject.toml", "rb") as f:
    current_versions.append(tomllib.load(f)["project"]["version"])
with open("Cargo.toml", "rb") as f:
    current_versions.append(tomllib.load(f)["package"]["version"])

if len({Version(v) for v in current_versions}) != 1:
    print("Multiple versions found. Please harmonize version numbers.")
    status = 1

current = current_versions[0]

if Version(current) <= Version(latest_pypi):
    print(f"Latest version is {latest_pypi} on PyPI. Please bump versions.")
    status = 1

if Version(current) <= Version(latest_crates_io):
    print(f"Latest version is {latest_crates_io} on crates.io. Please bump versions.")
    status = 1

sys.exit(status)

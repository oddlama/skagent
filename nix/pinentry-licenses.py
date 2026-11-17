"""Fails if skagent-pinentry links a crate that isn't permissively licensed.

GPUI comes from Zed's repository, where Apache-2.0, GPL-3.0 and AGPL-3.0
crates sit side by side, so a GPUI update could pull a copyleft crate into
the popup. Reads `cargo metadata` on stdin and checks every package reachable
from the root through normal and build dependencies (not dev-dependencies:
they never reach the binary).
"""

import json
import re
import sys

# Licenses a crate linked into the MIT-licensed popup may carry. MPL-2.0 is
# file-level copyleft: the crate's own source stays available on crates.io.
PERMISSIVE = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "ISC",
    "MIT",
    "MPL-2.0",
    "Unicode-3.0",
    "Unlicense",
    "Zlib",
}


def permitted(expression: str) -> bool:
    """Whether an SPDX expression can be satisfied with permissive licenses
    only. The old `/` separator means OR; `WITH` exceptions only add rights."""
    tokens = re.findall(r"\(|\)|[^\s()]+", expression.replace("/", " OR "))
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        token = peek()
        if token is None:
            raise ValueError(f"unexpected end of {expression!r}")
        position += 1
        return token

    def leaf() -> bool:
        token = take()
        if token == "(":
            value = either()
            if take() != ")":
                raise ValueError(f"unbalanced {expression!r}")
            return value
        if peek() == "WITH":
            take()
            take()
        return token in PERMISSIVE

    def both() -> bool:
        value = leaf()
        while peek() == "AND":
            take()
            value = leaf() and value
        return value

    def either() -> bool:
        value = both()
        while peek() == "OR":
            take()
            value = both() or value
        return value

    value = either()
    if peek() is not None:
        raise ValueError(f"trailing {peek()!r} in {expression!r}")
    return value


def main() -> int:
    metadata = json.load(sys.stdin)
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    reachable: set[str] = set()
    pending = [metadata["resolve"]["root"]]
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        for dependency in nodes[current]["deps"]:
            kinds = {kind["kind"] for kind in dependency["dep_kinds"]}
            if kinds & {None, "build"}:
                pending.append(dependency["pkg"])

    refused = []
    for package_id in sorted(reachable):
        package = packages[package_id]
        license_expression = package.get("license")
        try:
            allowed = license_expression is not None and permitted(license_expression)
        except ValueError as error:
            allowed = False
            license_expression = f"{license_expression} ({error})"
        if not allowed:
            refused.append(f"{package['name']} {package['version']}: {license_expression}")
    if refused:
        print("crates that aren't permissively licensed:", file=sys.stderr)
        for line in refused:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"{len(reachable)} crates, all permissively licensed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

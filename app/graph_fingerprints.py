"""Deterministic SHA-256 fingerprints over a resolved dependency graph.

Consumes the ``resolved`` mapping and ``dependency_graph`` edges emitted by a
successful ``/resolve`` call and computes a content fingerprint for ``<root>``
and for every resolved package.

Definitions
-----------
The fingerprint of a node hashes a canonical serialization of the *complete
dependency closure* reachable from that node: every node in the closure
contributes its canonical package name and normalized PEP 440 version, and
every deduplicated directed edge between closure members is recorded.  Because
the closure is a set rather than a traversal order, nodes inside cycles and
diamonds are counted exactly once, and neither the order of the ``resolved``
mapping nor the order (or duplication) of the input edges influences the
result.  Changing a version or an edge anywhere inside a closure changes
exactly the fingerprints of the nodes that can reach it; packages unreachable
from ``<root>`` still receive a fingerprint of their own closure and are
listed separately.

Canonical serialization
-----------------------
A closure is rendered as canonical JSON (object keys sorted, compact
separators, ASCII) of::

    {
        "nodes": [[name, version], ...],                          # sorted
        "edges": [[source, source_version, target, target_version], ...],
    }

and hashed with SHA-256 (hex digest).  All names are canonical
(``canonicalize_name``) and all versions normalized (``str(Version(...))``),
so equivalent spellings of the same graph always produce the same digest.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from packaging.version import Version

from .audit import parse_graph, parse_resolved
from .resolver import ROOT


def _closure(adjacency: dict[str, list[str]], start: str) -> set[str]:
    """Every node reachable from ``start`` (``start`` included).

    Iterative, so adversarially deep dependency chains cannot exhaust the
    Python call stack; membership (not visit order) is what gets hashed.
    """
    seen = {start}
    stack = [start]
    while stack:
        node = stack.pop()
        for nxt in adjacency.get(node, ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def _version_of(node: str, resolved: dict[str, Version]) -> str:
    return "" if node == ROOT else str(resolved[node])


def _fingerprint(
    closure: set[str],
    adjacency: dict[str, list[str]],
    resolved: dict[str, Version],
) -> str:
    """SHA-256 over the canonical serialization of one closure."""
    nodes = sorted((name, _version_of(name, resolved)) for name in closure)
    edges = sorted(
        (
            source,
            _version_of(source, resolved),
            target,
            _version_of(target, resolved),
        )
        for source in closure
        for target in adjacency.get(source, ())
        if target in closure
    )
    canonical = json.dumps(
        {"nodes": nodes, "edges": edges},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def run_graph_fingerprints(
    resolved_raw: dict[str, str],
    edges_raw: Iterable[Any],
) -> dict[str, Any]:
    """Fingerprint ``<root>`` and every resolved package (see module docstring)."""
    resolved = parse_resolved(resolved_raw)
    adjacency = parse_graph(edges_raw, resolved)

    root_closure = _closure(adjacency, ROOT)
    root_fingerprint = _fingerprint(root_closure, adjacency, resolved)

    packages: list[dict[str, Any]] = []
    for name in sorted(resolved):
        closure = _closure(adjacency, name)
        packages.append(
            {
                "package": name,
                "version": str(resolved[name]),
                "fingerprint": _fingerprint(closure, adjacency, resolved),
            }
        )

    unreachable = sorted(set(resolved) - root_closure)

    return {
        "status": "ok",
        "algorithm": "sha256",
        "summary": {
            "packages": len(resolved),
            "reachable": len(root_closure) - 1,  # exclude <root> itself
            "unreachable": len(unreachable),
        },
        "root": {"name": ROOT, "fingerprint": root_fingerprint},
        "packages": packages,
        "unreachable": [
            {"package": name, "version": str(resolved[name])} for name in unreachable
        ],
    }

"""End-to-end tests for POST /audit/graph-fingerprints."""

import hashlib
import random

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _fingerprints(**payload):
    response = client.post("/audit/graph-fingerprints", json=payload)
    return response.status_code, response.json()


def _edge(source, source_version, target, target_version):
    return {
        "source": source,
        "source_version": source_version,
        "target": target,
        "target_version": target_version,
    }


def _sha256(text):
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _by_package(entries):
    return {entry["package"]: entry for entry in entries}


CHAIN_RESOLVED = {"a": "1.0", "b": "2.0", "c": "3.0"}
CHAIN_GRAPH = [
    _edge("<root>", "", "a", "1.0"),
    _edge("a", "1.0", "b", "2.0"),
    _edge("b", "2.0", "c", "3.0"),
]


# ---------------------------------------------------------------------------
# Canonical form and response shape
# ---------------------------------------------------------------------------


def test_fingerprints_match_the_documented_canonical_form():
    status, body = _fingerprints(
        resolved={"a": "1.0", "b": "2.0"},
        dependency_graph=[
            _edge("<root>", "", "a", "1.0"),
            _edge("a", "1.0", "b", "2.0"),
        ],
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["algorithm"] == "sha256"
    assert body["summary"] == {"packages": 2, "reachable": 2, "unreachable": 0}
    assert body["unreachable"] == []

    packages = _by_package(body["packages"])
    assert [entry["package"] for entry in body["packages"]] == ["a", "b"]
    # b's closure is just itself: no outgoing edges.
    assert packages["b"]["fingerprint"] == _sha256(
        '{"edges":[],"nodes":[["b","2.0"]]}'
    )
    # a's closure is a -> b.
    assert packages["a"]["fingerprint"] == _sha256(
        '{"edges":[["a","1.0","b","2.0"]],"nodes":[["a","1.0"],["b","2.0"]]}'
    )
    # The root closure adds the <root> node and its edge.
    assert body["root"] == {
        "name": "<root>",
        "fingerprint": _sha256(
            '{"edges":[["<root>","","a","1.0"],["a","1.0","b","2.0"]],'
            '"nodes":[["<root>",""],["a","1.0"],["b","2.0"]]}'
        ),
    }


def test_empty_input_gives_the_empty_root_closure():
    status, body = _fingerprints(resolved={}, dependency_graph=[])
    assert status == 200
    assert body == {
        "status": "ok",
        "algorithm": "sha256",
        "summary": {"packages": 0, "reachable": 0, "unreachable": 0},
        "root": {
            "name": "<root>",
            "fingerprint": _sha256('{"edges":[],"nodes":[["<root>",""]]}'),
        },
        "packages": [],
        "unreachable": [],
    }


def test_every_package_gets_a_distinct_fingerprint_along_a_chain():
    status, body = _fingerprints(resolved=CHAIN_RESOLVED, dependency_graph=CHAIN_GRAPH)
    assert status == 200
    digests = [entry["fingerprint"] for entry in body["packages"]]
    digests.append(body["root"]["fingerprint"])
    # Closures along a chain differ, so all fingerprints differ.
    assert len(set(digests)) == 4
    for digest in digests:
        assert len(digest) == 64
        int(digest, 16)  # hex


# ---------------------------------------------------------------------------
# Determinism, normalization, cycles and diamonds
# ---------------------------------------------------------------------------


def test_deterministic_and_independent_of_input_order():
    payload = {"resolved": CHAIN_RESOLVED, "dependency_graph": CHAIN_GRAPH}
    baseline = client.post("/audit/graph-fingerprints", json=payload).json()
    assert all(
        client.post("/audit/graph-fingerprints", json=payload).json() == baseline
        for _ in range(5)
    )

    shuffled = CHAIN_GRAPH[:]
    random.Random(7).shuffle(shuffled)
    reordered = {
        # Mapping insertion order and edge order/duplication must not matter.
        "resolved": dict(reversed(list(CHAIN_RESOLVED.items()))),
        "dependency_graph": shuffled + shuffled[:2],
    }
    assert client.post("/audit/graph-fingerprints", json=reordered).json() == baseline


def test_names_and_versions_are_normalized_before_hashing():
    plain = client.post(
        "/audit/graph-fingerprints",
        json={
            "resolved": {"foo-bar": "1.0"},
            "dependency_graph": [_edge("<root>", "", "foo-bar", "1.0")],
        },
    ).json()
    spelled = client.post(
        "/audit/graph-fingerprints",
        json={
            # Foo_Bar/FOO.bar canonicalize to foo-bar; 01.0 normalizes to 1.0.
            "resolved": {"Foo_Bar": "01.0"},
            "dependency_graph": [_edge("<root>", "", "FOO.bar", "01.0")],
        },
    ).json()
    assert spelled == plain


def test_cycle_members_share_one_fingerprint_and_count_once():
    status, body = _fingerprints(
        resolved={"a": "1.0", "b": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "a", "1.0"),
            _edge("a", "1.0", "b", "1.0"),
            _edge("b", "1.0", "a", "1.0"),
        ],
    )
    assert status == 200
    packages = _by_package(body["packages"])
    # Both cycle members close over the same two-node, two-edge graph, so
    # their fingerprints coincide and each node appears exactly once.
    expected = _sha256(
        '{"edges":[["a","1.0","b","1.0"],["b","1.0","a","1.0"]],'
        '"nodes":[["a","1.0"],["b","1.0"]]}'
    )
    assert packages["a"]["fingerprint"] == expected
    assert packages["b"]["fingerprint"] == expected
    # The root closure additionally contains <root> and its edge.
    assert body["root"]["fingerprint"] != expected


def test_diamond_counts_the_shared_node_once():
    status, body = _fingerprints(
        resolved={"app": "1.0", "left": "1.0", "right": "1.0", "shared": "1.5"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("app", "1.0", "left", "1.0"),
            _edge("app", "1.0", "right", "1.0"),
            _edge("left", "1.0", "shared", "1.5"),
            _edge("right", "1.0", "shared", "1.5"),
        ],
    )
    assert status == 200
    packages = _by_package(body["packages"])
    # app's closure lists shared exactly once despite the two converging paths.
    assert packages["app"]["fingerprint"] == _sha256(
        '{"edges":['
        '["app","1.0","left","1.0"],["app","1.0","right","1.0"],'
        '["left","1.0","shared","1.5"],["right","1.0","shared","1.5"]'
        '],"nodes":[["app","1.0"],["left","1.0"],["right","1.0"],["shared","1.5"]]}'
    )
    # shared's own closure is just itself.
    assert packages["shared"]["fingerprint"] == _sha256(
        '{"edges":[],"nodes":[["shared","1.5"]]}'
    )


# ---------------------------------------------------------------------------
# Sensitivity: closure-internal changes move exactly the reaching fingerprints
# ---------------------------------------------------------------------------


def _bump_lib_payload(graph_edges):
    return {
        "resolved": {"app": "1.0", "lib": "1.1", "tool": "5.0"},
        "dependency_graph": graph_edges,
    }


def test_version_change_inside_closure_changes_only_reaching_fingerprints():
    base = client.post(
        "/audit/graph-fingerprints",
        json={
            "resolved": {"app": "1.0", "lib": "1.0", "tool": "5.0"},
            "dependency_graph": [
                _edge("<root>", "", "app", "1.0"),
                _edge("app", "1.0", "lib", "1.0"),
            ],
        },
    ).json()
    bumped = client.post(
        "/audit/graph-fingerprints",
        json=_bump_lib_payload(
            [
                _edge("<root>", "", "app", "1.0"),
                _edge("app", "1.0", "lib", "1.1"),
            ]
        ),
    ).json()

    base_packages = _by_package(base["packages"])
    bumped_packages = _by_package(bumped["packages"])
    # lib's own version changed.
    assert bumped_packages["lib"]["fingerprint"] != base_packages["lib"]["fingerprint"]
    # app reaches lib, so its closure (and the root's) changed too.
    assert bumped_packages["app"]["fingerprint"] != base_packages["app"]["fingerprint"]
    assert bumped["root"]["fingerprint"] != base["root"]["fingerprint"]
    # tool is unreachable from <root> and shares no closure with lib.
    assert bumped_packages["tool"]["fingerprint"] == base_packages["tool"]["fingerprint"]


def test_edge_change_inside_closure_changes_fingerprints():
    resolved = {"a": "1.0", "b": "1.0", "c": "1.0"}
    with_edge = client.post(
        "/audit/graph-fingerprints",
        json={
            "resolved": resolved,
            "dependency_graph": [
                _edge("<root>", "", "a", "1.0"),
                _edge("a", "1.0", "b", "1.0"),
                _edge("a", "1.0", "c", "1.0"),
            ],
        },
    ).json()
    without_edge = client.post(
        "/audit/graph-fingerprints",
        json={
            "resolved": resolved,
            "dependency_graph": [
                _edge("<root>", "", "a", "1.0"),
                _edge("a", "1.0", "b", "1.0"),
            ],
        },
    ).json()

    with_packages = _by_package(with_edge["packages"])
    without_packages = _by_package(without_edge["packages"])
    # a loses c from its closure; the root closure shrinks likewise.
    assert without_packages["a"]["fingerprint"] != with_packages["a"]["fingerprint"]
    assert without_edge["root"]["fingerprint"] != with_edge["root"]["fingerprint"]
    # c's own closure is just itself in both cases.
    assert without_packages["c"]["fingerprint"] == with_packages["c"]["fingerprint"]
    # ...and c is now unreachable from <root>.
    assert without_edge["unreachable"] == [{"package": "c", "version": "1.0"}]


# ---------------------------------------------------------------------------
# Unreachable packages
# ---------------------------------------------------------------------------


def test_unreachable_packages_are_fingerprinted_and_listed():
    status, body = _fingerprints(
        resolved={"app": "1.0", "ghost": "2.0", "zombie": "3.0"},
        dependency_graph=[_edge("<root>", "", "app", "1.0")],
    )
    assert status == 200
    assert body["summary"] == {"packages": 3, "reachable": 1, "unreachable": 2}
    assert body["unreachable"] == [
        {"package": "ghost", "version": "2.0"},
        {"package": "zombie", "version": "3.0"},
    ]
    packages = _by_package(body["packages"])
    assert set(packages) == {"app", "ghost", "zombie"}
    # An isolated package's closure is itself alone.
    assert packages["ghost"]["fingerprint"] == _sha256(
        '{"edges":[],"nodes":[["ghost","2.0"]]}'
    )


def test_edges_between_unreachable_packages_stay_out_of_the_root_closure():
    status, body = _fingerprints(
        resolved={"app": "1.0", "u1": "1.0", "u2": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("u1", "1.0", "u2", "1.0"),
        ],
    )
    assert status == 200
    assert body["summary"]["reachable"] == 1
    assert [entry["package"] for entry in body["unreachable"]] == ["u1", "u2"]
    # u1's own closure still records its edge to u2.
    packages = _by_package(body["packages"])
    assert packages["u1"]["fingerprint"] == _sha256(
        '{"edges":[["u1","1.0","u2","1.0"]],"nodes":[["u1","1.0"],["u2","1.0"]]}'
    )


# ---------------------------------------------------------------------------
# Roundtrip from /resolve
# ---------------------------------------------------------------------------


def test_roundtrip_from_resolve_response():
    resolve_body = client.post(
        "/resolve",
        json={
            "packages": {
                "app": {"1.0": {"dependencies": {"web": ">=2.0", "db": ""}}},
                "web": {
                    "2.0": {"dependencies": {"common": "<2.0"}},
                    "3.0": {"dependencies": {"common": ">=2.0"}},
                },
                "db": {"1.0": {"dependencies": {"common": "==1.5"}}},
                "common": {"1.5": {}, "2.0": {}},
            },
            "root": {"app": ""},
        },
    ).json()
    assert resolve_body["status"] == "ok"

    status, body = _fingerprints(
        resolved=resolve_body["resolved"],
        dependency_graph=resolve_body["dependency_graph"],
    )
    assert status == 200
    assert [entry["package"] for entry in body["packages"]] == sorted(
        resolve_body["resolved"]
    )
    assert body["unreachable"] == []
    for entry in body["packages"]:
        assert entry["version"] == resolve_body["resolved"][entry["package"]]
        assert len(entry["fingerprint"]) == 64
        int(entry["fingerprint"], 16)


# ---------------------------------------------------------------------------
# 400s (shared graph validation)
# ---------------------------------------------------------------------------


def test_dangling_target_returns_400():
    status, body = _fingerprints(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "", "ghost", "1.0")],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "dangling" in body["error"]["message"]


def test_dangling_source_returns_400():
    status, body = _fingerprints(
        resolved={"app": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("ghost", "1.0", "app", "1.0"),
        ],
    )
    assert status == 400
    assert "dangling" in body["error"]["message"]


def test_edge_version_inconsistent_with_resolved_returns_400():
    status, body = _fingerprints(
        resolved={"app": "1.0", "lib": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("app", "9.9", "lib", "1.0"),
        ],
    )
    assert status == 400
    assert "inconsistent" in body["error"]["message"]


def test_invalid_resolved_version_returns_400():
    status, body = _fingerprints(resolved={"x": "not-a-version"}, dependency_graph=[])
    assert status == 400
    assert "PEP 440" in body["error"]["message"]


def test_root_edge_with_source_version_returns_400():
    status, body = _fingerprints(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "1.0", "app", "1.0")],
    )
    assert status == 400


def test_root_is_a_reserved_package_name():
    status, body = _fingerprints(resolved={"<root>": "1.0"}, dependency_graph=[])
    assert status == 400
    assert "reserved" in body["error"]["message"]


def test_duplicate_canonical_names_return_400():
    status, body = _fingerprints(
        resolved={"Foo_Bar": "1.0", "foo-bar": "2.0"}, dependency_graph=[]
    )
    assert status == 400
    assert "duplicates" in body["error"]["message"]


def test_extra_fields_rejected():
    response = client.post(
        "/audit/graph-fingerprints",
        json={"resolved": {}, "dependency_graph": [], "nope": 1},
    )
    assert response.status_code == 422

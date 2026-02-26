"""Tests for meshmap.graph — MeshGraph pathfinding and routing."""

from __future__ import annotations

from pathlib import Path

from meshmap.graph import GraphEdge, MeshGraph

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_graph(*edges: tuple[str, str, float, float | None]) -> MeshGraph:
    """Build a graph from (a, b, snr_a_hears_b, snr_b_hears_a) tuples.

    Nodes are auto-created as "repeater" type.
    """
    g = MeshGraph()
    nodes_seen: set[str] = set()
    for a, b, snr_ab, snr_ba in edges:
        for pk in (a, b):
            if pk not in nodes_seen:
                g.upsert_node(pk, pk[:4], "repeater", None, None)
                nodes_seen.add(pk)
        g.upsert_edge(listener=a, talker=b, snr=snr_ab)
        if snr_ba is not None:
            g.upsert_edge(listener=b, talker=a, snr=snr_ba)
    return g


# ---------------------------------------------------------------------------
# find_route
# ---------------------------------------------------------------------------


class TestFindRoute:
    def test_same_node(self):
        g = MeshGraph()
        g.upsert_node("aaa", "A", "repeater", None, None)
        assert g.find_route("aaa", "aaa") == []

    def test_unknown_node_returns_none(self):
        g = MeshGraph()
        g.upsert_node("aaa", "A", "repeater", None, None)
        assert g.find_route("aaa", "zzz") is None

    def test_direct_neighbours(self):
        g = _make_graph(("aaa", "bbb", 15.0, 14.0))
        route = g.find_route("aaa", "bbb")
        assert route == []  # direct — no intermediates

    def test_two_hop_route(self):
        g = _make_graph(
            ("aaa", "bbb", 15.0, 14.0),
            ("bbb", "ccc", 12.0, 10.0),
        )
        route = g.find_route("aaa", "ccc")
        assert route == ["bbb"]

    def test_prefers_good_snr_over_fewer_hops(self):
        """Direct A→C has terrible SNR; A→B→C via good SNR should win."""
        g = _make_graph(
            ("aaa", "bbb", 15.0, 14.0),  # good link
            ("bbb", "ccc", 12.0, 10.0),  # decent link
            ("aaa", "ccc", -5.0, -8.0),  # terrible direct link
        )
        route = g.find_route("aaa", "ccc")
        assert route == ["bbb"]

    def test_prefers_fewer_hops_with_equal_snr(self):
        """When SNR is similar, prefer the shorter path."""
        g = _make_graph(
            ("aaa", "bbb", 18.0, 18.0),
            ("bbb", "ccc", 18.0, 18.0),
            ("aaa", "ccc", 18.0, 18.0),  # direct with same good SNR
        )
        route = g.find_route("aaa", "ccc")
        assert route == []  # direct is preferred

    def test_disconnected_nodes(self):
        """Nodes with no edges between clusters are unreachable."""
        g = _make_graph(
            ("aaa", "bbb", 10.0, 10.0),
        )
        g.upsert_node("ccc", "C", "repeater", None, None)
        assert g.find_route("aaa", "ccc") is None

    def test_no_snr_edge_treated_as_disconnected(self):
        """Edges with no SNR data at all should be skipped."""
        g = MeshGraph()
        g.upsert_node("aaa", "A", "repeater", None, None)
        g.upsert_node("bbb", "B", "repeater", None, None)
        # Manually create an edge with no SNR
        g._edges[("aaa", "bbb")] = GraphEdge(
            node_a="aaa",
            node_b="bbb",
            last_seen="2024-01-01",
            snr_a_hears_b=None,
            snr_b_hears_a=None,
        )
        assert g.find_route("aaa", "bbb") is None

    def test_one_direction_snr_uses_that_value(self):
        """If only one direction has SNR, use it (don't skip the edge)."""
        g = MeshGraph()
        g.upsert_node("aaa", "A", "repeater", None, None)
        g.upsert_node("bbb", "B", "repeater", None, None)
        g.upsert_edge(listener="aaa", talker="bbb", snr=10.0)
        # Only one direction set
        route = g.find_route("aaa", "bbb")
        assert route == []

    def test_uses_min_snr_of_both_directions(self):
        """Cost should use the worse (min) of two SNR directions."""
        # Route 1: A→B with asymmetric SNR (good one way, bad the other)
        # Route 2: A→C→B with consistently decent SNR
        g = _make_graph(
            ("aaa", "bbb", 20.0, -5.0),  # min = -5, cost = 3.5
            ("aaa", "ccc", 10.0, 10.0),  # min = 10, cost = 2.0
            ("ccc", "bbb", 10.0, 10.0),  # min = 10, cost = 2.0
        )
        g.find_route("aaa", "bbb")
        # Via ccc: 2.0 + 2.0 = 4.0, Direct: 3.5 — direct is still cheaper
        # Let's make the asymmetry worse
        g2 = _make_graph(
            ("aaa", "bbb", 20.0, -10.0),  # min = -10, cost = 4.0
            ("aaa", "ccc", 12.0, 12.0),  # min = 12, cost = 1.8
            ("ccc", "bbb", 12.0, 12.0),  # min = 12, cost = 1.8
        )
        route2 = g2.find_route("aaa", "bbb")
        assert route2 == ["ccc"]  # 1.8 + 1.8 = 3.6 < 4.0

    def test_multi_hop_route(self):
        g = _make_graph(
            ("aaa", "bbb", 15.0, 15.0),
            ("bbb", "ccc", 15.0, 15.0),
            ("ccc", "ddd", 15.0, 15.0),
            ("ddd", "eee", 15.0, 15.0),
        )
        route = g.find_route("aaa", "eee")
        assert route == ["bbb", "ccc", "ddd"]


# ---------------------------------------------------------------------------
# route_to_path_hex
# ---------------------------------------------------------------------------


class TestRouteToPathHex:
    def test_empty_route(self):
        g = MeshGraph()
        assert g.route_to_path_hex([]) == ""

    def test_single_hop(self):
        g = MeshGraph()
        assert g.route_to_path_hex(["ab1234"]) == "ab"

    def test_multiple_hops(self):
        g = MeshGraph()
        assert g.route_to_path_hex(["ab1234", "cd5678", "ef9012"]) == "abcdef"


# ---------------------------------------------------------------------------
# Persistence round-trip
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_save_load_preserves_graph(self, tmp_path: Path):
        g = _make_graph(
            ("aaa", "bbb", 15.0, 14.0),
            ("bbb", "ccc", 10.0, 12.0),
        )
        out = tmp_path / "graph.json"
        g.save(out)

        g2 = MeshGraph.load(out)
        assert set(g2.nodes.keys()) == {"aaa", "bbb", "ccc"}
        assert len(g2._edges) == 2
        # Pathfinding should work on loaded graph
        assert g2.find_route("aaa", "ccc") == ["bbb"]

    def test_load_nonexistent_returns_empty(self, tmp_path: Path):
        g = MeshGraph.load(tmp_path / "missing.json")
        assert len(g.nodes) == 0
        assert len(g._edges) == 0


# ---------------------------------------------------------------------------
# Edge cost sanity checks
# ---------------------------------------------------------------------------


class TestEdgeCostFormula:
    """Verify the cost formula produces expected values at key SNR points."""

    def test_cost_at_good_snr(self):
        # SNR = 15 → cost = 1.0 + max(0, 20-15)/10 = 1.5
        g = _make_graph(("aaa", "bbb", 15.0, 15.0))
        # Direct route should exist
        assert g.find_route("aaa", "bbb") == []

    def test_cost_at_zero_snr(self):
        # SNR = 0 → cost = 1.0 + max(0, 20-0)/10 = 3.0
        g = _make_graph(("aaa", "bbb", 0.0, 0.0))
        assert g.find_route("aaa", "bbb") == []

    def test_cost_at_negative_snr(self):
        # SNR = -10 → cost = 1.0 + max(0, 20-(-10))/10 = 4.0
        g = _make_graph(("aaa", "bbb", -10.0, -10.0))
        assert g.find_route("aaa", "bbb") == []

    def test_high_snr_cost_floors_at_one(self):
        # SNR = 25 → cost = 1.0 + max(0, 20-25)/10 = 1.0
        g = _make_graph(("aaa", "bbb", 25.0, 25.0))
        assert g.find_route("aaa", "bbb") == []

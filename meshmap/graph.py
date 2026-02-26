"""Persistent graph model for the mesh network exploration state."""

from __future__ import annotations

import heapq
import json
import os
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class GraphNode:
    public_key: str
    name: str | None
    node_type: str  # "repeater" | "node" | "unknown"
    lat: float | None
    lon: float | None
    first_seen: str  # ISO timestamp when first discovered
    last_seen: str  # ISO timestamp when last seen as a neighbour
    last_visited: str | None = None  # ISO timestamp of last successful neighbour fetch
    visit_failed: bool = False  # True if last login attempt failed
    depth: int = 0


@dataclass
class GraphEdge:
    node_a: str  # canonical min key
    node_b: str  # canonical max key
    last_seen: str
    snr_a_hears_b: float | None = None  # node_a received node_b's signal (b→a quality)
    snr_b_hears_a: float | None = None  # node_b received node_a's signal (a→b quality)


class MeshGraph:
    """In-memory graph with JSON persistence."""

    VERSION = 1

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        # Keyed by (min_key, max_key) for deduplication
        self._edges: dict[tuple[str, str], GraphEdge] = {}
        self._lock = threading.Lock()
        self.currently_visiting: str | None = None  # transient; not persisted
        self.currently_trying_route: list[str] = []  # transient; node IDs of active route attempt

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: Path | str) -> MeshGraph:
        """Load from a JSON file; returns empty graph if file does not exist."""
        path = Path(path)
        g = cls()
        if not path.exists():
            return g
        data = json.loads(path.read_text())
        for pk, nd in data.get("nodes", {}).items():
            g.nodes[pk] = GraphNode(**nd)
        for ed in data.get("edges", []):
            # Migrate v1 format (from_key/to_key/snr → node_a/node_b/snr_*)
            if "from_key" in ed:
                ed["node_a"] = ed.pop("from_key")
                ed["node_b"] = ed.pop("to_key")
            if "snr" in ed:
                ed.setdefault("snr_a_hears_b", ed.pop("snr"))
                ed.setdefault("snr_b_hears_a", None)
            edge = GraphEdge(**ed)
            key = (min(edge.node_a, edge.node_b), max(edge.node_a, edge.node_b))
            g._edges[key] = edge
        return g

    def save(self, path: Path | str) -> None:
        """Atomically save to a JSON file (write temp → rename)."""
        path = Path(path)
        with self._lock:
            data = {
                "version": self.VERSION,
                "last_updated": _now(),
                "nodes": {pk: asdict(n) for pk, n in self.nodes.items()},
                "edges": [asdict(e) for e in self._edges.values()],
            }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        os.replace(tmp, path)

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def upsert_node(
        self,
        public_key: str,
        name: str | None,
        node_type: str,
        lat: float | None,
        lon: float | None,
        depth: int = 0,
    ) -> GraphNode:
        """Add a node or update its metadata if already known."""
        now = _now()
        if public_key in self.nodes:
            node = self.nodes[public_key]
            node.last_seen = now
            if name is not None:
                node.name = name
            if lat is not None:
                node.lat = lat
            if lon is not None:
                node.lon = lon
            # Only upgrade type, never downgrade to "unknown"
            if node_type != "unknown" and node.node_type == "unknown":
                node.node_type = node_type
            # Depth: keep the shallowest discovered path
            if depth < node.depth:
                node.depth = depth
        else:
            node = GraphNode(
                public_key=public_key,
                name=name,
                node_type=node_type,
                lat=lat,
                lon=lon,
                first_seen=now,
                last_seen=now,
                depth=depth,
            )
            self.nodes[public_key] = node
        return node

    def upsert_edge(self, listener: str, talker: str, snr: float) -> GraphEdge:
        """Add or update a directed SNR observation.

        listener: the node that measured the SNR (it received talker's signal).
        talker:   the node that was transmitting.
        snr:      the SNR measured by listener.
        """
        key = (min(listener, talker), max(listener, talker))
        now = _now()
        if key not in self._edges:
            self._edges[key] = GraphEdge(node_a=key[0], node_b=key[1], last_seen=now)
        edge = self._edges[key]
        edge.last_seen = now
        if listener == key[0]:  # listener is node_a → a heard b
            edge.snr_a_hears_b = snr
        else:  # listener is node_b → b heard a
            edge.snr_b_hears_a = snr
        return edge

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def next_repeaters_to_visit(
        self, refresh: bool = False, retry: bool = False
    ) -> list[GraphNode]:
        """Return repeater nodes to visit next, sorted by priority.

        Priority order:
          1. Never-visited repeaters (last_visited is None and not failed)
          2. If retry=True, visit_failed repeaters (oldest last_seen first)
          3. If refresh=True, previously-visited repeaters (oldest last_visited first)

        visit_failed nodes are only re-queued when retry=True.
        Previously-visited nodes are only re-queued when refresh=True.
        """
        never_visited: list[GraphNode] = []
        failed_nodes: list[GraphNode] = []
        previously_visited: list[GraphNode] = []

        for node in self.nodes.values():
            if node.node_type != "repeater":
                continue
            if node.visit_failed:
                if retry:
                    failed_nodes.append(node)
            elif node.last_visited is None:
                never_visited.append(node)
            elif refresh:
                previously_visited.append(node)

        failed_nodes.sort(key=lambda n: n.last_seen)
        previously_visited.sort(key=lambda n: n.last_visited or "")

        return never_visited + failed_nodes + previously_visited

    @property
    def stats(self) -> dict[str, int]:
        visited = sum(1 for n in self.nodes.values() if n.last_visited is not None)
        pending = sum(
            1
            for n in self.nodes.values()
            if n.node_type == "repeater" and n.last_visited is None and not n.visit_failed
        )
        failed = sum(1 for n in self.nodes.values() if n.visit_failed)
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self._edges),
            "visited": visited,
            "pending": pending,
            "failed": failed,
        }

    # ------------------------------------------------------------------
    # Routing / pathfinding
    # ------------------------------------------------------------------

    def find_route(self, source: str, target: str) -> list[str] | None:
        """Find shortest route between two nodes using Dijkstra's algorithm.

        Returns a list of **intermediate** node pubkeys (excluding source and
        target), or None if unreachable.

        Edge cost balances hops and SNR:  cost = 1.0 + max(0, 20 - snr) / 10
        Uses the minimum SNR of both directions (conservative).
        Edges with no SNR data at all are skipped (treated as disconnected).
        """
        if source == target:
            return []
        if source not in self.nodes or target not in self.nodes:
            return None

        # Build adjacency list
        adj: dict[str, list[tuple[str, float]]] = {pk: [] for pk in self.nodes}
        for (a, b), edge in self._edges.items():
            snr_vals = [v for v in (edge.snr_a_hears_b, edge.snr_b_hears_a) if v is not None]
            if not snr_vals:
                continue  # no SNR data — treat as disconnected
            snr = min(snr_vals)
            cost = 1.0 + max(0, 20 - snr) / 10
            adj[a].append((b, cost))
            adj[b].append((a, cost))

        # Dijkstra
        dist: dict[str, float] = {source: 0.0}
        prev: dict[str, str | None] = {source: None}
        heap: list[tuple[float, str]] = [(0.0, source)]

        while heap:
            d, u = heapq.heappop(heap)
            if u == target:
                break
            if d > dist.get(u, float("inf")):
                continue
            for v, w in adj.get(u, []):
                nd = d + w
                if nd < dist.get(v, float("inf")):
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(heap, (nd, v))

        if target not in prev:
            return None

        # Reconstruct path and return intermediates only
        path: list[str] = []
        cur: str | None = target
        while cur is not None:
            path.append(cur)
            cur = prev.get(cur)
        path.reverse()
        # path = [source, ..., target] — return intermediates
        return path[1:-1]

    def route_to_path_hex(self, route: list[str]) -> str:
        """Encode a route (list of intermediate pubkeys) as a hex path string.

        Each hop is represented by the first byte of its pubkey.
        E.g. ["ab12...", "cd34..."] → "abcd"
        """
        return "".join(pk[:2] for pk in route)

    # ------------------------------------------------------------------
    # Serialisation for D3
    # ------------------------------------------------------------------

    def to_d3_json(self) -> dict[str, Any]:
        """Return a D3-compatible {nodes, links} dict (thread-safe read)."""
        with self._lock:
            nodes = [
                {
                    "id": n.public_key,
                    "name": n.name,
                    "type": n.node_type,
                    "lat": n.lat,
                    "lon": n.lon,
                    "visited": n.last_visited is not None,
                    "failed": n.visit_failed,
                    "depth": n.depth,
                    "last_visited": n.last_visited,
                }
                for n in self.nodes.values()
            ]
            links = [
                {
                    "source": e.node_a,
                    "target": e.node_b,
                    "snr_a_hears_b": e.snr_a_hears_b,  # b→a quality (b transmits, a receives)
                    "snr_b_hears_a": e.snr_b_hears_a,  # a→b quality (a transmits, b receives)
                    "last_seen": e.last_seen,
                }
                for e in self._edges.values()
            ]
        return {
            "nodes": nodes,
            "links": links,
            "currently_visiting": self.currently_visiting,
            "currently_trying_route": self.currently_trying_route,
        }

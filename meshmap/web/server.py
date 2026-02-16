"""Background HTTP server for the mesh graph visualization."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

_STATIC = Path(__file__).parent / "static"


class _Handler(BaseHTTPRequestHandler):
    # Injected at class-creation time by start_server()
    graph_fn: Callable[[], dict[str, Any]]
    stats_fn: Callable[[], dict[str, int]]

    def do_GET(self) -> None:
        path = self.path.split("?")[0]  # strip query string
        if path in ("/", "/index.html"):
            self._serve_file(_STATIC / "index.html", "text/html; charset=utf-8")
        elif path == "/graph.json":
            try:
                data = self.graph_fn()
                data["stats"] = self.stats_fn()
            except Exception:
                data = {"nodes": [], "links": [], "stats": {}}
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_file(self, path: Path, content_type: str) -> None:
        try:
            body = path.read_bytes()
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass  # suppress per-request console noise


def start_server(
    port: int,
    graph_fn: Callable[[], dict[str, Any]],
    stats_fn: Callable[[], dict[str, int]],
) -> HTTPServer:
    """Start the visualization server in a background daemon thread.

    Args:
        port: TCP port to listen on.
        graph_fn: Callable that returns the current D3-compatible graph dict.
        stats_fn: Callable that returns the current stats dict.

    Returns:
        The running HTTPServer instance (call server.shutdown() to stop it).
    """

    class Handler(_Handler):
        pass

    Handler.graph_fn = staticmethod(graph_fn)  # type: ignore[attr-defined]
    Handler.stats_fn = staticmethod(stats_fn)  # type: ignore[attr-defined]

    server = HTTPServer(("", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="meshmap-webserver")
    thread.start()
    return server

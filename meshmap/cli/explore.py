"""explore command - BFS graph exploration of the mesh network."""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import click
import meshcore
from meshcore.events import EventType
from rich.console import Console

from meshmap.graph import MeshGraph
from meshmap.scanner import MeshScanner


@click.command()
@click.pass_context
@click.option(
    "--output",
    "-o",
    default="meshmap-graph.json",
    type=click.Path(),
    show_default=True,
    help="Graph JSON file path.",
)
@click.option(
    "--resume/--no-resume",
    default=False,
    help="Load existing graph and continue from unvisited nodes.",
)
@click.option(
    "--refresh/--no-refresh",
    default=False,
    help="Re-visit already-explored nodes (re-queue by oldest last-visited).",
)
@click.option(
    "--retry/--no-retry",
    default=False,
    help="Retry nodes whose last visit failed.",
)
@click.option(
    "--serve/--no-serve",
    default=False,
    help="Start a web visualization server while running.",
)
@click.option(
    "--port",
    default=8080,
    show_default=True,
    type=int,
    help="Web server port.",
)
@click.option(
    "--depth",
    default=5,
    show_default=True,
    type=int,
    help="Maximum hop depth to explore.",
)
@click.option(
    "--wait-time",
    "-w",
    default=10.0,
    show_default=True,
    type=float,
    help="Seconds to listen for 0-hop discovery responses.",
)
def explore(
    ctx: click.Context,
    output: str,
    resume: bool,
    refresh: bool,
    retry: bool,
    serve: bool,
    port: int,
    depth: int,
    wait_time: float,
) -> None:
    """Explore the mesh network graph via BFS.

    Discovers 0-hop repeaters, then recursively logs in to each one to
    fetch their neighbour lists, building a graph of the network.

    The graph is saved to OUTPUT after each node is processed so
    exploration can be paused (Ctrl+C) and resumed with --resume.
    """
    asyncio.run(
        _explore(
            ctx.obj["serial_port"],
            ctx.obj["baudrate"],
            ctx.obj["debug"],
            ctx.obj.get("verbose", False),
            Path(output),
            resume,
            refresh,
            retry,
            serve,
            port,
            depth,
            wait_time,
            ctx.obj.get("sniff_active", False),
            ctx.obj.get("sniff_keys", []),
        )
    )


async def _explore(
    serial_port: str,
    baudrate: int,
    debug: bool,
    verbose: bool,
    output_path: Path,
    resume: bool,
    refresh: bool,
    retry: bool,
    serve: bool,
    port: int,
    max_depth: int,
    wait_time: float,
    sniff_active: bool = False,
    sniff_keys: list | None = None,
) -> None:
    console = Console()

    # ── Load or create graph ─────────────────────────────────────────────────
    if resume and output_path.exists():
        graph = MeshGraph.load(output_path)
        s = graph.stats
        console.print(
            f"[dim]Loaded graph: {s['total_nodes']} nodes, {s['total_edges']} edges, "
            f"{s['visited']} visited, {s['pending']} pending, {s['failed']} failed[/dim]"
        )
    else:
        graph = MeshGraph()

    # ── Web server ───────────────────────────────────────────────────────────
    if serve:
        from meshmap.web.server import start_server

        start_server(port, graph.to_d3_json, lambda: graph.stats)
        console.print(f"[green]Visualization at http://localhost:{port}[/green]")

    # ── Connect ──────────────────────────────────────────────────────────────
    console.print(f"[dim]Connecting to {serial_port}…[/dim]")
    try:
        mesh = await meshcore.MeshCore.create_serial(
            port=serial_port, baudrate=baudrate, debug=debug
        )
    except Exception as exc:
        console.print(f"[red]Connection failed: {exc}[/red]")
        sys.exit(1)
    console.print("[dim]Connected.[/dim]")

    sniffer = None
    if sniff_active:
        from meshmap.sniffer import PacketSniffer

        sniffer = PacketSniffer(mesh, debug=debug, graph=graph)
        await sniffer.attach(sniff_keys or [], None)

    try:
        await mesh.ensure_contacts()

        # ── Discover 0-hop repeaters ─────────────────────────────────────────
        graph.status_message = f"Discovering 0-hop repeaters ({wait_time:.0f}s)…"
        console.print(f"[dim]Discovering 0-hop repeaters ({wait_time:.0f}s)…[/dim]")
        scanner = MeshScanner(serial_port, baudrate=baudrate, debug=debug)
        scanner.mesh = mesh  # reuse existing connection
        repeaters = await scanner.discover_zero_hop_repeaters(wait_time=int(wait_time))

        # Add the scanner itself as a node so pathfinding can route from it
        self_info = mesh.self_info or {}
        self_pubkey = self_info.get("public_key", "")
        if self_pubkey:
            graph.upsert_node(
                self_pubkey,
                self_info.get("adv_name", "self"),
                "node",
                self_info.get("adv_lat"),
                self_info.get("adv_lon"),
                depth=0,
            )

        for r in repeaters:
            canonical_pk = _resolve_pubkey(r["public_key"], mesh.contacts)
            graph.upsert_node(
                canonical_pk,
                r.get("name"),
                "repeater",
                r.get("lat"),
                r.get("lon"),
                depth=0,
            )
            # Create edge from scanner to 0-hop repeater so pathfinding works
            snr = r.get("snr")
            if self_pubkey and snr is not None:
                graph.upsert_edge(listener=self_pubkey, talker=canonical_pk, snr=snr)

        console.print(f"[dim]Found {len(repeaters)} 0-hop repeater(s).[/dim]")
        graph.save(output_path)

        # ── BFS exploration loop ─────────────────────────────────────────────
        while True:
            pending = graph.next_repeaters_to_visit(refresh=refresh, retry=retry)
            if not pending:
                graph.status_message = "Exploration complete"
                console.print("[green]Exploration complete — no more nodes to visit.[/green]")
                break

            node = pending[0]
            label = node.name or (node.public_key[:12] + "…")

            if node.depth >= max_depth:
                # Mark as visited at depth limit so we don't loop forever
                node.last_visited = datetime.now(UTC).isoformat()
                node.visit_failed = False
                graph.save(output_path)
                console.print(f"[dim]Skipping {label} — depth {node.depth} ≥ {max_depth}[/dim]")
                continue

            remaining = graph.stats["pending"]
            graph.status_message = f"Visiting {label} (depth {node.depth}, {remaining} remaining)"
            console.print(
                f"Visiting [cyan]{label}[/cyan] (depth {node.depth}, {remaining} remaining)…"
            )

            # Find the contact in the local contact list
            contact = _find_contact_by_pubkey(node.public_key, mesh.contacts)
            if contact is None:
                console.print("  [yellow]Not in contact list — skipping[/yellow]")
                node.visit_failed = True
                graph.save(output_path)
                continue

            self_pubkey = mesh.self_info.get("public_key", "") if mesh.self_info else ""
            graph.currently_visiting = node.public_key
            try:
                neighbours = await _login_fetch_logout(
                    mesh,
                    contact,
                    graph=graph,
                    self_pubkey=self_pubkey,
                    console=console,
                )
                node.last_visited = datetime.now(UTC).isoformat()
                node.visit_failed = False

                for nb in neighbours:
                    nb_prefix = nb.get("pubkey", "")
                    if not nb_prefix:
                        continue

                    # Resolve to full pubkey when possible
                    nb_pk, nb_contact = _resolve_pubkey_and_contact(nb_prefix, mesh.contacts)
                    nb_type = (
                        "repeater"
                        if (nb_contact and nb_contact.get("type") == 2)
                        else "node"
                        if nb_contact
                        else "unknown"
                    )

                    graph.upsert_node(
                        nb_pk,
                        nb.get("name"),
                        nb_type,
                        nb.get("lat"),
                        nb.get("lon"),
                        depth=node.depth + 1,
                    )

                    snr = nb.get("snr")
                    if snr is not None:
                        # node (visitor) heard nb at this SNR → node is the listener
                        graph.upsert_edge(listener=node.public_key, talker=nb_pk, snr=snr)

                graph.save(output_path)
                s = graph.stats
                console.print(
                    f"  [green]✓[/green] {len(neighbours)} neighbours. "
                    f"Total: {s['total_nodes']} nodes, {s['total_edges']} edges, "
                    f"{s['pending']} pending"
                )

            except KeyboardInterrupt:
                raise
            except Exception as exc:
                console.print(f"  [red]✗[/red] {exc}")
                node.visit_failed = True
                graph.save(output_path)
            finally:
                graph.currently_visiting = None
                graph.currently_trying_route = []

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — saving graph…[/yellow]")
        graph.status_message = "Interrupted"
        graph.save(output_path)
    finally:
        if sniffer is not None:
            sniffer.detach()
        await mesh.disconnect()

    s = graph.stats
    console.print(f"\n[bold]Graph saved to {output_path}[/bold]")
    console.print(
        f"Nodes: {s['total_nodes']}  Edges: {s['total_edges']}  "
        f"Visited: {s['visited']}  Failed: {s['failed']}  Pending: {s['pending']}"
    )


# ── Helpers ────────────────────────────────────────────────────────────────────


def _resolve_pubkey(pubkey: str, contacts: dict[str, Any]) -> str:
    """Return the full pubkey from contacts if the given pubkey is a prefix; else return as-is."""
    prefix = pubkey[:8].lower()
    for pk in contacts:
        if pk.lower().startswith(prefix):
            return pk
    return pubkey


def _resolve_pubkey_and_contact(
    prefix: str, contacts: dict[str, Any]
) -> tuple[str, dict[str, Any] | None]:
    """Match a pubkey prefix against contacts. Returns (full_pk, contact_or_None)."""
    p = prefix.lower()
    for pk, contact in contacts.items():
        if pk.lower().startswith(p):
            return pk, contact
    return prefix, None


def _find_contact_by_pubkey(pubkey: str, contacts: dict[str, Any]) -> dict[str, Any] | None:
    """Find a contact whose full pubkey starts with the given string (or equals it)."""
    pk_lower = pubkey.lower()
    for pk, contact in contacts.items():
        if pk.lower().startswith(pk_lower) or pk_lower.startswith(pk.lower()):
            return contact
    return None


async def _try_login(
    mesh: Any,
    contact: dict[str, Any],
    password: str,
    attempts: int,
) -> bool:
    """Attempt to log in to a contact. Returns True on success, False on timeout.

    Raises RuntimeError if the login is explicitly rejected.
    """
    name = contact.get("adv_name", "?")
    for attempt in range(1, attempts + 1):
        login_event = await mesh.commands.send_login(contact, password)
        if login_event and login_event.type == EventType.ERROR:
            if attempt < attempts:
                await asyncio.sleep(2)
            continue

        t_ok = asyncio.create_task(mesh.wait_for_event(EventType.LOGIN_SUCCESS, timeout=10))
        t_fail = asyncio.create_task(mesh.wait_for_event(EventType.LOGIN_FAILED, timeout=10))
        done, pending_tasks = await asyncio.wait(
            {t_ok, t_fail}, return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending_tasks:
            t.cancel()

        if t_fail in done and t_fail.result() is not None:
            raise RuntimeError(f"Login rejected by {name!r}")
        if t_ok in done and t_ok.result() is not None:
            return True
        if attempt < attempts:
            await asyncio.sleep(2)

    return False


async def _login_fetch_logout(
    mesh: Any,
    contact: dict[str, Any],
    password: str = "",
    graph: MeshGraph | None = None,
    self_pubkey: str = "",
    console: Console | None = None,
) -> list[dict[str, Any]]:
    """Login to a contact, fetch its neighbours, then logout.

    Uses a retry cascade with progressively broader routing strategies:
      1. Graph-computed route via change_contact_path (up to 3 attempts)
      2. Existing device route (up to 2 attempts)
      3. Flood routing via reset_path (up to 2 attempts)

    Raises:
        RuntimeError: if login fails or no neighbour response is received.
    """
    if console is None:
        console = Console()
    name = contact.get("adv_name", "?")
    target_pk = contact.get("public_key", "")
    _fetch_attempts = 3
    logged_in = False
    route_desc = ""
    tried_path_hex: str | None = None  # track which path we already tried

    # Snapshot the device's cached route *before* we overwrite it
    orig_out_path = contact.get("out_path", "")
    orig_out_path_len = contact.get("out_path_len", 0)
    if orig_out_path and orig_out_path_len and orig_out_path_len > 0:
        orig_device_path_hex = orig_out_path[: orig_out_path_len * 2]
    else:
        orig_device_path_hex = ""

    def _set_route_vis(node_ids: list[str]) -> None:
        """Update the graph's route visualization (visible in the web UI)."""
        if graph is not None:
            graph.currently_trying_route = node_ids

    def _set_status(msg: str) -> None:
        """Update the graph's status message (visible in the web UI)."""
        if graph is not None:
            graph.status_message = msg

    # ── Strategy 1: Graph-computed route (bidir first, then any) ────────────
    if graph is not None and self_pubkey:
        tried_paths: list[str] = []
        for bidir_pass, label in [(True, "bidirectional"), (False, "any-direction")]:
            if logged_in:
                break
            route = graph.find_route(self_pubkey, target_pk, require_bidir=bidir_pass)
            if route is None:
                console.print(f"  [dim]No {label} computed path available[/dim]")
                continue
            path_hex = graph.route_to_path_hex(route)
            if path_hex in tried_paths:
                console.print(f"  [dim]Skipping {label} path (same as already tried)[/dim]")
                continue
            tried_paths.append(path_hex)
            tried_path_hex = path_hex
            hop_names = []
            for pk in route:
                node = graph.nodes.get(pk)
                hop_names.append(node.name or pk[:8] if node else pk[:8])
            if hop_names:
                via = " → ".join(hop_names)
                route_desc = f"{label} path via {via}"
                console.print(f"  [blue]Trying[/blue] {route_desc} [dim](path={path_hex})[/dim]")
            else:
                route_desc = f"{label} direct path"
                console.print(f"  [blue]Trying[/blue] {route_desc}")
            _set_status(f"Connecting to {name}: {route_desc}")
            _set_route_vis([self_pubkey, *route, target_pk])
            await mesh.commands.change_contact_path(contact, path_hex)
            logged_in = await _try_login(mesh, contact, password, attempts=3)
            if not logged_in:
                console.print(f"  [yellow]Failed[/yellow] {route_desc}")
                _set_route_vis([])

    # ── Strategy 2: Original device route (only if it had a real path) ──────
    if not logged_in:
        if not orig_device_path_hex:
            console.print("  [dim]Skipping device route (no cached path)[/dim]")
        elif tried_path_hex is not None and orig_device_path_hex == tried_path_hex:
            console.print("  [dim]Skipping device route (same as computed path)[/dim]")
        else:
            route_desc = (
                f"original device route "
                f"[dim](path={orig_device_path_hex}, {orig_out_path_len} hop(s))[/dim]"
            )
            await mesh.commands.change_contact_path(contact, orig_device_path_hex)
            _set_status(f"Connecting to {name}: cached device route")
            _set_route_vis([self_pubkey, target_pk] if self_pubkey else [])
            console.print(f"  [blue]Trying[/blue] {route_desc}")
            logged_in = await _try_login(mesh, contact, password, attempts=2)
            if not logged_in:
                console.print("  [yellow]Failed[/yellow] original device route")
                _set_route_vis([])

    # ── Strategy 3: Flood routing ────────────────────────────────────────────
    if not logged_in:
        route_desc = "flood routing"
        console.print(f"  [blue]Trying[/blue] {route_desc}")
        _set_status(f"Connecting to {name}: flood routing")
        _set_route_vis([])  # flood has no specific path to show
        await mesh.commands.reset_path(contact)
        logged_in = await _try_login(mesh, contact, password, attempts=2)
        if not logged_in:
            console.print(f"  [yellow]Failed[/yellow] {route_desc}")

    if not logged_in:
        _set_status(f"Failed to connect to {name}")
        _set_route_vis([])
        raise RuntimeError(f"Could not log in to {name!r} after all routing strategies")

    # ── Fetch phase ──────────────────────────────────────────────────────────
    _set_status(f"Fetching neighbours from {name}…")
    _set_route_vis([])
    result = None
    try:
        for attempt in range(1, _fetch_attempts + 1):
            result = await mesh.commands.fetch_all_neighbours(contact, timeout=30, min_timeout=15)
            if result is not None:
                break
            if attempt < _fetch_attempts:
                await asyncio.sleep(2)
    finally:
        await mesh.commands.send_logout(contact)

    _set_status("")

    if result is None:
        raise RuntimeError(f"No neighbour response from {name!r}")

    neighbours: list[dict[str, Any]] = result.get("neighbours", [])
    _resolve_names(neighbours, mesh.contacts)
    return neighbours


def _resolve_names(neighbours: list[dict[str, Any]], contacts: dict[str, Any]) -> None:
    """Add name/lat/lon to each neighbour by prefix-matching its pubkey."""
    for nb in neighbours:
        prefix = nb.get("pubkey", "").lower()
        nb.setdefault("name", None)
        nb.setdefault("lat", None)
        nb.setdefault("lon", None)
        if not prefix:
            continue
        for pk, c in contacts.items():
            if pk.lower().startswith(prefix):
                nb["name"] = c.get("adv_name")
                nb["lat"] = c.get("adv_lat")
                nb["lon"] = c.get("adv_lon")
                break

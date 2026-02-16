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
    "--output", "-o",
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
    "--wait-time", "-w",
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
    asyncio.run(_explore(
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
    ))


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
        sniffer = PacketSniffer(mesh, debug=debug)
        await sniffer.attach(sniff_keys or [], None)

    try:
        await mesh.ensure_contacts()

        # ── Discover 0-hop repeaters ─────────────────────────────────────────
        console.print(f"[dim]Discovering 0-hop repeaters ({wait_time:.0f}s)…[/dim]")
        scanner = MeshScanner(serial_port, baudrate=baudrate, debug=debug)
        scanner.mesh = mesh  # reuse existing connection
        repeaters = await scanner.discover_zero_hop_repeaters(wait_time=int(wait_time))

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
        console.print(f"[dim]Found {len(repeaters)} 0-hop repeater(s).[/dim]")
        graph.save(output_path)

        # ── BFS exploration loop ─────────────────────────────────────────────
        while True:
            pending = graph.next_repeaters_to_visit(refresh=refresh, retry=retry)
            if not pending:
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

            console.print(
                f"Visiting [cyan]{label}[/cyan] "
                f"(depth {node.depth}, {graph.stats['pending']} remaining)…"
            )

            # Find the contact in the local contact list
            contact = _find_contact_by_pubkey(node.public_key, mesh.contacts)
            if contact is None:
                console.print("  [yellow]Not in contact list — skipping[/yellow]")
                node.visit_failed = True
                graph.save(output_path)
                continue

            graph.currently_visiting = node.public_key
            try:
                neighbours = await _login_fetch_logout(mesh, contact)
                node.last_visited = datetime.now(UTC).isoformat()
                node.visit_failed = False

                for nb in neighbours:
                    nb_prefix = nb.get("pubkey", "")
                    if not nb_prefix:
                        continue

                    # Resolve to full pubkey when possible
                    nb_pk, nb_contact = _resolve_pubkey_and_contact(nb_prefix, mesh.contacts)
                    nb_type = (
                        "repeater" if (nb_contact and nb_contact.get("type") == 2)
                        else "node" if nb_contact
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

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — saving graph…[/yellow]")
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


async def _login_fetch_logout(
    mesh: Any,
    contact: dict[str, Any],
    password: str = "",
) -> list[dict[str, Any]]:
    """Login to a contact, fetch its neighbours, then logout.

    Mirrors the logic in meshmap.neighbours.get_neighbours but reuses an
    existing mesh connection instead of creating a new one.

    Raises:
        RuntimeError: if login fails or no neighbour response is received.
    """
    name = contact.get("adv_name", "?")
    _login_attempts = 3
    _fetch_attempts = 3

    # ── Login phase ──────────────────────────────────────────────────────────
    logged_in = False
    for attempt in range(1, _login_attempts + 1):
        login_event = await mesh.commands.send_login(contact, password)
        if login_event and login_event.type == EventType.ERROR:
            if attempt < _login_attempts:
                await asyncio.sleep(2)
            continue

        t_ok = asyncio.create_task(
            mesh.wait_for_event(EventType.LOGIN_SUCCESS, timeout=10)
        )
        t_fail = asyncio.create_task(
            mesh.wait_for_event(EventType.LOGIN_FAILED, timeout=10)
        )
        done, pending_tasks = await asyncio.wait(
            {t_ok, t_fail}, return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending_tasks:
            t.cancel()

        if t_fail in done and t_fail.result() is not None:
            raise RuntimeError(f"Login rejected by {name!r}")
        if t_ok in done and t_ok.result() is not None:
            logged_in = True
            break
        if attempt < _login_attempts:
            await asyncio.sleep(2)

    if not logged_in:
        raise RuntimeError(f"Could not log in to {name!r} after {_login_attempts} attempt(s)")

    # ── Fetch phase ──────────────────────────────────────────────────────────
    result = None
    try:
        for attempt in range(1, _fetch_attempts + 1):
            result = await mesh.commands.fetch_all_neighbours(
                contact, timeout=30, min_timeout=15
            )
            if result is not None:
                break
            if attempt < _fetch_attempts:
                await asyncio.sleep(2)
    finally:
        await mesh.commands.send_logout(contact)

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

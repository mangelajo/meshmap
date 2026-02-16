"""get-neighbours command - login to a router and print its neighbour list."""

import asyncio
import json
import math
import sys
from datetime import timedelta
from typing import Any

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from meshmap.models import snr_color
from meshmap.neighbours import get_neighbours


@click.command("get-neighbours")
@click.argument("contact", metavar="CONTACT")
@click.option(
    "--password", "-P",
    default="",
    show_default=False,
    help="Login password (default: empty string for guest access).",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["table", "json", "yaml"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.pass_context
def get_neighbours_cmd(ctx, contact: str, password: str, output: str) -> None:
    """Login to a router and print its neighbour list.

    CONTACT is matched against the node name or public key
    (case-insensitive substring match on either).

    Logs in as guest by default; supply -P to use a specific password.
    """
    asyncio.run(_run(
        ctx.obj["serial_port"],
        ctx.obj["baudrate"],
        ctx.obj["debug"],
        ctx.obj.get("verbose", False),
        contact,
        password,
        output,
        ctx.obj.get("sniff_active", False),
        ctx.obj.get("sniff_keys", []),
    ))


async def _run(
    serial_port: str,
    baudrate: int,
    debug: bool,
    verbose: bool,
    contact: str,
    password: str,
    output: str,
    sniff_active: bool = False,
    sniff_keys: list | None = None,
) -> None:
    try:
        contact, neighbours = await get_neighbours(
            serial_port, baudrate, debug, contact, password,
            verbose=verbose,
            sniff_keys=sniff_keys if sniff_active else None,
        )
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if output == "json":
        click.echo(json.dumps(_to_dict(contact, neighbours), indent=2, ensure_ascii=False))
    elif output == "yaml":
        click.echo(
            yaml.dump(_to_dict(contact, neighbours), allow_unicode=True, sort_keys=False),
            nl=False,
        )
    else:
        _print_table(contact, neighbours)


def _to_dict(contact: dict[str, Any], neighbours: list[dict[str, Any]]) -> dict[str, Any]:
    """Serialisable structure for json/yaml output."""
    ctype = {1: "contact", 2: "repeater", 3: "chatroom"}.get(contact.get("type", 0), "unknown")
    return {
        "contact": {
            "name": contact.get("adv_name"),
            "type": ctype,
            "path_len": contact.get("out_path_len"),
            "public_key": contact.get("public_key"),
            "lat": contact.get("adv_lat"),
            "lon": contact.get("adv_lon"),
        },
        "neighbours": neighbours,
    }


_snr_style = snr_color


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return great-circle distance in kilometres between two lat/lon points."""
    r = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return r * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _print_table(contact: dict[str, Any], neighbours: list[dict[str, Any]]) -> None:
    console = Console()

    name = contact.get("adv_name", "unknown")
    ctype = {1: "contact", 2: "repeater", 3: "chatroom"}.get(contact.get("type", 0), "unknown")
    path_len = contact.get("out_path_len", -1)
    path_str = "flood" if path_len == -1 else str(path_len)
    pubkey = contact.get("public_key", "")

    # Subtitle line inside the panel header area
    subtitle = (
        f"[dim]{ctype}[/dim]  "
        f"[dim]path_len=[/dim][cyan]{path_str}[/cyan]  "
        f"[dim]{pubkey[:16]}…[/dim]"
    )

    repeater_lat = contact.get("adv_lat")
    repeater_lon = contact.get("adv_lon")
    show_dist = repeater_lat is not None and repeater_lon is not None

    table = Table(box=None, show_header=True, header_style="bold dim", padding=(0, 1))
    table.add_column("Pubkey", style="yellow", no_wrap=True)
    table.add_column("Last heard", justify="right", style="dim")
    table.add_column("SNR", justify="right", no_wrap=True)
    if show_dist:
        table.add_column("Dist", justify="right", style="dim", no_wrap=True)
    table.add_column("Name", style="cyan")

    for nb in neighbours:
        pubkey_nb = nb.get("pubkey", "")
        secs_ago = nb.get("secs_ago", 0)
        snr = nb.get("snr")
        nb_name = nb.get("name") or ""

        heard = _format_duration(secs_ago)
        if snr is not None:
            style = _snr_style(snr)
            snr_text = Text(f"{snr:+.2f} dB", style=style)
        else:
            snr_text = Text("—", style="dim")

        if show_dist:
            nb_lat, nb_lon = nb.get("lat"), nb.get("lon")
            if nb_lat is not None and nb_lon is not None:
                km = _haversine_km(repeater_lat, repeater_lon, nb_lat, nb_lon)
                dist_str = f"{km:.1f} km" if km >= 1.0 else f"{km * 1000:.0f} m"
            else:
                dist_str = "—"
            table.add_row(pubkey_nb, heard, snr_text, dist_str, nb_name)
        else:
            table.add_row(pubkey_nb, heard, snr_text, nb_name)

    title = f"[bold cyan]{name}[/bold cyan]  {subtitle}"
    n = len(neighbours)
    panel = Panel(
        table,
        title=title,
        subtitle=f"[dim]{n} neighbour{'s' if n != 1 else ''}[/dim]",
        border_style="cyan",
    )
    console.print(panel)


def _format_duration(seconds: int) -> str:
    if seconds < 0:
        return "unknown"
    td = timedelta(seconds=seconds)
    if td.days > 0:
        return f"{td.days}d {td.seconds // 3600}h ago"
    hours, remainder = divmod(td.seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours > 0:
        return f"{hours}h {minutes}m ago"
    if minutes > 0:
        return f"{minutes}m {secs}s ago"
    return f"{secs}s ago"

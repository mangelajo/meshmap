"""Contacts command - show all known contacts."""

import asyncio
import json
import sys
from datetime import UTC, datetime
from typing import Any

import click
import yaml
from rich.console import Console
from rich.table import Table

from meshmap.scanner import MeshScanner


@click.command()
@click.pass_context
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json", "yaml"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format.",
)
def all_contacts(ctx, output: str):
    """Show all contacts (including unknown paths)."""
    asyncio.run(
        show_all_contacts(
            ctx.obj["serial_port"],
            ctx.obj["debug"],
            ctx.obj["baudrate"],
            output,
            ctx.obj.get("sniff_active", False),
            ctx.obj.get("sniff_keys", []),
        )
    )


async def show_all_contacts(
    serial_port: str,
    debug: bool,
    baudrate: int,
    output: str,
    sniff_active: bool = False,
    sniff_keys: list | None = None,
) -> None:
    """Show all contacts."""
    try:
        scanner = MeshScanner(serial_port, debug=debug)
        await scanner.connect()

        if sniff_active:
            await scanner.start_sniff(sniff_keys or [])

        contacts = await scanner.get_all_contacts()

        if output == "json":
            click.echo(json.dumps(contacts, indent=2, sort_keys=True))
        elif output == "yaml":
            click.echo(yaml.dump(contacts, allow_unicode=True, sort_keys=True), nl=False)
        else:
            _print_contacts_table(contacts)

        await scanner.disconnect()

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


def _print_contacts_table(contacts: dict[str, Any]) -> None:
    """Render contacts as a rich table."""
    console = Console()

    table = Table(title=f"Contacts ({len(contacts)} total)", show_lines=False)
    table.add_column("Name", style="bold cyan", no_wrap=True)
    table.add_column("Public Key", style="dim")
    table.add_column("Type", justify="center")
    table.add_column("Path Len", justify="right")
    table.add_column("Lat", justify="right")
    table.add_column("Lon", justify="right")
    table.add_column("Last Advert", style="dim")

    def _path_sort_key(kv: tuple) -> int:
        v = kv[1].get("out_path_len")
        if v is None or v == -1:
            return 1000
        return v

    sorted_contacts = sorted(contacts.items(), key=_path_sort_key)

    for pubkey, contact in sorted_contacts:
        name = contact.get("adv_name") or ""
        ctype = contact.get("type", 0)
        type_label = {1: "contact", 2: "repeater", 3: "chatroom"}.get(ctype, str(ctype))
        path_len = contact.get("out_path_len")
        path_str = "flood" if path_len == -1 else (str(path_len) if path_len is not None else "")
        lat = contact.get("adv_lat")
        lon = contact.get("adv_lon")
        lat_str = f"{lat:.5f}" if lat is not None else ""
        lon_str = f"{lon:.5f}" if lon is not None else ""
        ts = contact.get("last_advert")
        last_advert = datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d %H:%M:%S") if ts else ""

        table.add_row(
            name,
            f"{pubkey[:16]}…",
            type_label,
            path_str,
            lat_str,
            lon_str,
            str(last_advert),
        )

    console.print(table)

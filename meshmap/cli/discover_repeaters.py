"""discover-repeaters command - find 0-hop repeaters via active node discovery."""

import asyncio
import json
import sys
from datetime import UTC, datetime
from typing import Any

import click
import yaml
from rich.console import Console
from rich.table import Table
from rich.text import Text

from meshmap.models import snr_color
from meshmap.scanner import MeshScanner


@click.command()
@click.pass_context
@click.option(
    '--output', '-o',
    type=click.Choice(['table', 'json', 'yaml'], case_sensitive=False),
    default='table',
    show_default=True,
    help='Output format.'
)
@click.option(
    '--wait', '-w',
    default=10,
    show_default=True,
    type=int,
    help='Seconds to listen for discovery responses.'
)
def discover_repeaters(ctx, output: str, wait: int):
    """Discover repeaters reachable at 0 hops (directly connected).

    Sends a NODE_DISCOVER_REQ control packet and collects responses from
    nearby repeaters for WAIT seconds.
    """
    asyncio.run(_discover_repeaters(
        ctx.obj['serial_port'],
        ctx.obj['debug'],
        ctx.obj['baudrate'],
        output,
        wait,
        ctx.obj.get('sniff_active', False),
        ctx.obj.get('sniff_keys', []),
    ))


async def _discover_repeaters(
    serial_port: str,
    debug: bool,
    baudrate: int,
    output: str,
    wait: int,
    sniff_active: bool = False,
    sniff_keys: list | None = None,
) -> None:
    try:
        scanner = MeshScanner(serial_port, debug=debug)
        await scanner.connect()

        # Load contacts first so the sniffer attaches instantly (no blocking
        # ensure_contacts call inside attach()) and is active before we send
        # the discovery request.
        await scanner.get_all_contacts()

        if sniff_active:
            await scanner.start_sniff(sniff_keys or [])

        repeaters = await scanner.discover_zero_hop_repeaters(wait_time=wait)

        if output == 'json':
            click.echo(json.dumps(repeaters, indent=2))
        elif output == 'yaml':
            click.echo(yaml.dump(repeaters, allow_unicode=True), nl=False)
        else:
            _print_table(repeaters)

        await scanner.disconnect()

    except KeyboardInterrupt:
        click.echo("\nInterrupted.")
        sys.exit(130)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _print_table(repeaters: list[dict[str, Any]]) -> None:
    console = Console()
    table = Table(title=f"0-hop repeaters ({len(repeaters)} found)", show_lines=False)
    table.add_column("Name", style="bold cyan", no_wrap=True)
    table.add_column("Public Key", style="dim")
    table.add_column("SNR", justify="right", no_wrap=True)
    table.add_column("Lat", justify="right")
    table.add_column("Lon", justify="right")
    table.add_column("Last Advert", style="dim")

    repeaters_sorted = sorted(
        repeaters,
        key=lambda r: r.get('snr') or float('-inf'),
        reverse=True,
    )

    for node in repeaters_sorted:
        lat = node.get('lat')
        lon = node.get('lon')
        ts = node.get('last_advert')
        last_advert = (
            datetime.fromtimestamp(ts, tz=UTC).strftime('%Y-%m-%d %H:%M:%S') if ts else ''
        )
        snr = node.get('snr')
        if snr is not None:
            sc = snr_color(snr)
            snr_cell = Text(f"{snr:+.1f} dB", style=sc)
        else:
            snr_cell = Text('—', style='dim')

        table.add_row(
            node.get('name') or '',
            f"{node['public_key'][:16]}…",
            snr_cell,
            f"{lat:.5f}" if lat is not None else '',
            f"{lon:.5f}" if lon is not None else '',
            last_advert,
        )

    console.print(table)

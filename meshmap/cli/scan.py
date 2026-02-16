"""Scan command - discover 0-hop nodes."""

import asyncio
import sys

import click

from meshmap.scanner import MeshScanner


@click.command()
@click.pass_context
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def scan(ctx, verbose: bool):
    """Scan for 0-hop nodes (default operation)."""
    asyncio.run(scan_zero_hop(
        ctx.obj['serial_port'],
        ctx.obj['debug'],
        ctx.obj['baudrate'],
        verbose,
        ctx.obj.get('sniff_active', False),
        ctx.obj.get('sniff_keys', []),
    ))


async def scan_zero_hop(
    serial_port: str,
    debug: bool,
    baudrate: int,
    verbose: bool,
    sniff_active: bool = False,
    sniff_keys: list | None = None,
) -> None:
    """Scan for 0-hop nodes."""
    try:
        scanner = MeshScanner(serial_port, debug=debug)
        await scanner.connect()

        if sniff_active:
            await scanner.start_sniff(sniff_keys or [])

        nodes = await scanner.scan_zero_hop_nodes()

        click.echo("\n" + "=" * 50)
        click.echo(f"Scan complete! Found {len(nodes)} 0-hop node(s).")
        click.echo("=" * 50)

        if verbose and nodes:
            click.echo("\nNode details:")
            for node in nodes:
                click.echo(f"\n  Node: {node['name']}")
                click.echo(f"    Type: {node['type']}")
                click.echo(f"    Public Key: {node['public_key'][:16]}...")
                click.echo(f"    Out Path Length: {node['out_path_len']}")
                click.echo(f"    Last Advert: {node['last_advert']}")
                click.echo(f"    Lat/Lon: {node['lat']}, {node['lon']}")

        await scanner.disconnect()

    except KeyboardInterrupt:
        click.echo("\n\nScan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        click.echo(f"\nError: {e}", err=True)
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

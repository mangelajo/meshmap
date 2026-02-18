"""RF-discover command - find nearby nodes by listening to RF activity."""

import asyncio
import json
import sys

import click

from meshmap.scanner import MeshScanner


@click.command()
@click.argument("duration", type=int)
@click.pass_context
def rf_discovery(ctx, duration: int):
    """Discover nearby nodes by listening to RF activity for DURATION seconds."""
    asyncio.run(
        do_rf_discovery(ctx.obj["serial_port"], ctx.obj["debug"], ctx.obj["baudrate"], duration)
    )


async def do_rf_discovery(serial_port: str, debug: bool, baudrate: int, duration: int) -> None:
    """Discover nearby nodes by RF activity."""
    try:
        scanner = MeshScanner(serial_port, debug=debug)
        await scanner.connect()

        results = await scanner.discover_by_rf_activity(duration=duration)
        click.echo("\n" + "=" * 50)
        click.echo("RF Discovery Results:")
        click.echo("=" * 50)
        click.echo(json.dumps(results, indent=2, sort_keys=True, default=str))

        await scanner.disconnect()

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

"""Sniff command - capture and decode RF packets."""

import asyncio
import sys
from pathlib import Path

import click

from meshmap.scanner import MeshScanner
from meshmap.sniffer import PacketSniffer


@click.command()
@click.argument('duration', type=int)
@click.option(
    '--decrypt', '-k',
    'keyfiles',
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help='Path to private key file for decrypting packets (can be used multiple times)'
)
@click.option(
    '--channel', '-c',
    'channels',
    multiple=True,
    help='Channel name to decrypt (e.g., #general, #public). Can be used multiple times.'
)
@click.option(
    '--hexdump/--no-hexdump', '-x',
    default=False,
    help='Show hexdump of decrypted payloads'
)
@click.pass_context
def sniff(ctx, duration: int, keyfiles: tuple[Path, ...], channels: tuple[str, ...], hexdump: bool):
    """Sniff and decode RF packets for DURATION seconds.

    Examples:

        \b
        meshmap -p /dev/ttyUSB0 sniff 60
        meshmap -p /dev/ttyUSB0 sniff 60 -k mykey.txt -c '#general' -c '#public'
        meshmap -p /dev/ttyUSB0 sniff 60 -k key1.txt -k key2.txt --hexdump
    """
    asyncio.run(do_sniff(
        ctx.obj['serial_port'],
        ctx.obj['debug'],
        ctx.obj['baudrate'],
        duration,
        list(keyfiles),
        list(channels),
        hexdump
    ))


async def do_sniff(
    serial_port: str,
    debug: bool,
    baudrate: int,
    duration: int,
    keyfiles: list[Path],
    channels: list[str],
    hexdump: bool
) -> None:
    """Sniff and decode RF packets."""
    try:
        scanner = MeshScanner(serial_port, debug=debug)
        await scanner.connect()

        private_keys = []
        for keyfile in keyfiles:
            try:
                private_key_hex = keyfile.read_text().strip()

                if len(private_key_hex) != 128:
                    click.echo(
                        f"Error: Invalid private key length in {keyfile}. "
                        f"Expected 128 hex chars, got {len(private_key_hex)}",
                        err=True
                    )
                    sys.exit(1)

                if not all(c in '0123456789abcdefABCDEF' for c in private_key_hex):
                    click.echo(
                        f"Error: Invalid private key format in {keyfile}. Must be hexadecimal.",
                        err=True
                    )
                    sys.exit(1)

                private_keys.append({
                    'hex': private_key_hex,
                    'file': str(keyfile)
                })

            except FileNotFoundError:
                click.echo(f"Error: Private key file not found: {keyfile}", err=True)
                sys.exit(1)
            except Exception as e:
                click.echo(f"Error loading private key from {keyfile}: {e}", err=True)
                sys.exit(1)

        if private_keys:
            click.echo(f"🔑 Loaded {len(private_keys)} private key(s):")
            for key_info in private_keys:
                click.echo(f"   - {key_info['file']}")

        channel_names = list(channels) if channels else []
        if channel_names:
            click.echo(
                f"📻 Will attempt to decrypt {len(channel_names)} channel(s): "
                f"{', '.join(channel_names)}"
            )

        if scanner.mesh:
            sniffer = PacketSniffer(scanner.mesh, debug=debug)
            await sniffer.sniff(
                duration=duration,
                private_keys=private_keys if private_keys else None,
                channel_names=channel_names if channel_names else None,
                show_hexdump=hexdump
            )

        await scanner.disconnect()

    except KeyboardInterrupt:
        click.echo("\n\nSniffing interrupted by user.")
        sys.exit(130)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

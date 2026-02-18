"""Command-line interface for meshmap using Click."""

import asyncio
import sys
from pathlib import Path

import click

from .contacts import all_contacts
from .discover_repeaters import discover_repeaters
from .explore import explore
from .export_key import export_key
from .get_neighbours import get_neighbours_cmd
from .guest_login import guest_login
from .rf_discover import rf_discovery
from .scan import scan, scan_zero_hop
from .sniff import sniff


def _load_sniff_keys(keyfiles: tuple) -> list[dict[str, str]]:
    """Validate and load private key files for packet decryption."""
    private_keys = []
    for keyfile in keyfiles:
        try:
            key_hex = Path(keyfile).read_text().strip()
        except Exception as exc:
            raise click.BadParameter(f"Cannot read key file {keyfile}: {exc}") from exc

        if len(key_hex) != 128 or not all(c in "0123456789abcdefABCDEF" for c in key_hex):
            raise click.BadParameter(
                f"{keyfile}: expected 128 hex characters (64-byte Ed25519 key), "
                f"got {len(key_hex)} characters"
            )
        private_keys.append({"hex": key_hex, "file": str(keyfile)})
    return private_keys


@click.group(invoke_without_command=True)
@click.option(
    "--serial-port",
    "-p",
    required=True,
    type=str,
    help="Serial port to connect to (e.g., /dev/ttyUSB0 or COM3)",
)
@click.option(
    "--debug/--no-debug", "-d", default=False, help="Enable low-level debug logging from meshcore"
)
@click.option(
    "--verbose/--no-verbose", "-v", default=False, help="Print progress messages to stderr"
)
@click.option("--baudrate", "-b", default=115200, type=int, help="Serial port baud rate")
@click.option(
    "--sniff",
    "sniff_active",
    is_flag=True,
    default=False,
    help="Print RF packets in real-time while the command runs.",
)
@click.option(
    "--sniff-key",
    "sniff_keyfiles",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Private key file for packet decryption (can be repeated).",
)
@click.pass_context
def cli(
    ctx,
    serial_port: str,
    debug: bool,
    verbose: bool,
    baudrate: int,
    sniff_active: bool,
    sniff_keyfiles: tuple,
) -> None:
    """Scan and map meshcore network graphs.

    By default, scans for 0-hop nodes. Use subcommands for other operations.
    """
    ctx.ensure_object(dict)
    ctx.obj["serial_port"] = serial_port
    ctx.obj["debug"] = debug
    ctx.obj["verbose"] = verbose
    ctx.obj["baudrate"] = baudrate
    ctx.obj["sniff_active"] = sniff_active
    ctx.obj["sniff_keys"] = _load_sniff_keys(sniff_keyfiles) if sniff_keyfiles else []

    if ctx.invoked_subcommand is None:
        asyncio.run(
            scan_zero_hop(
                serial_port,
                debug,
                baudrate,
                verbose=False,
                sniff_active=sniff_active,
                sniff_keys=ctx.obj["sniff_keys"],
            )
        )


cli.add_command(scan)
cli.add_command(all_contacts, name="contacts")
cli.add_command(discover_repeaters, name="discover-repeaters")
cli.add_command(explore)
cli.add_command(get_neighbours_cmd, name="get-neighbours")
cli.add_command(guest_login, name="guest-login")
cli.add_command(rf_discovery, name="rf-discover")
cli.add_command(sniff)
cli.add_command(export_key, name="export-key")


def main() -> int:
    """Main entry point for the meshmap CLI."""
    try:
        cli(obj={})
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    except Exception:
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

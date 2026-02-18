"""Export-key command - export the device's private key to a file."""

import asyncio
import sys
from pathlib import Path

import click
import nacl.bindings

from meshmap.scanner import MeshScanner


@click.command()
@click.argument("output_file", type=click.Path(path_type=Path))
@click.pass_context
def export_key(ctx, output_file: Path):
    """Export private key from connected device to OUTPUT_FILE.

    Requires serial connection. The exported key can be used with the sniff command.
    """
    asyncio.run(
        do_export_key(ctx.obj["serial_port"], ctx.obj["debug"], ctx.obj["baudrate"], output_file)
    )


async def do_export_key(serial_port: str, debug: bool, baudrate: int, output_file: Path) -> None:
    """Export private key from device."""
    try:
        scanner = MeshScanner(serial_port, debug=debug)
        await scanner.connect()

        if not scanner.mesh:
            click.echo("Error: Not connected to mesh", err=True)
            sys.exit(1)

        click.echo("🔑 Exporting private key from device...")

        result = await scanner.mesh.commands.export_private_key()

        if result.type.value == "private_key":
            private_key_bytes = result.payload["private_key"]
            private_key_hex = private_key_bytes.hex()

            output_file.write_text(private_key_hex)

            click.echo(f"✅ Private key exported to {output_file}")
            click.echo(
                f"   Key length: {len(private_key_hex)} chars ({len(private_key_bytes)} bytes)"
            )

            if len(private_key_bytes) == 64:
                scalar = private_key_bytes[:32]
                derived_pubkey = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(scalar)
                derived_pubkey_hex = derived_pubkey.hex()

                self_pubkey = scanner.mesh.self_info.get("public_key", "")
                if derived_pubkey_hex.lower() == self_pubkey.lower():
                    click.secho(
                        "✅ Key verification: Derived public key matches device!", fg="green"
                    )
                    click.echo(f"   Device public key: {self_pubkey[:16]}...{self_pubkey[-16:]}")
                else:
                    click.secho(
                        "⚠️  Warning: Derived public key doesn't match device public key",
                        fg="yellow",
                    )
                    click.echo(
                        f"   Derived: {derived_pubkey_hex[:16]}...{derived_pubkey_hex[-16:]}"
                    )
                    click.echo(f"   Device:  {self_pubkey[:16]}...{self_pubkey[-16:]}")

        elif result.type.value == "disabled":
            click.echo("❌ Private key export is disabled on this device", err=True)
            click.echo(f"   Reason: {result.payload.get('reason', 'unknown')}")
            await scanner.disconnect()
            sys.exit(1)
        else:
            click.echo("❌ Failed to export key", err=True)
            click.echo(f"   Response type: {result.type.value}")
            click.echo(f"   Payload: {result.payload}")
            await scanner.disconnect()
            sys.exit(1)

        await scanner.disconnect()

    except Exception as e:
        click.echo(f"Error exporting key: {e}", err=True)
        if debug:
            import traceback

            traceback.print_exc()
        sys.exit(1)

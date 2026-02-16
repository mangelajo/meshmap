"""Guest-login command - access a repeater's neighbor list."""

import asyncio
import json
import sys

import click

from meshmap.scanner import MeshScanner


@click.command()
@click.argument('contact_name')
@click.pass_context
def guest_login(ctx, contact_name: str):
    """Guest login to a contact and get its neighbor list.

    Search by name or public key prefix.
    """
    asyncio.run(do_guest_login(
        ctx.obj['serial_port'],
        ctx.obj['debug'],
        ctx.obj['baudrate'],
        contact_name,
        ctx.obj.get('sniff_active', False),
        ctx.obj.get('sniff_keys', []),
    ))


async def do_guest_login(
    serial_port: str,
    debug: bool,
    baudrate: int,
    contact_name: str,
    sniff_active: bool = False,
    sniff_keys: list | None = None,
) -> None:
    """Guest login to a contact."""
    try:
        scanner = MeshScanner(serial_port, debug=debug)
        await scanner.connect()

        if sniff_active:
            await scanner.start_sniff(sniff_keys or [])

        contacts = await scanner.get_all_contacts()

        target_contact = None
        for pk, contact in contacts.items():
            name = contact.get('adv_name', '')
            if contact_name.lower() in name.lower() or contact_name.lower() in pk.lower():
                target_contact = contact
                break

        if not target_contact:
            click.echo(f"\n✗ Contact '{contact_name}' not found in contact list.")
            click.echo("Available contacts:")
            for pk, contact in contacts.items():
                click.echo(f"  - {contact.get('adv_name')} ({pk[:16]}...)")
            await scanner.disconnect()
            sys.exit(1)

        result = await scanner.guest_login_and_get_neighbors(target_contact)

        if result:
            click.echo("\n" + "=" * 50)
            click.echo("Guest login results:")
            click.echo("=" * 50)
            click.echo(json.dumps(result, indent=2, sort_keys=True, default=str))

        await scanner.disconnect()

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

"""Neighbour discovery - login to a contact and retrieve its neighbour list."""

import asyncio
from typing import Any

import click
import meshcore
from meshcore.events import EventType


async def get_neighbours(
    serial_port: str,
    baudrate: int,
    debug: bool,
    contact_name: str,
    password: str = "",
    verbose: bool = False,
    sniff_keys: list[dict[str, str]] | None = None,
    sniff_channels: list[str] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Connect, find a contact, login, and return its neighbours.

    Args:
        serial_port: Path to serial port.
        baudrate: Serial baud rate.
        debug: Enable meshcore debug logging.
        contact_name: Name or public-key prefix to search for.
        password: Login password (empty string for guest access).

    Returns:
        (contact, neighbours) where neighbours is a list of dicts with keys:
            pubkey, secs_ago, snr

    Raises:
        ValueError: If the contact is not found.
        RuntimeError: If the neighbour request fails.
    """
    from meshmap.sniffer import PacketSniffer

    def _log(msg: str) -> None:
        if verbose:
            click.echo(msg, err=True)

    _log(f"Connecting to {serial_port}...")
    mesh = await meshcore.MeshCore.create_serial(
        port=serial_port, baudrate=baudrate, debug=debug
    )
    _log("Connected.")

    sniffer = None
    try:
        _log("Loading contacts...")
        await mesh.ensure_contacts()
        _log(f"  {len(mesh.contacts)} contacts loaded.")

        if sniff_keys or sniff_channels:
            _log("Attaching packet sniffer...")
            sniffer = PacketSniffer(mesh, debug=debug)
            await sniffer.attach(sniff_keys, sniff_channels)
            _log("  Sniffer active.")

        contact = _find_contact(mesh.contacts, contact_name)
        name = contact.get("adv_name", "?")
        ctype = {1: "contact", 2: "repeater", 3: "chatroom"}.get(contact.get("type", 0), "unknown")
        path_len = contact.get("out_path_len", -1)
        pubkey_prefix = contact.get("public_key", "")[:16]
        _log(f"Found: {name!r}  type={ctype}  path_len={path_len}  key={pubkey_prefix}…")

        _login_attempts = 3
        _fetch_attempts = 3
        pw_label = f"password={password!r}" if password else "guest (no password)"

        # --- Login phase ---
        logged_in = False
        for attempt in range(1, _login_attempts + 1):
            _log(f"Login attempt {attempt}/{_login_attempts} as {pw_label}...")
            login_event = await mesh.commands.send_login(contact, password)
            _log(f"  Login send: {login_event.type.name if login_event else 'None'}")
            if login_event and login_event.type == EventType.ERROR:
                _log(f"  Login send failed: {login_event.payload}")
                if attempt < _login_attempts:
                    _log("  Retrying in 2 s...")
                    await asyncio.sleep(2)
                continue
            _log("  Waiting for LOGIN_SUCCESS / LOGIN_FAILED (10 s)...")
            t_ok = asyncio.create_task(
                mesh.wait_for_event(EventType.LOGIN_SUCCESS, timeout=10)
            )
            t_fail = asyncio.create_task(
                mesh.wait_for_event(EventType.LOGIN_FAILED, timeout=10)
            )
            done, pending = await asyncio.wait(
                {t_ok, t_fail}, return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()

            if t_fail in done and t_fail.result() is not None:
                _log("  Login rejected (LOGIN_FAILED).")
            elif t_ok in done and t_ok.result() is not None:
                _log("  Login accepted.")
                logged_in = True
                break
            else:
                _log("  No LOGIN_SUCCESS received (timeout).")
            if attempt < _login_attempts:
                _log("  Retrying in 2 s...")
                await asyncio.sleep(2)

        if not logged_in:
            raise RuntimeError(f"Could not log in to {name!r} after {_login_attempts} attempt(s)")

        # --- Fetch phase ---
        result = None
        try:
            for attempt in range(1, _fetch_attempts + 1):
                _log(f"Fetching neighbours (attempt {attempt}/{_fetch_attempts}, timeout=30 s, min=15 s)...")
                result = await mesh.commands.fetch_all_neighbours(
                    contact, timeout=30, min_timeout=15
                )
                if result is not None:
                    break
                if attempt < _fetch_attempts:
                    _log("  Timed out — retrying in 2 s...")
                    await asyncio.sleep(2)
        finally:
            _log("Logging out...")
            await mesh.commands.send_logout(contact)
            _log("  Logged out.")

        if result is None:
            raise RuntimeError(
                f"No neighbour response from {name!r} after {_fetch_attempts} attempt(s)"
            )

        neighbours = result.get("neighbours", [])
        _resolve_names(neighbours, mesh.contacts)
        neighbours.sort(key=lambda nb: nb.get("snr") or float("-inf"), reverse=True)
        _log(
            f"Got {len(neighbours)} neighbours "
            f"(total reported: {result.get('neighbours_count', '?')})."
        )
        return contact, neighbours
    finally:
        if sniffer is not None:
            sniffer.detach()
        await mesh.disconnect()


def _resolve_names(neighbours: list[dict[str, Any]], contacts: dict[str, Any]) -> None:
    """Add 'name', 'lat', 'lon' to each neighbour by prefix-matching its pubkey against contacts."""
    for nb in neighbours:
        prefix = nb.get("pubkey", "").lower()
        nb["name"] = None
        nb["lat"] = None
        nb["lon"] = None
        if not prefix:
            continue
        for pk, c in contacts.items():
            if pk.lower().startswith(prefix):
                nb["name"] = c.get("adv_name")
                nb["lat"] = c.get("adv_lat")
                nb["lon"] = c.get("adv_lon")
                break


def _find_contact(contacts: dict[str, Any], query: str) -> dict[str, Any]:
    """Return the first contact whose name or public key contains *query*."""
    query_lower = query.lower()
    for pubkey, contact in contacts.items():
        name = contact.get("adv_name", "")
        if query_lower in name.lower() or query_lower in pubkey.lower():
            return contact

    looks_like_pubkey = all(c in "0123456789abcdef" for c in query_lower)
    if looks_like_pubkey:
        raise ValueError(
            f"No contact with pubkey prefix '{query}' found in local contact list "
            f"({len(contacts)} contacts). "
            f"Communicating with a node requires its full public key (for encryption and routing). "
            f"The node must broadcast an advertisement before this device can add it as a contact. "
            f"Wait for it to advertise, or run 'rf-discover' to request advertisements from nearby nodes."
        )

    available = ", ".join(
        f"{c.get('adv_name')} ({pk[:12]}…)" for pk, c in contacts.items()
    )
    raise ValueError(
        f"Contact '{query}' not found. Available contacts: {available}"
    )

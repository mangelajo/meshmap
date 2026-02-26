"""Packet sniffing and display utilities for meshcore networks."""

import asyncio
from datetime import datetime
from typing import Any

import meshcore
from meshcore.events import EventType
from rich.console import Console
from rich.panel import Panel

from meshmap import crypto, decoder
from meshmap.models import snr_color


class PacketSniffer:
    """Sniff and decode RF packets from meshcore networks."""

    def __init__(self, mesh: meshcore.MeshCore, debug: bool = False, graph: object | None = None):
        """Initialize the packet sniffer.

        Args:
            mesh: MeshCore instance to sniff packets from
            debug: Enable debug output (default: False)
            graph: Optional MeshGraph instance for updating nodes from ADVERT packets
        """
        self.mesh = mesh
        self.debug = debug
        self.graph = graph
        self.console = Console()
        self._subscription: Any = None
        self._packet_count: int = 0
        self._contact_map: dict[str, str] = {}

    def _render_decrypted(self, decoded: decoder.DecodedPacket, show_hexdump: bool) -> list[str]:
        """Render decrypted content from a fully-populated DecodedPacket.

        All data is read exclusively from the model; no dict access here.

        Args:
            decoded: DecodedPacket with decryption fields populated
            show_hexdump: Whether to include a hex dump of the plaintext

        Returns:
            List of Rich-formatted strings to append to the output panel
        """
        lines: list[str] = []

        lines.append(f"[green]Decrypted:[/green] [dim](using {decoded.decrypted_by})[/dim]")

        if decoded.src_name:
            lines.append(f"  [dim]From:[/dim] [green]{decoded.src_name}[/green]")

        if decoded.decrypted_datetime:
            lines.append(f"  [dim]Time:[/dim] {decoded.decrypted_datetime}")

        # TXT_MSG fields
        if decoded.txt_type_name:
            attempt = decoded.txt_attempt or 0
            lines.append(
                f"  [dim]TXT Type:[/dim] [cyan]{decoded.txt_type_name}[/cyan] "
                f"[dim](attempt {attempt})[/dim]"
            )
            if decoded.txt_signed_sender_prefix:
                lines.append(
                    f"  [dim]Signed Sender:[/dim] "
                    f"[yellow]{decoded.txt_signed_sender_prefix}[/yellow]"
                )

        # REQ fields
        if decoded.req_type_name:
            lines.append(f"  [dim]Request Type:[/dim] [cyan]{decoded.req_type_name}[/cyan]")
            if decoded.req_data_hex:
                lines.append(f"  [dim]Request Data:[/dim] {len(decoded.req_data_hex) // 2} bytes")
                for line in decoder.format_hexdump(bytes.fromhex(decoded.req_data_hex)).split("\n"):
                    lines.append(f"    [dim]{line}[/dim]")

        # RESPONSE fields
        if decoded.resp_data_hex:
            lines.append(f"  [dim]Response Data:[/dim] {len(decoded.resp_data_hex) // 2} bytes")
            for line in decoder.format_hexdump(bytes.fromhex(decoded.resp_data_hex)).split("\n"):
                lines.append(f"    [dim]{line}[/dim]")

        # GET_NEIGHBORS fields
        if decoded.resp_neighbours_list:
            total = decoded.resp_neighbours_total_count or 0
            count = decoded.resp_neighbours_results_count or 0
            lines.append(f"  [dim]Neighbors:[/dim] {count} of {total} total")
            for nb in decoded.resp_neighbours_list:
                secs = nb["heard_seconds_ago"]
                if secs < 60:
                    time_str = f"{secs}s ago"
                elif secs < 3600:
                    time_str = f"{secs // 60}m ago"
                elif secs < 86400:
                    time_str = f"{secs // 3600}h ago"
                else:
                    time_str = f"{secs // 86400}d ago"

                snr = nb["snr"]
                sc = snr_color(snr)

                line = (
                    f"    [yellow]{nb['pubkey']:8s}[/yellow] - "
                    f"{time_str:8s} - "
                    f"SNR [{sc}]{snr:6.2f}[/{sc}] dB"
                )
                if nb.get("name"):
                    line += f" - [cyan]{nb['name']}[/cyan]"
                lines.append(line)

        # PATH fields
        if decoded.path_return_len is not None:
            lines.append(f"  [dim]Return Path Length:[/dim] {decoded.path_return_len} hops")
            if decoded.path_return_hops:
                hops = ", ".join(decoded.path_return_hops)
                lines.append(f"  [dim]Return Path:[/dim] [yellow]{hops}[/yellow]")
            if decoded.path_extra_type_name:
                lines.append(
                    f"  [dim]Extra Type:[/dim] [cyan]{decoded.path_extra_type_name}[/cyan]"
                )
                if decoded.path_extra_ack_crc:
                    lines.append(f"    [dim]ACK CRC:[/dim] {decoded.path_extra_ack_crc}")

        # ANON_REQ fields
        if decoded.anon_password:
            lines.append(f"  [dim]Password:[/dim] [yellow]{decoded.anon_password}[/yellow]")
            if decoded.anon_room_sync_since:
                lines.append(f"  [dim]Sync Since:[/dim] {decoded.anon_room_sync_since}")

        # GRP_TXT / GRP_DATA fields
        if decoded.channel_name:
            lines.append(f"  [dim]Channel:[/dim] [cyan]{decoded.channel_name}[/cyan]")
        if decoded.grp_txt_type_name:
            lines.append(f"  [dim]TXT Type:[/dim] [cyan]{decoded.grp_txt_type_name}[/cyan]")
        if decoded.grp_sender_name:
            lines.append(f"  [dim]From:[/dim] [green]{decoded.grp_sender_name}[/green]")
        if decoded.grp_timestamp:
            try:
                ts_str = datetime.fromtimestamp(decoded.grp_timestamp).strftime("%Y-%m-%d %H:%M:%S")
                lines.append(f"  [dim]Time:[/dim] {ts_str}")
            except (ValueError, OSError):
                pass

        # Plaintext message (TXT_MSG or GRP_TXT)
        if decoded.txt_plaintext_message:
            msg = decoded.txt_plaintext_message
            if len(msg) > 200:
                msg = msg[:200] + "..."
            lines.append(f"  [dim]Message:[/dim] {msg}")
        elif decoded.grp_message_text:
            msg = decoded.grp_message_text
            if len(msg) > 200:
                msg = msg[:200] + "..."
            lines.append(f"  [dim]Message:[/dim] {msg}")

        # Hexdump of decrypted plaintext
        if show_hexdump and decoded.decrypted_plaintext_hex:
            plaintext_bytes = bytes.fromhex(decoded.decrypted_plaintext_hex)
            lines.append("  [dim]Hexdump:[/dim]")
            for line in decoder.format_hexdump(plaintext_bytes).split("\n"):
                lines.append(f"    [dim]{line}[/dim]")

        return lines

    async def attach(
        self,
        private_keys: list[dict[str, str]] | None,
        channel_names: list[str] | None,
        show_hexdump: bool = False,
    ) -> None:
        """Load contacts and begin listening for RF packets in the background.

        Packets are printed to the console as they arrive.
        Call detach() to stop.  Use sniff() for standalone timed sniffing.

        Args:
            private_keys: Optional list of dicts with 'hex' and 'file' keys for decryption
            channel_names: Optional channel names for group message decryption
            show_hexdump: Show hexdump of decrypted payloads
        """
        await self.mesh.ensure_contacts()
        contacts = self.mesh.contacts

        self._contact_map = {}
        for public_key, contact in contacts.items():
            name = contact.get("adv_name", "Unknown")
            if len(public_key) >= 8:
                self._contact_map[public_key[:8].lower()] = name

        self._packet_count = 0
        contact_map = self._contact_map  # local alias for the closure

        async def on_packet(event: Any) -> None:
            """Handle received packet."""
            self._packet_count += 1

            data = event.payload
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            # Build packet info display
            output = []

            # Signal info with color coding
            rssi = data.get("rssi", 0)
            snr = data.get("snr", 0)
            rssi_color = "green" if rssi > -80 else "yellow" if rssi > -100 else "red"
            sc = snr_color(snr)
            output.append(
                f"[dim]Signal:[/dim] RSSI=[{rssi_color}]{rssi}[/{rssi_color}] dBm, "
                f"SNR=[{sc}]{snr}[/{sc}] dB"
            )

            raw_hex = data.get("raw_hex", "")
            payload_len = data.get("payload_length", 0)
            output.append(f"[dim]Length:[/dim] {payload_len} bytes")

            # Extract actual mesh packet (skip SNR and RSSI bytes)
            # raw_hex format from RX_LOG_DATA: [SNR:1byte][RSSI:1byte][mesh_packet:...]
            # We need to skip first 2 bytes (4 hex characters)
            if len(raw_hex) >= 4:
                packet_hex = raw_hex[4:]  # Skip SNR+RSSI
            else:
                packet_hex = raw_hex

            # Try to decode the mesh packet
            decoded = decoder.decode_packet(packet_hex, contact_map)

            # Show header breakdown
            if decoded.header_hex:
                output.append(f"[dim]Header:[/dim] [cyan]{decoded.header_hex}[/cyan]")

            # Show route type
            if decoded.route_type:
                route_color = "blue" if "DIRECT" in decoded.route_type else "magenta"
                output.append(
                    f"  [dim]Route:[/dim]   [{route_color}]{decoded.route_type}[/{route_color}]"
                )

            # Show payload type
            if decoded.payload_type:
                ptype = decoded.payload_type
                type_colors = {
                    "ADVERT": "yellow",
                    "TXT_MSG": "green",
                    "GRP_TXT": "cyan",
                    "REQ": "blue",
                    "RESPONSE": "blue",
                    "ACK": "dim",
                }
                type_color = type_colors.get(ptype, "white")
                output.append(f"  [dim]Type:[/dim]    [{type_color}]{ptype}[/{type_color}]")

            # Show payload version
            if decoded.payload_ver is not None:
                output.append(f"  [dim]Version:[/dim] {decoded.payload_ver}")

            # Show transport codes if present
            if decoded.transport_codes:
                codes = ", ".join(decoded.transport_codes)
                output.append(f"[dim]Transport codes:[/dim] {codes}")

            # Show path information
            if decoded.path_len is not None:
                output.append(f"[dim]Path:[/dim] {decoded.path_len} hops")
                if decoded.path_hops:
                    # Display each hop with matching contacts
                    for i, hop_info in enumerate(decoded.path_hops, 1):
                        hop_hash = hop_info.hash
                        contacts_list = hop_info.contacts

                        if contacts_list:
                            # Show contact names
                            contact_names = ", ".join(contacts_list)
                            if len(contacts_list) > 1:
                                matches_text = f"[dim]({len(contacts_list)} matches)[/dim]"
                                output.append(
                                    f"  Hop {i}: [yellow]{hop_hash}[/yellow] "
                                    f"[green]{contact_names}[/green] {matches_text}"
                                )
                            else:
                                output.append(
                                    f"  Hop {i}: [yellow]{hop_hash}[/yellow] "
                                    f"[green]{contact_names}[/green]"
                                )
                        else:
                            # No matching contact
                            output.append(
                                f"  Hop {i}: [yellow]{hop_hash}[/yellow] [dim](unknown)[/dim]"
                            )

            # Show source/destination addresses
            if decoded.src_hash or decoded.dest_hash:
                if decoded.src_hash:
                    src_display = f"[yellow]{decoded.src_hash}[/yellow]"
                    if decoded.src_name:
                        src_display += f" [green]{decoded.src_name}[/green]"
                    output.append(f"[dim]From:[/dim] {src_display}")

                if decoded.dest_hash:
                    dest_display = f"[yellow]{decoded.dest_hash}[/yellow]"
                    if decoded.dest_name:
                        dest_display += f" [green]{decoded.dest_name}[/green]"
                    output.append(f"[dim]To:[/dim]   {dest_display}")

            # Learn names from ADVERT packets
            if decoded.advert_pubkey and decoded.advert_name:
                key = decoded.advert_pubkey[:8].lower()
                if key not in contact_map:
                    contact_map[key] = decoded.advert_name

            # Update graph from ADVERT packets when graph is available
            if self.graph and decoded.advert_pubkey and decoded.advert_name:
                self.graph.upsert_node(
                    decoded.advert_pubkey,
                    decoded.advert_name,
                    decoded.advert_type.lower() if decoded.advert_type else "unknown",
                    decoded.advert_lat,
                    decoded.advert_lon,
                )

            # Show ADVERT details
            if decoded.advert_pubkey:
                pubkey_display = f"[yellow]{decoded.advert_pubkey}[/yellow]"
                if decoded.advert_contact_name:
                    pubkey_display += f" [green]{decoded.advert_contact_name}[/green]"
                output.append(f"[dim]ADVERT from:[/dim] {pubkey_display}")

                if decoded.advert_timestamp:
                    from datetime import datetime as dt

                    try:
                        ts_str = dt.fromtimestamp(decoded.advert_timestamp)
                        ts_formatted = ts_str.strftime("%Y-%m-%d %H:%M:%S")
                        output.append(f"  [dim]Timestamp:[/dim] {ts_formatted}")
                    except (ValueError, OSError):
                        ts_raw = decoded.advert_timestamp
                        output.append(f"  [dim]Timestamp:[/dim] {ts_raw} [red](invalid)[/red]")

                if decoded.advert_signature:
                    output.append(
                        f"  [dim]Signature:[/dim] [cyan]{decoded.advert_signature}[/cyan]"
                    )

                if decoded.advert_type:
                    output.append(f"  [dim]Type:[/dim] [cyan]{decoded.advert_type}[/cyan]")

                if decoded.advert_name:
                    output.append(f"  [dim]Name:[/dim] [green]{decoded.advert_name}[/green]")

                if decoded.advert_lat is not None:
                    lat = decoded.advert_lat
                    lon = decoded.advert_lon
                    output.append(f"  [dim]Location:[/dim] [yellow]{lat:.6f}, {lon:.6f}[/yellow]")

                if decoded.advert_extra1:
                    output.append(
                        f"  [dim]Extra1:[/dim] [cyan]0x{decoded.advert_extra1:04x}[/cyan]"
                    )

                if decoded.advert_extra2:
                    output.append(
                        f"  [dim]Extra2:[/dim] [cyan]0x{decoded.advert_extra2:04x}[/cyan]"
                    )

                if decoded.advert_app_data_len:
                    output.append(f"  [dim]App Data:[/dim] {decoded.advert_app_data_len} bytes")
                    if show_hexdump and decoded.advert_app_data_hex:
                        app_data_bytes = bytes.fromhex(decoded.advert_app_data_hex)
                        output.append("  [dim]App Data Hexdump:[/dim]")
                        for line in decoder.format_hexdump(app_data_bytes).split("\n"):
                            output.append(f"    [dim]{line}[/dim]")

            # Show ANON_REQ sender
            if decoded.anon_sender_pubkey:
                sender_display = f"[yellow]{decoded.anon_sender_pubkey}[/yellow]"
                if decoded.anon_sender_name:
                    sender_display += f" [green]{decoded.anon_sender_name}[/green]"
                output.append(f"[dim]Anon Sender:[/dim] {sender_display}")

            # Show ACK details
            if decoded.ack_crc:
                output.append(f"[dim]ACK CRC:[/dim] [cyan]{decoded.ack_crc}[/cyan]")

            # Show MULTIPART details
            if decoded.multipart_remaining is not None:
                output.append(
                    f"[dim]Multipart:[/dim] {decoded.multipart_remaining} remaining, "
                    f"type=[cyan]{decoded.multipart_type_name}[/cyan]"
                )
                if decoded.multipart_payload_hex:
                    payload_len = len(decoded.multipart_payload_hex) // 2
                    output.append(f"  [dim]Wrapped Payload:[/dim] {payload_len} bytes")

            # Show CONTROL details
            if decoded.control_type:
                zero_hop = " [yellow](zero-hop)[/yellow]" if decoded.control_is_zero_hop else ""
                subtype_str = f" [{decoded.control_subtype}]" if decoded.control_subtype else ""
                output.append(
                    f"[dim]Control Type:[/dim] [cyan]{decoded.control_type}[/cyan]"
                    f"{zero_hop}{subtype_str}"
                )

                # Show DISCOVER_REQ details
                if decoded.control_subtype == "DISCOVER_REQ":
                    if decoded.discover_tag:
                        output.append(
                            f"  [dim]Discovery Tag:[/dim] [cyan]{decoded.discover_tag}[/cyan]"
                        )
                    if decoded.discover_adv_types:
                        types_str = ", ".join(decoded.discover_adv_types)
                        output.append(f"  [dim]Looking for:[/dim] [yellow]{types_str}[/yellow]")
                    if decoded.discover_since_datetime:
                        output.append(f"  [dim]Since:[/dim] {decoded.discover_since_datetime}")

                # Show DISCOVER_RESP details
                elif decoded.control_subtype == "DISCOVER_RESP":
                    if decoded.discover_node_type:
                        output.append(
                            f"  [dim]Node Type:[/dim] [green]{decoded.discover_node_type}[/green]"
                        )
                    if decoded.discover_snr is not None:
                        sc = snr_color(decoded.discover_snr)
                        output.append(
                            f"  [dim]Reported SNR:[/dim] [{sc}]{decoded.discover_snr:.2f}[/{sc}] dB"
                        )
                    if decoded.discover_tag:
                        output.append(
                            f"  [dim]Discovery Tag:[/dim] [cyan]{decoded.discover_tag}[/cyan]"
                        )
                    if decoded.discover_pubkey:
                        key_type = "full key" if decoded.discover_pubkey_full else "prefix"
                        output.append(
                            f"  [dim]Public Key:[/dim] [yellow]{decoded.discover_pubkey}[/yellow] "
                            f"[dim]({key_type})[/dim]"
                        )
                        if decoded.discover_contact_name:
                            output.append(
                                f"  [dim]Contact:[/dim] [green]{decoded.discover_contact_name}[/green]"
                            )

                # Show raw control data if not a known sub-type
                if not decoded.control_subtype and decoded.control_data_hex:
                    data_len = len(decoded.control_data_hex) // 2
                    output.append(f"  [dim]Control Data:[/dim] {data_len} bytes")

            # Show TRACE details
            if decoded.trace_tag:
                output.append(f"[dim]Trace Tag:[/dim] [cyan]{decoded.trace_tag}[/cyan]")
            if decoded.trace_auth:
                output.append(f"[dim]Trace Auth:[/dim] [cyan]{decoded.trace_auth}[/cyan]")
            if decoded.trace_flags:
                output.append(f"[dim]Trace Flags:[/dim] [cyan]{decoded.trace_flags}[/cyan]")
                if decoded.trace_path_hash_size:
                    output.append(
                        f"  [dim]Path Hash Size:[/dim] {decoded.trace_path_hash_size} bytes"
                    )

            if decoded.trace_path_hashes:
                output.append("[dim]Trace Path Hashes:[/dim]")
                for i, hop_hash in enumerate(decoded.trace_path_hashes, 1):
                    output.append(f"  Hop {i}: [yellow]{hop_hash}[/yellow]")

            if decoded.trace_snr_values:
                snr_str = ", ".join(f"{snr:.1f} dB" for snr in decoded.trace_snr_values)
                output.append(f"[dim]Trace SNR Values:[/dim] [green]{snr_str}[/green]")

            if decoded.trace_path_data and not decoded.trace_path_hashes:
                # Fallback: show raw path data if not parsed
                path_bytes = bytes.fromhex(decoded.trace_path_data)
                path_str = " ".join(f"{b:02x}" for b in path_bytes)
                output.append(f"[dim]Trace Path Data:[/dim] [yellow]{path_str}[/yellow]")

            # Show channel for group messages
            if decoded.channel_hash:
                output.append(f"[dim]Channel:[/dim] [cyan]{decoded.channel_hash}[/cyan]")

            # Show encryption details
            if decoded.mac:
                output.append(f"[dim]MAC:[/dim] [cyan]{decoded.mac}[/cyan]")

            if decoded.encrypted_len:
                output.append(f"[dim]Encrypted:[/dim] {decoded.encrypted_len} bytes")

            # Show payload summary
            if decoded.payload_len:
                payload_type = decoded.payload_type or ""
                if payload_type in ["REQ", "RESPONSE", "TXT_MSG"]:
                    output.append(
                        f"[dim]Payload:[/dim] {decoded.payload_len} bytes "
                        f"[yellow](encrypted)[/yellow]"
                    )
                elif payload_type in ["GRP_TXT", "GRP_DATA"]:
                    output.append(
                        f"[dim]Payload:[/dim] {decoded.payload_len} bytes "
                        f"[yellow](encrypted group msg)[/yellow]"
                    )
                else:
                    output.append(f"[dim]Payload:[/dim] {decoded.payload_len} bytes")

                # Try to decrypt payload if private keys are provided
                if private_keys and decoded.payload_hex:
                    payload_type = decoded.payload_type or ""
                    if payload_type in ["REQ", "RESPONSE", "TXT_MSG", "PATH", "ANON_REQ"]:
                        decrypted = False
                        for key_info in private_keys:
                            try:
                                result = crypto.decrypt_packet_payload(
                                    packet_type=payload_type,
                                    payload_hex=decoded.payload_hex,
                                    private_key_hex=key_info["hex"],
                                    contacts=contacts,
                                    debug=self.debug,
                                )
                                if result and result.get("success"):
                                    decoder.apply_decryption_to_packet(
                                        decoded, result, key_info["file"]
                                    )
                                    decrypted = True
                                    break
                            except Exception as e:
                                if self.debug:
                                    output.append(f"[dim]Key {key_info['file']} failed: {e}[/dim]")
                                continue

                        if decrypted:
                            output.extend(self._render_decrypted(decoded, show_hexdump))
                        elif self.debug:
                            num_keys = len(private_keys)
                            output.append(
                                f"[red]Decrypt failed:[/red] None of the {num_keys} key(s) worked"
                            )

                # Try to decrypt group messages if channel names provided
                if channel_names and decoded.payload_hex:
                    payload_type = decoded.payload_type or ""
                    if payload_type in ["GRP_TXT", "GRP_DATA"]:
                        try:
                            result = crypto.decrypt_group_message(
                                payload_hex=decoded.payload_hex, channel_names=channel_names
                            )
                            if result and result.get("success"):
                                decoder.apply_decryption_to_packet(decoded, result)
                                output.extend(self._render_decrypted(decoded, show_hexdump))
                            elif result and result.get("error") and self.debug:
                                output.append(f"[red]Group decrypt failed:[/red] {result['error']}")
                        except Exception as e:
                            if self.debug:
                                output.append(f"[red]Group decrypt error:[/red] {e}")

            # Show raw packet in hexdump format
            if packet_hex:
                packet_bytes = bytes.fromhex(packet_hex)
                output.append("[dim]Raw:[/dim]")
                for line in decoder.format_hexdump(packet_bytes).split("\n"):
                    output.append(f"  [dim]{line}[/dim]")

            if decoded.decode_error:
                output.append(f"[red]Decode Error:[/red] {decoded.decode_error}")
                if self.debug and decoded.decode_traceback:
                    output.append(f"[dim]{decoded.decode_traceback}[/dim]")

            # Display in rich panel
            title = f"[bold cyan]Packet #{self._packet_count}[/bold cyan] [dim]@ {timestamp}[/dim]"
            self.console.print(Panel("\n".join(output), title=title, border_style="cyan"))

        self._subscription = self.mesh.subscribe(EventType.RX_LOG_DATA, on_packet)

    def detach(self) -> None:
        """Stop listening for RF packets."""
        if self._subscription is not None:
            self.mesh.unsubscribe(self._subscription)
            self._subscription = None

    async def sniff(
        self,
        duration: int,
        private_keys: list[dict[str, str]] | None,
        channel_names: list[str] | None,
        show_hexdump: bool,
    ) -> None:
        """Sniff and decode RF packets showing detailed information.

        Args:
            duration: Seconds to sniff packets
            private_keys: Optional list of private keys for decrypting packets
                         Each dict contains 'hex' (128 hex chars) and 'file' (filename)
            channel_names: Optional list of channel names for decrypting group messages
            show_hexdump: Show hexdump of decrypted payloads
        """
        self.console.print("[cyan]Loading contact list for address identification...[/cyan]")
        self.console.print(f"[yellow]📡 Starting packet sniffer (duration: {duration}s)[/yellow]")
        self.console.print("─" * 80, style="dim")

        await self.attach(private_keys, channel_names, show_hexdump)

        self.console.print(
            f"[green]✓[/green] Loaded {len(self._contact_map)} contacts for identification"
        )
        self.console.print(
            "\n[bold yellow]Listening for packets...[/bold yellow] [dim](Press Ctrl+C to stop)[/dim]"
        )
        self.console.print("─" * 80, style="dim")

        try:
            await asyncio.sleep(duration)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Sniffer stopped by user[/yellow]")
        finally:
            self.detach()

        self.console.print("\n" + "─" * 80, style="dim")
        summary_text = (
            f"[bold cyan]Summary:[/bold cyan] Captured [green]{self._packet_count}[/green] "
            f"packets in [yellow]{duration}s[/yellow]"
        )
        self.console.print(summary_text)
        if duration > 0:
            avg = self._packet_count / duration
            avg_text = f"   [dim]Average:[/dim] [cyan]{avg:.1f}[/cyan] packets/second"
            self.console.print(avg_text)
        self.console.print("─" * 80, style="dim")

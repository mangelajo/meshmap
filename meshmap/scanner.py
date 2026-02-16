"""Network scanner for discovering meshcore nodes."""

from typing import Any

import meshcore


class MeshScanner:
    """Scanner for discovering meshcore network nodes."""

    def __init__(self, serial_port: str, baudrate: int = 115200, debug: bool = False):
        """Initialize the mesh scanner.

        Args:
            serial_port: Path to the serial port (e.g., '/dev/ttyUSB0')
            baudrate: Serial port baud rate (default: 115200)
            debug: Enable debug logging (default: False)
        """
        self.serial_port = serial_port
        self.baudrate = baudrate
        self.debug = debug
        self.mesh: meshcore.MeshCore | None = None
        self.nodes: dict[str, Any] = {}

    async def connect(self) -> None:
        """Connect to the meshcore network via serial port."""
        print(f"Connecting to meshcore network on {self.serial_port}...")
        self.mesh = await meshcore.MeshCore.create_serial(
            port=self.serial_port,
            baudrate=self.baudrate,
            debug=self.debug
        )
        print("Connected successfully!")
        if self.debug and self.mesh:
            print(f"Self info: {self.mesh.self_info}")

    async def discover_neighbours(self, wait_time: int = 15) -> None:
        """Wait for nearby nodes to advertise themselves.

        Args:
            wait_time: Seconds to wait for advertisements (default: 15)
        """
        import asyncio

        from meshcore.events import EventType

        if not self.mesh:
            raise RuntimeError("Not connected. Call connect() first.")

        print(f"Listening for nearby node advertisements ({wait_time}s)...")

        # Enable auto-update to receive live contact updates
        self.mesh.auto_update_contacts = True

        # Subscribe to contact events to see new advertisements
        discovered_nodes: set = set()

        async def on_contact_event(event: Any) -> None:
            """Handle contact advertisement events."""
            contact = event.data
            name = contact.get('adv_name', 'Unknown')
            path_len = contact.get('out_path_len', -1)
            if path_len == 0 and name not in discovered_nodes:
                discovered_nodes.add(name)
                print(f"  ✓ Discovered: {name}")

        # Subscribe to NEXT_CONTACT events
        subscription = self.mesh.subscribe(EventType.NEXT_CONTACT, on_contact_event)

        try:
            # Wait for advertisements
            await asyncio.sleep(wait_time)
        finally:
            self.mesh.unsubscribe(subscription)

        if discovered_nodes:
            print(f"Discovery complete! Found {len(discovered_nodes)} nearby node(s).")
        else:
            print("Discovery complete. No new nearby nodes detected.")

    async def scan_zero_hop_nodes(self, discover: bool = True) -> list[dict[str, Any]]:
        """Scan for 0-hop (directly connected) nodes.

        Args:
            discover: If True, trigger active neighbor discovery first

        Returns:
            List of node information dictionaries
        """
        if not self.mesh:
            raise RuntimeError("Not connected. Call connect() first.")

        # Trigger neighbor discovery if requested
        if discover:
            await self.discover_neighbours()

        print("Scanning for 0-hop nodes...")

        # Ensure contacts are fetched
        await self.mesh.ensure_contacts()

        # Get the contacts (nodes) from meshcore
        # contacts is a dict where keys are public keys
        contacts = self.mesh.contacts

        zero_hop_nodes = []
        for public_key, contact in contacts.items():
            # Filter for 0-hop nodes (directly connected)
            # out_path_len: 0 means directly connected, -1 means unknown path
            out_path_len = contact.get('out_path_len', -1)
            contact_type = contact.get('type', 0)  # 1=contact, 2=repeater

            if self.debug:
                name = contact.get('adv_name', 'Unknown')
                print(f"  Contact: {name} - path_len={out_path_len}, type={contact_type}")

            if out_path_len == 0:
                node_info = {
                    'public_key': public_key,
                    'name': contact.get('adv_name', 'Unknown'),
                    'type': 'repeater' if contact_type == 2 else 'contact',
                    'out_path_len': out_path_len,
                    'last_advert': contact.get('last_advert'),
                    'lat': contact.get('adv_lat'),
                    'lon': contact.get('adv_lon'),
                }
                zero_hop_nodes.append(node_info)
                self.nodes[public_key] = node_info
                print(f"  Found: {node_info['name']} ({node_info['type']}) - Direct connection")

        print(f"\nTotal 0-hop nodes found: {len(zero_hop_nodes)}")
        return zero_hop_nodes

    async def guest_login_and_get_neighbors(
        self, contact: dict[str, Any], guest_password: str = ""
    ) -> dict[str, Any] | None:
        """Guest login to a repeater and retrieve its neighbor list.

        Args:
            contact: The contact dictionary to login to
            guest_password: Guest password (default: empty string)

        Returns:
            List of neighbor information from the repeater
        """
        if not self.mesh:
            raise RuntimeError("Not connected. Call connect() first.")

        name = contact.get('adv_name', 'Unknown')
        print(f"Attempting guest login to: {name}")

        try:
            # Try to login as guest
            login_result = await self.mesh.commands.send_login(contact, guest_password)
            if self.debug:
                print(f"  Login result: {login_result}")

            print(f"  ✓ Logged in to {name}")

            # Request neighbors list from the repeater
            print(f"  Requesting neighbors from {name}...")
            try:
                neighbors = await self.mesh.commands.fetch_all_neighbours(
                    contact, timeout=30, min_timeout=15
                )
            except Exception as e:
                if self.debug:
                    print(f"  fetch_all_neighbours failed: {e}, trying req_neighbours_sync...")
                neighbors = await self.mesh.commands.req_neighbours_sync(
                    contact, count=255, timeout=30.0
                )

            if self.debug:
                print(f"  Neighbors response: {neighbors}")

            # Request basic info
            print(f"  Requesting basic info from {name}...")
            basic_info = await self.mesh.commands.req_basic_sync(contact, timeout=30.0)

            if self.debug:
                print(f"  Basic info: {basic_info}")

            # Request status
            print(f"  Requesting status from {name}...")
            status = await self.mesh.commands.req_status_sync(contact, timeout=30.0)

            if self.debug:
                print(f"  Status: {status}")

            # Logout
            await self.mesh.commands.send_logout(contact)
            print(f"  ✓ Logged out from {name}")

            return {
                'contact': name,
                'public_key': contact.get('public_key'),
                'neighbors': neighbors,
                'basic_info': basic_info,
                'status': status,
            }

        except Exception as e:
            print(f"  ✗ Failed to login/query {name}: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
            return None

    async def get_all_contacts(self) -> dict[str, Any]:
        """Get all contacts from the mesh network.

        Returns:
            Dictionary of all contacts with their details
        """
        if not self.mesh:
            raise RuntimeError("Not connected. Call connect() first.")

        await self.mesh.ensure_contacts()
        return self.mesh.contacts

    async def discover_by_rf_activity(self, duration: int = 30) -> list[dict[str, Any]]:
        """Discover nearby nodes by listening to RF packet activity.

        Args:
            duration: Seconds to listen for RF activity (default: 30)

        Returns:
            List of discovered nodes with signal information
        """
        import asyncio
        from collections import defaultdict

        from meshcore.events import EventType

        if not self.mesh:
            raise RuntimeError("Not connected. Call connect() first.")

        print(f"Listening for RF activity from nearby nodes ({duration}s)...")

        # Track nodes we hear packets from
        rf_nodes: dict[str, dict[str, Any]] = {}
        packet_counts = defaultdict(int)

        async def on_rf_data(event: Any) -> None:
            """Handle RF log data events."""
            data = event.payload
            payload_hex = data.get('raw_hex', '')
            snr = data.get('snr')
            rssi = data.get('rssi')

            # Try to extract node identifier from payload
            # First few bytes often contain source info
            if len(payload_hex) >= 16:
                node_prefix = payload_hex[:16]

                if node_prefix not in rf_nodes or rssi > rf_nodes[node_prefix].get('rssi', -999):
                    rf_nodes[node_prefix] = {
                        'node_prefix': node_prefix,
                        'snr': snr,
                        'rssi': rssi,
                        'payload_length': data.get('payload_length', 0),
                        'sample_payload': payload_hex[:32],
                    }

                packet_counts[node_prefix] += 1

                if self.debug:
                    print(f"  RF: {node_prefix[:12]}... SNR={snr}, RSSI={rssi}")

        # Subscribe to RX_LOG_DATA events
        subscription = self.mesh.subscribe(EventType.RX_LOG_DATA, on_rf_data)

        try:
            await asyncio.sleep(duration)
        finally:
            self.mesh.unsubscribe(subscription)

        # Build results
        results = []
        for node_prefix, info in rf_nodes.items():
            info['packet_count'] = packet_counts[node_prefix]
            results.append(info)

        # Sort by signal strength (RSSI)
        results.sort(key=lambda x: x['rssi'], reverse=True)

        print(f"\nDiscovered {len(results)} nodes from RF activity:")
        for node in results:
            print(
                f"  {node['node_prefix'][:12]}... "
                f"RSSI={node['rssi']}, SNR={node['snr']}, "
                f"packets={node['packet_count']}"
            )

        return results

    async def sniff_packets(
        self,
        duration: int = 60,
        private_key_hex: str | None = None,
        channel_names: list[str] | None = None,
        show_hexdump: bool = False
    ) -> None:
        """Sniff and decode RF packets showing detailed information.

        Args:
            duration: Seconds to sniff packets (default: 60)
            private_key_hex: Optional private key for decrypting packets (128 hex chars)
            channel_names: Optional list of channel names for decrypting group messages
            show_hexdump: Show hexdump of decrypted payloads (default: False)
        """
        import asyncio
        from datetime import datetime

        from meshcore.events import EventType

        if not self.mesh:
            raise RuntimeError("Not connected. Call connect() first.")

        # Pre-load all contacts to identify addresses in packets
        print("Loading contact list for address identification...")
        await self.mesh.ensure_contacts()
        contacts = self.mesh.contacts

        # Build mapping of address prefixes to contact names
        contact_map: dict[str, str] = {}
        for public_key, contact in contacts.items():
            name = contact.get('adv_name', 'Unknown')
            # Map public key prefix to name
            if len(public_key) >= 8:
                contact_map[public_key[:8].lower()] = name

        print(f"Loaded {len(contact_map)} contacts for identification")
        print(f"Starting packet sniffer (duration: {duration}s)")
        print("=" * 80)

        packet_count = 0

        def format_hexdump(data: bytes) -> str:
            """Format binary data as hexdump -C style output.

            Args:
                data: Binary data to format

            Returns:
                Formatted hexdump string
            """
            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]

                # Offset (4 hex digits, 16-bit)
                offset = f"{i:04x}"

                # Hex representation (two groups of 8 bytes)
                hex_part1 = ' '.join(f"{b:02x}" for b in chunk[:8])
                hex_part2 = ' '.join(f"{b:02x}" for b in chunk[8:16]) if len(chunk) > 8 else ''

                # Pad hex parts if needed
                hex_part1 = hex_part1.ljust(23)  # 8 bytes = "xx xx xx xx xx xx xx xx" = 23 chars
                hex_part2 = hex_part2.ljust(23)

                # ASCII representation
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

                # Combine parts
                lines.append(f"{offset}  {hex_part1} {hex_part2} |{ascii_part}|")

            # Add final offset line
            lines.append(f"{len(data):04x}")

            return '\n'.join(lines)

        # Route type definitions (from Packet.h)
        route_types = {
            0x00: "TRANSPORT_FLOOD",
            0x01: "FLOOD",
            0x02: "DIRECT",
            0x03: "TRANSPORT_DIRECT",
        }

        # Payload type definitions (from Packet.h)
        payload_types = {
            0x00: "REQ",
            0x01: "RESPONSE",
            0x02: "TXT_MSG",
            0x03: "ACK",
            0x04: "ADVERT",
            0x05: "GRP_TXT",
            0x06: "GRP_DATA",
            0x07: "ANON_REQ",
            0x08: "PATH",
            0x09: "TRACE",
            0x0A: "MULTIPART",
            0x0B: "CONTROL",
            0x0F: "RAW_CUSTOM",
        }

        def decode_packet(payload_hex: str) -> dict[str, Any]:
            """Decode meshcore packet according to actual packet structure.

            Packet format (from MeshCore/src/Packet.cpp):
            [header:1] [transport_codes:4 (optional)] [path_len:1] [path:path_len] [payload:remaining]

            Header byte (from Packet.h):
            - Bits 0-1: Route type
            - Bits 2-5: Payload type
            - Bits 6-7: Payload version
            """
            decoded: dict[str, Any] = {}

            if len(payload_hex) < 2:
                return decoded

            try:
                # Convert hex string to bytes
                data = bytes.fromhex(payload_hex)
                offset = 0

                # Decode header byte
                header = data[offset]
                offset += 1

                # Extract route type (bits 0-1)
                route_type = header & 0x03
                decoded['route_type'] = route_types.get(route_type, f"UNKNOWN_{route_type}")
                decoded['route_type_hex'] = f"0x{route_type:02x}"

                # Extract payload type (bits 2-5, shifted right by 2)
                payload_type = (header >> 2) & 0x0F
                decoded['payload_type'] = payload_types.get(payload_type, f"UNKNOWN_{payload_type}")
                decoded['payload_type_hex'] = f"0x{payload_type:02x}"

                # Extract payload version (bits 6-7, shifted right by 6)
                payload_ver = (header >> 6) & 0x03
                decoded['payload_ver'] = payload_ver

                decoded['header_hex'] = f"0x{header:02x}"

                # Check if transport codes are present
                # TRANSPORT_FLOOD (0x00) or TRANSPORT_DIRECT (0x03)
                has_transport = route_type in (0x00, 0x03)

                if has_transport and len(data) >= offset + 4:
                    # Read 2 uint16_t transport codes (little-endian)
                    transport_code_1 = int.from_bytes(data[offset:offset+2], 'little')
                    transport_code_2 = int.from_bytes(data[offset+2:offset+4], 'little')
                    decoded['transport_codes'] = [
                        f"0x{transport_code_1:04x}",
                        f"0x{transport_code_2:04x}"
                    ]
                    offset += 4

                # Read path length
                if len(data) >= offset + 1:
                    path_len = data[offset]
                    decoded['path_len'] = path_len
                    offset += 1

                    # Read path data
                    if len(data) >= offset + path_len:
                        path_data = data[offset:offset+path_len]
                        decoded['path_hex'] = path_data.hex()

                        # Parse path as hop list (1-byte hashes) and match to contacts
                        if path_len > 0:
                            hops_with_contacts = []
                            for hop_byte in path_data:
                                hop_hash = f"{hop_byte:02x}"
                                hop_hex = f"0x{hop_hash}"

                                # Find all contacts matching this hop hash
                                matching_contacts = []
                                for pubkey, name in contact_map.items():
                                    if pubkey.startswith(hop_hash):
                                        matching_contacts.append(name)

                                hops_with_contacts.append({
                                    'hash': hop_hex,
                                    'contacts': matching_contacts
                                })

                            decoded['path_hops'] = hops_with_contacts
                        offset += path_len

                # Remaining bytes are the payload
                if len(data) > offset:
                    payload_data = data[offset:]
                    decoded['payload_hex'] = payload_data.hex()
                    decoded['payload_len'] = len(payload_data)

                    # Decode payload based on packet type
                    payload_offset = 0

                    if payload_type in [0x00, 0x01, 0x02, 0x08]:  # REQ, RESPONSE, TXT_MSG, PATH
                        # Format: [dest_hash:1][src_hash:1][MAC:2][encrypted_data]
                        # Encrypted payload formats:
                        #   TXT_MSG: [timestamp:4][flags:1][text:null-terminated]
                        #   REQ: [timestamp:4][request_data:variable]
                        #   RESPONSE: [response_data:variable]
                        #   PATH: [timestamp:4][path_data:variable]
                        if len(payload_data) >= 2:
                            dest_hash = payload_data[payload_offset]
                            src_hash = payload_data[payload_offset + 1]
                            decoded['dest_hash'] = f"0x{dest_hash:02x}"
                            decoded['src_hash'] = f"0x{src_hash:02x}"

                            # Try to match hashes to known contacts
                            dest_hash_hex = f"{dest_hash:02x}"
                            src_hash_hex = f"{src_hash:02x}"

                            for pubkey, name in contact_map.items():
                                if pubkey.startswith(dest_hash_hex):
                                    decoded['dest_name'] = name
                                if pubkey.startswith(src_hash_hex):
                                    decoded['src_name'] = name

                            # Extract MAC and encrypted data
                            if len(payload_data) >= 4:
                                mac = payload_data[2:4]
                                decoded['mac'] = mac.hex()
                                if len(payload_data) > 4:
                                    encrypted_data = payload_data[4:]
                                    decoded['encrypted_data_hex'] = encrypted_data.hex()
                                    decoded['encrypted_len'] = len(encrypted_data)

                    elif payload_type == 0x04:  # ADVERT
                        # Format: [pubkey:32][timestamp:4][signature:64][app_data:up to 32]
                        # App data: name, lat/lon, and other metadata
                        if len(payload_data) >= 32:
                            pubkey_hex = payload_data[:32].hex()
                            decoded['advert_pubkey'] = pubkey_hex
                            # Check if this matches any known contact
                            if pubkey_hex[:8].lower() in contact_map:
                                decoded['advert_contact_name'] = contact_map[pubkey_hex[:8].lower()]

                            if len(payload_data) >= 36:
                                # Extract timestamp
                                timestamp_bytes = payload_data[32:36]
                                timestamp = int.from_bytes(timestamp_bytes, 'little')
                                decoded['advert_timestamp'] = timestamp

                            if len(payload_data) >= 100:
                                # Extract signature (64 bytes)
                                signature = payload_data[36:100]
                                decoded['advert_signature'] = signature.hex()

                            if len(payload_data) > 100:
                                # Parse app_data structure
                                app_data = payload_data[100:]
                                decoded['advert_app_data_hex'] = app_data.hex()
                                decoded['advert_app_data_len'] = len(app_data)

                                # Decode app_data structure
                                if len(app_data) > 0:
                                    import struct
                                    flags = app_data[0]
                                    offset = 1

                                    # Type (bits 0-3)
                                    adv_type = flags & 0x0F
                                    type_names = {
                                        0: "NONE",
                                        1: "CHAT",
                                        2: "REPEATER",
                                        3: "ROOM",
                                        4: "SENSOR"
                                    }
                                    type_name = type_names.get(adv_type, f"UNKNOWN_{adv_type}")
                                    decoded['advert_type'] = type_name

                                    # Lat/Lon (if present)
                                    if flags & 0x10 and len(app_data) >= offset + 8:
                                        lat_bytes = app_data[offset:offset+4]
                                        lon_bytes = app_data[offset+4:offset+8]
                                        lat_int = struct.unpack('<i', lat_bytes)[0]
                                        lon_int = struct.unpack('<i', lon_bytes)[0]
                                        decoded['advert_lat'] = lat_int / 1_000_000.0
                                        decoded['advert_lon'] = lon_int / 1_000_000.0
                                        offset += 8

                                    # Extra1 (future use, if present)
                                    if flags & 0x20 and len(app_data) >= offset + 2:
                                        extra1 = struct.unpack('<H', app_data[offset:offset+2])[0]
                                        decoded['advert_extra1'] = extra1
                                        offset += 2

                                    # Extra2 (future use, if present)
                                    if flags & 0x40 and len(app_data) >= offset + 2:
                                        extra2 = struct.unpack('<H', app_data[offset:offset+2])[0]
                                        decoded['advert_extra2'] = extra2
                                        offset += 2

                                    # Name (if present, remainder of app_data)
                                    if flags & 0x80 and len(app_data) > offset:
                                        name_bytes = app_data[offset:]
                                        name_str = name_bytes.decode('utf-8', errors='replace')
                                        decoded['advert_name'] = name_str.rstrip('\x00')

                    elif payload_type == 0x07:  # ANON_REQ
                        # Format: [dest_hash:1][sender_pubkey:32][MAC:2][encrypted_data]
                        # Used for anonymous requests (ephemeral sender key)
                        if len(payload_data) >= 33:
                            dest_hash = payload_data[payload_offset]
                            decoded['dest_hash'] = f"0x{dest_hash:02x}"

                            sender_pubkey = payload_data[payload_offset+1:payload_offset+33]
                            decoded['anon_sender_pubkey'] = sender_pubkey.hex()

                            # Try to match dest hash to known contact
                            dest_hash_hex = f"{dest_hash:02x}"
                            for pubkey, name in contact_map.items():
                                if pubkey.startswith(dest_hash_hex):
                                    decoded['dest_name'] = name

                            # Check if sender pubkey is known (unlikely for anon)
                            sender_pubkey_hex = sender_pubkey.hex()
                            if sender_pubkey_hex[:8].lower() in contact_map:
                                decoded['anon_sender_name'] = contact_map[sender_pubkey_hex[:8].lower()]

                            # Extract MAC and encrypted data
                            if len(payload_data) >= 35:
                                mac = payload_data[33:35]
                                decoded['mac'] = mac.hex()
                                if len(payload_data) > 35:
                                    encrypted_data = payload_data[35:]
                                    decoded['encrypted_data_hex'] = encrypted_data.hex()
                                    decoded['encrypted_len'] = len(encrypted_data)

                    elif payload_type in [0x05, 0x06]:  # GRP_TXT, GRP_DATA
                        # Format: [channel_hash:1][MAC:2][encrypted_data]
                        # Encrypted payload for GRP_TXT:
                        #   [timestamp:4][txt_type:1]["sender_name: message":null-terminated]
                        # Encrypted payload for GRP_DATA:
                        #   [timestamp:4][data:variable]
                        if len(payload_data) >= 1:
                            channel_hash = payload_data[payload_offset]
                            decoded['channel_hash'] = f"0x{channel_hash:02x}"

                            # Extract MAC and encrypted data
                            if len(payload_data) >= 3:
                                mac = payload_data[1:3]
                                decoded['mac'] = mac.hex()
                                if len(payload_data) > 3:
                                    encrypted_data = payload_data[3:]
                                    decoded['encrypted_data_hex'] = encrypted_data.hex()
                                    decoded['encrypted_len'] = len(encrypted_data)

                decoded['total_bytes'] = len(data)

            except Exception as e:
                decoded['decode_error'] = str(e)
                import traceback
                decoded['decode_traceback'] = traceback.format_exc()

            return decoded

        async def on_packet(event: Any) -> None:
            """Handle received packet."""
            nonlocal packet_count
            packet_count += 1

            data = event.payload
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            print(f"\n[{timestamp}] Packet #{packet_count}")
            print("-" * 80)

            # Basic RF info
            print(f"  Signal: RSSI={data.get('rssi')} dBm, SNR={data.get('snr')} dB")

            raw_hex = data.get('raw_hex', '')
            payload_len = data.get('payload_length', 0)
            print(f"  Length: {payload_len} bytes")

            # Extract actual mesh packet (skip SNR and RSSI bytes)
            # raw_hex format from RX_LOG_DATA: [SNR:1byte][RSSI:1byte][mesh_packet:...]
            # We need to skip first 2 bytes (4 hex characters)
            if len(raw_hex) >= 4:
                packet_hex = raw_hex[4:]  # Skip SNR+RSSI
            else:
                packet_hex = raw_hex

            # Try to decode the mesh packet
            decoded = decode_packet(packet_hex)

            # Show header breakdown
            if decoded.get('header_hex'):
                print(f"  Header: {decoded['header_hex']}")

            # Show route type
            if decoded.get('route_type'):
                print(f"    Route:   {decoded['route_type']}")

            # Show payload type
            if decoded.get('payload_type'):
                print(f"    Type:    {decoded['payload_type']}")

            # Show payload version
            if 'payload_ver' in decoded:
                print(f"    Version: {decoded['payload_ver']}")

            # Show transport codes if present
            if decoded.get('transport_codes'):
                codes = ', '.join(decoded['transport_codes'])
                print(f"  Transport codes: {codes}")

            # Show path information
            if 'path_len' in decoded:
                print(f"  Path: {decoded['path_len']} hops")
                if decoded.get('path_hops'):
                    # Display each hop with matching contacts
                    for i, hop_info in enumerate(decoded['path_hops'], 1):
                        hop_hash = hop_info['hash']
                        contacts = hop_info.get('contacts', [])

                        if contacts:
                            # Show contact names
                            contact_names = ', '.join(contacts)
                            if len(contacts) > 1:
                                matches_text = f"({len(contacts)} matches)"
                                print(f"    Hop {i}: {hop_hash} [{contact_names}] {matches_text}")
                            else:
                                print(f"    Hop {i}: {hop_hash} [{contact_names}]")
                        else:
                            # No matching contact
                            print(f"    Hop {i}: {hop_hash} (unknown)")

            # Show source/destination addresses
            if decoded.get('src_hash') or decoded.get('dest_hash'):
                if decoded.get('src_hash'):
                    src_display = decoded['src_hash']
                    if decoded.get('src_name'):
                        src_display += f" [{decoded['src_name']}]"
                    print(f"  From: {src_display}")

                if decoded.get('dest_hash'):
                    dest_display = decoded['dest_hash']
                    if decoded.get('dest_name'):
                        dest_display += f" [{decoded['dest_name']}]"
                    print(f"  To:   {dest_display}")

            # Show ADVERT details
            if decoded.get('advert_pubkey'):
                pubkey_display = decoded['advert_pubkey'][:16] + "..."
                if decoded.get('advert_contact_name'):
                    pubkey_display += f" [{decoded['advert_contact_name']}]"
                print(f"  ADVERT from: {pubkey_display}")

                if decoded.get('advert_timestamp'):
                    from datetime import datetime as dt
                    try:
                        ts_str = dt.fromtimestamp(decoded['advert_timestamp'])
                        ts_formatted = ts_str.strftime('%Y-%m-%d %H:%M:%S')
                        print(f"    Timestamp: {ts_formatted}")
                    except (ValueError, OSError):
                        ts_raw = decoded['advert_timestamp']
                        print(f"    Timestamp: {ts_raw} (invalid)")

                if decoded.get('advert_signature'):
                    sig_display = decoded['advert_signature'][:32] + "..."
                    print(f"    Signature: {sig_display}")

                if decoded.get('advert_type'):
                    print(f"    Type: {decoded['advert_type']}")

                if decoded.get('advert_name'):
                    print(f"    Name: {decoded['advert_name']}")

                if decoded.get('advert_lat') is not None:
                    lat = decoded['advert_lat']
                    lon = decoded['advert_lon']
                    print(f"    Location: {lat:.6f}, {lon:.6f}")

                if decoded.get('advert_extra1'):
                    print(f"    Extra1: 0x{decoded['advert_extra1']:04x}")

                if decoded.get('advert_extra2'):
                    print(f"    Extra2: 0x{decoded['advert_extra2']:04x}")

                if decoded.get('advert_app_data_len'):
                    print(f"    App Data: {decoded['advert_app_data_len']} bytes")
                    if show_hexdump and decoded.get('advert_app_data_hex'):
                        app_data_bytes = bytes.fromhex(decoded['advert_app_data_hex'])
                        print("    App Data Hexdump:")
                        for line in format_hexdump(app_data_bytes).split('\n'):
                            print(f"      {line}")

            # Show ANON_REQ sender
            if decoded.get('anon_sender_pubkey'):
                sender_display = decoded['anon_sender_pubkey'][:16] + "..."
                if decoded.get('anon_sender_name'):
                    sender_display += f" [{decoded['anon_sender_name']}]"
                print(f"  Anon Sender: {sender_display}")

            # Show channel for group messages
            if decoded.get('channel_hash'):
                print(f"  Channel: {decoded['channel_hash']}")

            # Show encryption details
            if decoded.get('mac'):
                print(f"  MAC: {decoded['mac']}")

            if decoded.get('encrypted_len'):
                print(f"  Encrypted: {decoded['encrypted_len']} bytes")

            # Show payload summary
            if decoded.get('payload_len'):
                payload_type = decoded.get('payload_type', '')
                if payload_type in ['REQ', 'RESPONSE', 'TXT_MSG']:
                    print(f"  Payload: {decoded['payload_len']} bytes (encrypted)")
                elif payload_type in ['GRP_TXT', 'GRP_DATA']:
                    print(f"  Payload: {decoded['payload_len']} bytes (encrypted group msg)")
                else:
                    print(f"  Payload: {decoded['payload_len']} bytes")

                # Try to decrypt payload if private key is provided
                if private_key_hex and decoded.get('payload_hex'):
                    payload_type = decoded.get('payload_type', '')
                    if payload_type in ['REQ', 'RESPONSE', 'TXT_MSG', 'PATH', 'ANON_REQ']:
                        from meshmap.crypto import decrypt_packet_payload

                        try:
                            decryption_result = decrypt_packet_payload(
                                packet_type=payload_type,
                                payload_hex=decoded['payload_hex'],
                                private_key_hex=private_key_hex,
                                contacts=contacts
                            )

                            if decryption_result and decryption_result.get('success'):
                                print("  🔓 Decrypted:")
                                if 'contact_name' in decryption_result:
                                    print(f"    From: {decryption_result['contact_name']}")
                                if 'plaintext' in decryption_result:
                                    # Show first 200 chars of plaintext
                                    text = decryption_result['plaintext']
                                    if len(text) > 200:
                                        text = text[:200] + "..."
                                    print(f"    Data: {text}")

                                # Show hexdump if requested
                                if show_hexdump and 'plaintext_hex' in decryption_result:
                                    plaintext_hex = decryption_result['plaintext_hex']
                                    plaintext_bytes = bytes.fromhex(plaintext_hex)
                                    print("    Hexdump:")
                                    for line in format_hexdump(plaintext_bytes).split('\n'):
                                        print(f"      {line}")
                            elif decryption_result and decryption_result.get('error'):
                                if self.debug:
                                    print(f"  🔒 Decrypt failed: {decryption_result['error']}")
                        except Exception as e:
                            if self.debug:
                                print(f"  🔒 Decrypt error: {e}")

                # Try to decrypt group messages if channel names provided
                if channel_names and decoded.get('payload_hex'):
                    payload_type = decoded.get('payload_type', '')
                    if payload_type in ['GRP_TXT', 'GRP_DATA']:
                        from meshmap.crypto import decrypt_group_message

                        try:
                            decryption_result = decrypt_group_message(
                                payload_hex=decoded['payload_hex'],
                                channel_names=channel_names
                            )

                            if decryption_result and decryption_result.get('success'):
                                print("  🔓 Decrypted Group Message:")
                                if 'channel_name' in decryption_result:
                                    print(f"    Channel: {decryption_result['channel_name']}")
                                if 'sender' in decryption_result:
                                    print(f"    From: {decryption_result['sender']}")
                                if 'message' in decryption_result:
                                    msg = decryption_result['message']
                                    if len(msg) > 200:
                                        msg = msg[:200] + "..."
                                    print(f"    Message: {msg}")
                                if 'timestamp' in decryption_result:
                                    from datetime import datetime as dt
                                    try:
                                        ts = dt.fromtimestamp(decryption_result['timestamp'])
                                        print(f"    Time: {ts.strftime('%Y-%m-%d %H:%M:%S')}")
                                    except (ValueError, OSError):
                                        pass

                                # Show hexdump if requested
                                if show_hexdump and 'plaintext_hex' in decryption_result:
                                    plaintext_hex = decryption_result['plaintext_hex']
                                    plaintext_bytes = bytes.fromhex(plaintext_hex)
                                    print("    Hexdump:")
                                    for line in format_hexdump(plaintext_bytes).split('\n'):
                                        print(f"      {line}")
                            elif decryption_result and decryption_result.get('error'):
                                if self.debug:
                                    err = decryption_result['error']
                                    print(f"  🔒 Group decrypt failed: {err}")
                        except Exception as e:
                            if self.debug:
                                print(f"  🔒 Group decrypt error: {e}")

            # Show raw packet in hexdump format
            if packet_hex:
                packet_bytes = bytes.fromhex(packet_hex)
                print("  Raw:")
                for line in format_hexdump(packet_bytes).split('\n'):
                    print(f"    {line}")

            if decoded.get('decode_error'):
                print(f"  ❌ Decode Error: {decoded['decode_error']}")
                if self.debug and decoded.get('decode_traceback'):
                    print(decoded['decode_traceback'])

            print("-" * 80)

        # Subscribe to all RF packet events
        subscription = self.mesh.subscribe(EventType.RX_LOG_DATA, on_packet)

        print(f"\n🔍 Listening for packets... (Press Ctrl+C to stop)")
        print("=" * 80)

        try:
            await asyncio.sleep(duration)
        except KeyboardInterrupt:
            print("\n\n⏹️  Sniffer stopped by user")
        finally:
            self.mesh.unsubscribe(subscription)

        print("\n" + "=" * 80)
        print(f"📊 Summary: Captured {packet_count} packets in {duration}s")
        if duration > 0:
            print(f"   Average: {packet_count/duration:.1f} packets/second")
        print("=" * 80)

    async def disconnect(self) -> None:
        """Disconnect from the meshcore network."""
        if self.mesh:
            await self.mesh.disconnect()
            print("Disconnected from meshcore network.")

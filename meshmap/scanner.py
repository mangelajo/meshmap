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
        self._sniffer: Any = None  # PacketSniffer instance when --sniff is active

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

    async def discover_neighbours(self, wait_time: int = 10) -> None:
        """Actively discover nearby nodes by broadcasting a 0-hop advertisement.

        Sends a zero-hop advertisement so nearby nodes hear us, then listens
        for ADVERTISEMENT push events from nodes that respond.

        Args:
            wait_time: Seconds to wait for responses after sending the advert (default: 10)
        """
        import asyncio

        from meshcore.events import EventType

        if not self.mesh:
            raise RuntimeError("Not connected. Call connect() first.")

        discovered_nodes: set = set()

        async def on_advert(event: Any) -> None:
            name = event.payload.get('adv_name') or event.payload.get('name', 'Unknown')
            if name not in discovered_nodes:
                discovered_nodes.add(name)
                print(f"  ✓ Heard: {name}")

        subscription = self.mesh.subscribe(EventType.ADVERTISEMENT, on_advert)

        try:
            # Broadcast our own 0-hop advertisement to prompt nearby nodes to respond
            print("Broadcasting 0-hop advertisement to discover nearby nodes...")
            await self.mesh.commands.send_advert(flood=False)
            print(f"Listening for responses ({wait_time}s)...")
            await asyncio.sleep(wait_time)
        finally:
            self.mesh.unsubscribe(subscription)

        if discovered_nodes:
            print(f"Discovery complete! Heard {len(discovered_nodes)} nearby node(s).")
        else:
            print("Discovery complete. No nearby nodes responded.")

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

    async def discover_zero_hop_repeaters(self, wait_time: int = 10) -> list[dict[str, Any]]:
        """Discover 0-hop repeaters using an active NODE_DISCOVER_REQ control packet.

        Sends control packet 0x80 to prompt nearby nodes to identify themselves,
        then collects DISCOVER_RESPONSE events and filters for repeaters (node_type == 2).

        Args:
            wait_time: Seconds to listen for responses (default: 10)

        Returns:
            List of repeater dicts with keys: public_key, name, snr, lat, lon, last_advert
        """
        import asyncio

        from meshcore.events import EventType

        if not self.mesh:
            raise RuntimeError("Not connected. Call connect() first.")

        await self.mesh.ensure_contacts()

        discovered: dict[str, dict[str, Any]] = {}

        async def on_discover(event: Any) -> None:
            node_type = event.payload.get('node_type', 0)
            if node_type != 2:
                return
            pubkey = event.payload.get('pubkey', '')
            if pubkey and pubkey not in discovered:
                snr = event.payload.get('SNR_in')
                snr_str = f"{snr:+.1f} dB" if snr is not None else "?"
                print(f"  ✓ Repeater: {pubkey[:16]}… SNR={snr_str}")
                discovered[pubkey] = event.payload

        subscription = self.mesh.subscribe(EventType.DISCOVER_RESPONSE, on_discover)

        try:
            print("Sending node discovery request...")
            # filter is a bitmask: bit N = respond if ADV_TYPE == N.
            # ADV_TYPE_REPEATER=2, so bit 2 (0x04) targets repeaters only.
            await self.mesh.commands.send_node_discover_req(filter=0x04, prefix_only=False)
            print(f"Listening for responses ({wait_time}s)...")
            await asyncio.sleep(wait_time)
        finally:
            self.mesh.unsubscribe(subscription)

        contacts = self.mesh.contacts
        repeaters = []
        for pubkey, disc in discovered.items():
            contact = next(
                (c for pk, c in contacts.items() if pk.lower().startswith(pubkey[:8].lower())),
                None,
            )
            repeaters.append({
                'public_key': pubkey,
                'name': contact.get('adv_name') if contact else f'Unknown ({pubkey[:8]}…)',
                'type': 'repeater',
                'out_path_len': 0,
                'snr': disc.get('SNR_in'),
                'lat': contact.get('adv_lat') if contact else None,
                'lon': contact.get('adv_lon') if contact else None,
                'last_advert': contact.get('last_advert') if contact else None,
            })

        print(f"\nTotal 0-hop repeaters discovered: {len(repeaters)}")
        return repeaters

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

    async def start_sniff(
        self,
        private_keys: list[dict[str, str]] | None = None,
        channel_names: list[str] | None = None,
    ) -> None:
        """Attach a background packet sniffer to the current connection.

        Args:
            private_keys: Optional list of dicts with 'hex' and 'file' for decryption
            channel_names: Optional channel names for group message decryption
        """
        from meshmap.sniffer import PacketSniffer

        if not self.mesh:
            raise RuntimeError("Not connected. Call connect() first.")
        self._sniffer = PacketSniffer(self.mesh, debug=self.debug)
        await self._sniffer.attach(private_keys, channel_names)

    def stop_sniff(self) -> None:
        """Detach the background packet sniffer if active."""
        if self._sniffer is not None:
            self._sniffer.detach()
            self._sniffer = None

    async def disconnect(self) -> None:
        """Disconnect from the meshcore network."""
        self.stop_sniff()
        if self.mesh:
            await self.mesh.disconnect()
            print("Disconnected from meshcore network.")

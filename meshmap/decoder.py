"""Packet decoding utilities for meshcore packets."""

import struct
from typing import Any

from meshmap.models import DecodedPacket, HopInfo

# Route type definitions (from Packet.h)
ROUTE_TYPES = {
    0x00: "TRANSPORT_FLOOD",
    0x01: "FLOOD",
    0x02: "DIRECT",
    0x03: "TRANSPORT_DIRECT",
}

# Payload type definitions (from Packet.h)
PAYLOAD_TYPES = {
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

# ADVERT type definitions
ADVERT_TYPES = {
    0: "NONE",
    1: "CHAT",
    2: "REPEATER",
    3: "ROOM",
    4: "SENSOR"
}


def format_hexdump(data: bytes) -> str:
    """Format binary data as hexdump -C style output.

    Args:
        data: Binary data to format

    Returns:
        Formatted hexdump string with 16-bit offsets
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


def decode_packet(payload_hex: str, contact_map: dict[str, str]) -> DecodedPacket:
    """Decode meshcore packet according to actual packet structure.

    Packet format (from MeshCore/src/Packet.cpp):
    [header:1] [transport_codes:4 (optional)] [path_len:1] [path:path_len] [payload:remaining]

    Header byte (from Packet.h):
    - Bits 0-1: Route type
    - Bits 2-5: Payload type
    - Bits 6-7: Payload version

    Args:
        payload_hex: Hex string of the packet payload
        contact_map: Dictionary mapping public key prefixes to contact names

    Returns:
        DecodedPacket object with all decoded fields
    """
    packet = DecodedPacket()

    if len(payload_hex) < 2:
        return packet

    try:
        # Convert hex string to bytes
        data = bytes.fromhex(payload_hex)
        offset = 0

        # Decode header byte
        header = data[offset]
        offset += 1

        # Extract route type (bits 0-1)
        route_type = header & 0x03
        packet.route_type = ROUTE_TYPES.get(route_type, f"UNKNOWN_{route_type}")
        packet.route_type_hex = f"0x{route_type:02x}"

        # Extract payload type (bits 2-5, shifted right by 2)
        payload_type = (header >> 2) & 0x0F
        packet.payload_type = PAYLOAD_TYPES.get(payload_type, f"UNKNOWN_{payload_type}")
        packet.payload_type_hex = f"0x{payload_type:02x}"

        # Extract payload version (bits 6-7, shifted right by 6)
        payload_ver = (header >> 6) & 0x03
        packet.payload_ver = payload_ver

        # Store full header
        packet.header_hex = f"0x{header:02x}"

        # Check if transport codes are present (based on route type)
        has_transport_codes = route_type in [0x00, 0x03]  # TRANSPORT_FLOOD or TRANSPORT_DIRECT

        if has_transport_codes and len(data) > offset + 4:
            # Read 4 transport code bytes
            transport_codes = data[offset:offset+4]
            packet.transport_codes = [f"0x{b:02x}" for b in transport_codes]
            offset += 4

        # Read path length
        if len(data) > offset:
            path_len = data[offset]
            packet.path_len = path_len
            offset += 1

            # Read path data (hop addresses)
            if path_len > 0 and len(data) >= offset + path_len:
                path_data = data[offset:offset+path_len]
                offset += path_len

                # Match each hop to contacts
                hops_with_contacts = []
                for hop_byte in path_data:
                    hop_hash = f"{hop_byte:02x}"
                    matching_contacts = []
                    for pubkey, name in contact_map.items():
                        if pubkey.startswith(hop_hash):
                            matching_contacts.append(name)
                    hops_with_contacts.append(
                        HopInfo(hash=f"0x{hop_hash}", contacts=matching_contacts)
                    )
                packet.path_hops = hops_with_contacts

        # Extract payload data (everything after path)
        if len(data) > offset:
            payload_data = data[offset:]
            packet.payload_hex = payload_data.hex()
            packet.payload_len = len(payload_data)

            # Decode payload based on type
            _decode_payload(packet, payload_type, payload_data, contact_map)

        packet.total_bytes = len(data)

    except Exception as e:
        packet.decode_error = str(e)
        import traceback
        packet.decode_traceback = traceback.format_exc()

    return packet


def _decode_multipart(packet: DecodedPacket, payload_data: bytes) -> None:
    """Decode MULTIPART payload structure.

    Format: [header_byte:1][wrapped_payload:variable]
    - Upper 4 bits of header_byte: remaining packets
    - Lower 4 bits of header_byte: wrapped payload type
    """
    if len(payload_data) >= 1:
        header_byte = payload_data[0]
        remaining = (header_byte >> 4) & 0x0F
        wrapped_type = header_byte & 0x0F

        packet.multipart_remaining = remaining
        packet.multipart_type = f"0x{wrapped_type:02x}"
        packet.multipart_type_name = PAYLOAD_TYPES.get(wrapped_type, f"UNKNOWN_{wrapped_type}")

        if len(payload_data) > 1:
            wrapped_payload = payload_data[1:]
            packet.multipart_payload_hex = wrapped_payload.hex()


def _decode_control(packet: DecodedPacket, payload_data: bytes, contact_map: dict[str, str]) -> None:
    """Decode CONTROL payload structure.

    Format: [control_type:1][control_data:variable]
    - Bit 0x80 of control_type indicates zero-hop control packet
    - Upper 4 bits: sub_type (0x8=DISCOVER_REQ, 0x9=DISCOVER_RESP)
    """
    if len(payload_data) >= 1:
        control_type = payload_data[0]
        packet.control_type = f"0x{control_type:02x}"
        packet.control_is_zero_hop = (control_type & 0x80) != 0

        # Extract sub_type from upper 4 bits
        sub_type = (control_type >> 4) & 0x0F

        if len(payload_data) > 1:
            control_data = payload_data[1:]
            packet.control_data_hex = control_data.hex()

            # Decode DISCOVER_REQ (sub_type 0x8)
            if sub_type == 0x8 and len(control_data) >= 5:
                # Format: [type_filter:1][tag:4][since:4 (optional)]
                type_filter = control_data[0]
                tag = struct.unpack('<I', control_data[1:5])[0]

                packet.control_subtype = "DISCOVER_REQ"
                packet.discover_type_filter = f"0x{type_filter:02x}"
                packet.discover_tag = f"0x{tag:08x}"

                # Decode type_filter bits
                adv_types = []
                if type_filter & 0x01:
                    adv_types.append("CHAT")
                if type_filter & 0x02:
                    adv_types.append("REPEATER")
                if type_filter & 0x04:
                    adv_types.append("ROOM")
                if type_filter & 0x08:
                    adv_types.append("SENSOR")
                packet.discover_adv_types = adv_types

                # Check for optional 'since' timestamp
                if len(control_data) >= 9:
                    since = struct.unpack('<I', control_data[5:9])[0]
                    if since > 0:
                        from datetime import datetime
                        packet.discover_since = since
                        packet.discover_since_datetime = datetime.fromtimestamp(since).isoformat()

            # Decode DISCOVER_RESP (sub_type 0x9)
            elif sub_type == 0x9 and len(control_data) >= 6:
                # Format: [snr:1][tag:4][pubkey:8 or 32]
                # Lower 4 bits of control_type: node_type
                node_type = control_type & 0x0F
                node_type_names = {1: "CHAT", 2: "REPEATER", 3: "ROOM", 4: "SENSOR"}

                snr_byte = control_data[0]
                # SNR is signed, stored as SNR*4
                snr_signed = snr_byte if snr_byte < 128 else snr_byte - 256
                snr_float = snr_signed / 4.0

                tag = struct.unpack('<I', control_data[1:5])[0]

                packet.control_subtype = "DISCOVER_RESP"
                packet.discover_node_type = node_type_names.get(node_type, f"UNKNOWN_{node_type}")
                packet.discover_snr = snr_float
                packet.discover_tag = f"0x{tag:08x}"

                # Extract pubkey (8 bytes for prefix or 32 bytes for full key)
                pubkey_data = control_data[5:]
                if len(pubkey_data) >= 8:
                    # Check if it's 8-byte prefix or 32-byte full key
                    if len(pubkey_data) >= 32:
                        pubkey_hex = pubkey_data[:32].hex()
                        packet.discover_pubkey = pubkey_hex
                        packet.discover_pubkey_full = True
                    else:
                        pubkey_hex = pubkey_data[:8].hex()
                        packet.discover_pubkey = pubkey_hex
                        packet.discover_pubkey_full = False

                    # Try to match to contact
                    pubkey_prefix = pubkey_hex[:8] if len(pubkey_hex) >= 8 else pubkey_hex
                    if pubkey_prefix in contact_map:
                        packet.discover_contact_name = contact_map[pubkey_prefix]


def _decode_payload(
    packet: DecodedPacket,
    payload_type: int,
    payload_data: bytes,
    contact_map: dict[str, str]
) -> None:
    """Decode payload data based on type."""
    if payload_type == 0x0A:  # MULTIPART
        _decode_multipart(packet, payload_data)

    elif payload_type == 0x0B:  # CONTROL
        _decode_control(packet, payload_data, contact_map)

    elif payload_type == 0x03:  # ACK
        # Format: [ack_crc:4]
        if len(payload_data) >= 4:
            ack_crc = struct.unpack('<I', payload_data[:4])[0]
            packet.ack_crc = f"0x{ack_crc:08x}"

    elif payload_type == 0x09:  # TRACE
        # Format: [trace_tag:4][auth_code:4][flags:1][path_data:variable]
        if len(payload_data) >= 4:
            trace_tag = struct.unpack('<I', payload_data[:4])[0]
            packet.trace_tag = f"0x{trace_tag:08x}"

            if len(payload_data) >= 8:
                auth_code = struct.unpack('<I', payload_data[4:8])[0]
                packet.trace_auth = f"0x{auth_code:08x}"

            if len(payload_data) >= 9:
                flags = payload_data[8]
                packet.trace_flags = f"0x{flags:02x}"

                # Lower 2 bits of flags: path_sz (hash size: 0=1, 1=2, 2=4, 3=8 bytes)
                path_sz_bits = flags & 0x03
                path_hash_size = 1 << path_sz_bits  # Convert to actual byte size
                packet.trace_path_hash_size = path_hash_size

                if len(payload_data) > 9:
                    path_data = payload_data[9:]
                    packet.trace_path_data = path_data.hex()

                    # Parse path hashes and SNR values
                    # Path hashes are at positions determined by path_len
                    # Current offset calculation: offset = path_len << path_sz_bits
                    if packet.path_len is not None and packet.path_len > 0:
                        current_offset = packet.path_len << path_sz_bits
                        packet.trace_current_offset = current_offset

                        # Extract path hashes (before current offset)
                        if len(path_data) >= current_offset:
                            path_hashes = []
                            for i in range(packet.path_len):
                                start = i * path_hash_size
                                end = start + path_hash_size
                                if end <= len(path_data):
                                    hop_hash = path_data[start:end].hex()
                                    path_hashes.append(f"0x{hop_hash}")
                            packet.trace_path_hashes = path_hashes

                            # Extract SNR values (after current offset, 1 byte each, SNR*4)
                            if len(path_data) > current_offset:
                                snr_data = path_data[current_offset:]
                                snr_values = []
                                for snr_byte in snr_data:
                                    # SNR is signed, stored as SNR*4
                                    snr_signed = snr_byte if snr_byte < 128 else snr_byte - 256
                                    snr_float = snr_signed / 4.0
                                    snr_values.append(snr_float)
                                packet.trace_snr_values = snr_values

    elif payload_type in [0x00, 0x01, 0x02, 0x08]:  # REQ, RESPONSE, TXT_MSG, PATH
        # Format: [dest_hash:1][src_hash:1][MAC:2][encrypted_data]
        if len(payload_data) >= 4:
            dest_hash = payload_data[0]
            src_hash = payload_data[1]
            mac = payload_data[2:4]

            packet.dest_hash = f"0x{dest_hash:02x}"
            packet.src_hash = f"0x{src_hash:02x}"
            packet.mac = mac.hex()

            # Try to match hashes to contacts
            for pubkey, name in contact_map.items():
                if pubkey.startswith(f"{src_hash:02x}"):
                    packet.src_name = name
                    break
            for pubkey, name in contact_map.items():
                if pubkey.startswith(f"{dest_hash:02x}"):
                    packet.dest_name = name
                    break

            if len(payload_data) > 4:
                encrypted_data = payload_data[4:]
                packet.encrypted_data_hex = encrypted_data.hex()
                packet.encrypted_len = len(encrypted_data)

    elif payload_type == 0x04:  # ADVERT
        _decode_advert(packet, payload_data, contact_map)

    elif payload_type == 0x07:  # ANON_REQ
        # Format: [dest_hash:1][sender_pubkey:32][MAC:2][encrypted_data]
        if len(payload_data) >= 33:
            dest_hash = payload_data[0]
            sender_pubkey = payload_data[1:33]
            packet.dest_hash = f"0x{dest_hash:02x}"
            packet.anon_sender_pubkey = sender_pubkey.hex()

            # Check if sender matches any known contact
            sender_pubkey_hex = sender_pubkey.hex()
            if sender_pubkey_hex[:8].lower() in contact_map:
                packet.anon_sender_name = contact_map[sender_pubkey_hex[:8].lower()]

            if len(payload_data) >= 35:
                mac = payload_data[33:35]
                packet.mac = mac.hex()

                if len(payload_data) > 35:
                    encrypted_data = payload_data[35:]
                    packet.encrypted_data_hex = encrypted_data.hex()
                    packet.encrypted_len = len(encrypted_data)

    elif payload_type in [0x05, 0x06]:  # GRP_TXT, GRP_DATA
        # Format: [channel_hash:1][MAC:2][encrypted_data]
        if len(payload_data) >= 1:
            channel_hash = payload_data[0]
            packet.channel_hash = f"0x{channel_hash:02x}"

            if len(payload_data) >= 3:
                mac = payload_data[1:3]
                packet.mac = mac.hex()

                if len(payload_data) > 3:
                    encrypted_data = payload_data[3:]
                    packet.encrypted_data_hex = encrypted_data.hex()
                    packet.encrypted_len = len(encrypted_data)


def _decode_advert(
    packet: DecodedPacket,
    payload_data: bytes,
    contact_map: dict[str, str]
) -> None:
    """Decode ADVERT payload structure."""
    # Format: [pubkey:32][timestamp:4][signature:64][app_data:up to 32]
    if len(payload_data) >= 32:
        pubkey_hex = payload_data[:32].hex()
        packet.advert_pubkey = pubkey_hex
        # Check if this matches any known contact
        if pubkey_hex[:8].lower() in contact_map:
            packet.advert_contact_name = contact_map[pubkey_hex[:8].lower()]

        if len(payload_data) >= 36:
            # Extract timestamp
            timestamp_bytes = payload_data[32:36]
            timestamp = int.from_bytes(timestamp_bytes, 'little')
            packet.advert_timestamp = timestamp

        if len(payload_data) >= 100:
            # Extract signature (64 bytes)
            signature = payload_data[36:100]
            packet.advert_signature = signature.hex()

        if len(payload_data) > 100:
            # Parse app_data structure
            app_data = payload_data[100:]
            packet.advert_app_data_hex = app_data.hex()
            packet.advert_app_data_len = len(app_data)

            # Decode app_data structure
            if len(app_data) > 0:
                flags = app_data[0]
                offset = 1

                # Type (bits 0-3)
                adv_type = flags & 0x0F
                type_name = ADVERT_TYPES.get(adv_type, f"UNKNOWN_{adv_type}")
                packet.advert_type = type_name

                # Lat/Lon (if present)
                if flags & 0x10 and len(app_data) >= offset + 8:
                    lat_bytes = app_data[offset:offset+4]
                    lon_bytes = app_data[offset+4:offset+8]
                    lat_int = struct.unpack('<i', lat_bytes)[0]
                    lon_int = struct.unpack('<i', lon_bytes)[0]
                    packet.advert_lat = lat_int / 1_000_000.0
                    packet.advert_lon = lon_int / 1_000_000.0
                    offset += 8

                # Extra1 (future use, if present)
                if flags & 0x20 and len(app_data) >= offset + 2:
                    extra1 = struct.unpack('<H', app_data[offset:offset+2])[0]
                    packet.advert_extra1 = extra1
                    offset += 2

                # Extra2 (future use, if present)
                if flags & 0x40 and len(app_data) >= offset + 2:
                    extra2 = struct.unpack('<H', app_data[offset:offset+2])[0]
                    packet.advert_extra2 = extra2
                    offset += 2

                # Name (if present, remainder of app_data)
                if flags & 0x80 and len(app_data) > offset:
                    name_bytes = app_data[offset:]
                    name_str = name_bytes.decode('utf-8', errors='replace')
                    packet.advert_name = name_str.rstrip('\x00')


def apply_decryption_to_packet(
    packet: DecodedPacket,
    decryption_result: dict[str, Any],
    key_file: str | None = None
) -> None:
    """Map a decryption result dict into the corresponding DecodedPacket fields.

    This ensures all data lives in the model before the presentation layer
    renders it, keeping sniffer.py free of data extraction logic.

    Args:
        packet: The DecodedPacket to populate
        decryption_result: Dict returned by decrypt_packet_payload() or
                           decrypt_group_message()
        key_file: Optional label for which key was used to decrypt
    """
    if key_file:
        packet.decrypted_by = key_file

    # Common fields present in all decrypted results
    if 'contact_name' in decryption_result:
        packet.src_name = decryption_result['contact_name']
    if 'datetime' in decryption_result:
        packet.decrypted_datetime = decryption_result['datetime']
    if 'plaintext_hex' in decryption_result:
        packet.decrypted_plaintext_hex = decryption_result['plaintext_hex']

    # TXT_MSG fields
    if 'timestamp' in decryption_result and 'txt_type' in decryption_result:
        # 'timestamp' key is used for TXT_MSG (and GRP_TXT via legacy alias)
        packet.txt_timestamp = decryption_result['timestamp']
    if 'txt_type' in decryption_result:
        packet.txt_type = decryption_result['txt_type']
    if 'txt_type_name' in decryption_result:
        packet.txt_type_name = decryption_result['txt_type_name']
    if 'txt_attempt' in decryption_result:
        packet.txt_attempt = decryption_result['txt_attempt']
    if 'txt_signed_sender_prefix' in decryption_result:
        packet.txt_signed_sender_prefix = decryption_result['txt_signed_sender_prefix']
    if 'txt_plaintext_message' in decryption_result:
        packet.txt_plaintext_message = decryption_result['txt_plaintext_message']
    elif 'plaintext' in decryption_result and packet.txt_plaintext_message is None:
        # Legacy fallback: bare 'plaintext' key
        packet.txt_plaintext_message = decryption_result['plaintext']

    # REQ fields
    if 'req_timestamp' in decryption_result:
        packet.req_timestamp = decryption_result['req_timestamp']
    if 'req_type' in decryption_result:
        packet.req_type = decryption_result['req_type']
    if 'req_type_name' in decryption_result:
        packet.req_type_name = decryption_result['req_type_name']
    if 'req_data_hex' in decryption_result:
        packet.req_data_hex = decryption_result['req_data_hex']

    # RESPONSE fields
    if 'resp_timestamp' in decryption_result:
        packet.resp_timestamp = decryption_result['resp_timestamp']
    if 'resp_data_hex' in decryption_result:
        packet.resp_data_hex = decryption_result['resp_data_hex']
    if 'resp_neighbours_total_count' in decryption_result:
        packet.resp_neighbours_total_count = decryption_result['resp_neighbours_total_count']
    if 'resp_neighbours_results_count' in decryption_result:
        packet.resp_neighbours_results_count = decryption_result['resp_neighbours_results_count']
    if 'resp_neighbours_list' in decryption_result:
        packet.resp_neighbours_list = decryption_result['resp_neighbours_list']

    # PATH fields
    if 'path_return_len' in decryption_result:
        packet.path_return_len = decryption_result['path_return_len']
    if 'path_return_hops' in decryption_result:
        packet.path_return_hops = decryption_result['path_return_hops']
    if 'path_extra_type' in decryption_result:
        packet.path_extra_type = decryption_result['path_extra_type']
    if 'path_extra_type_name' in decryption_result:
        packet.path_extra_type_name = decryption_result['path_extra_type_name']
    if 'path_extra_payload_hex' in decryption_result:
        packet.path_extra_payload_hex = decryption_result['path_extra_payload_hex']
    if 'path_extra_ack_crc' in decryption_result:
        packet.path_extra_ack_crc = decryption_result['path_extra_ack_crc']

    # ANON_REQ fields
    if 'anon_req_timestamp' in decryption_result:
        packet.anon_req_timestamp = decryption_result['anon_req_timestamp']
    if 'anon_req_tag' in decryption_result:
        packet.anon_req_tag = decryption_result['anon_req_tag']
    if 'anon_room_sync_since' in decryption_result:
        packet.anon_room_sync_since = decryption_result['anon_room_sync_since']
    if 'anon_password' in decryption_result:
        packet.anon_password = decryption_result['anon_password']
    if 'anon_req_data_hex' in decryption_result:
        packet.anon_req_data_hex = decryption_result['anon_req_data_hex']

    # GRP_TXT / GRP_DATA fields
    if 'channel_name' in decryption_result:
        packet.channel_name = decryption_result['channel_name']
    if 'grp_timestamp' in decryption_result:
        packet.grp_timestamp = decryption_result['grp_timestamp']
    if 'grp_txt_type' in decryption_result:
        packet.grp_txt_type = decryption_result['grp_txt_type']
    if 'grp_txt_type_name' in decryption_result:
        packet.grp_txt_type_name = decryption_result['grp_txt_type_name']
    if 'grp_sender_name' in decryption_result:
        packet.grp_sender_name = decryption_result['grp_sender_name']
    if 'grp_message_text' in decryption_result:
        packet.grp_message_text = decryption_result['grp_message_text']

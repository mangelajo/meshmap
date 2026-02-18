"""Cryptographic utilities for decrypting meshcore packets."""

import struct
from datetime import datetime
from typing import Any

import nacl.bindings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# TXT_MSG type constants (from TxtDataHelpers.h)
TXT_TYPE_PLAIN = 0  # Plain text message
TXT_TYPE_CLI_DATA = 1  # CLI command
TXT_TYPE_SIGNED_PLAIN = 2  # Plain text, signed by sender

# REQ type constants (from BaseChatMesh.cpp)
REQ_TYPE_GET_STATS = 0x01  # Get stats of repeater or room server
REQ_TYPE_KEEP_ALIVE = 0x02  # Keep alive (deprecated)
REQ_TYPE_GET_TELEMETRY = 0x03  # Get telemetry data
REQ_TYPE_GET_MIN_MAX_AVG = 0x04  # Get min, max, average for time span
REQ_TYPE_GET_ACCESS_LIST = 0x05  # Get node's approved access list
REQ_TYPE_GET_NEIGHBORS = 0x06  # Get repeater node's neighbors
REQ_TYPE_GET_OWNER_INFO = 0x07  # Get repeater firmware-ver/name/owner info

# Payload type constants (for extra type in PATH packets)
PAYLOAD_TYPE_ACK = 0x03
PAYLOAD_TYPE_RESPONSE = 0x01

TXT_TYPE_NAMES = {
    TXT_TYPE_PLAIN: "PLAIN",
    TXT_TYPE_CLI_DATA: "CLI_DATA",
    TXT_TYPE_SIGNED_PLAIN: "SIGNED_PLAIN",
}

REQ_TYPE_NAMES = {
    REQ_TYPE_GET_STATS: "GET_STATS",
    REQ_TYPE_KEEP_ALIVE: "KEEP_ALIVE",
    REQ_TYPE_GET_TELEMETRY: "GET_TELEMETRY",
    REQ_TYPE_GET_MIN_MAX_AVG: "GET_MIN_MAX_AVG",
    REQ_TYPE_GET_ACCESS_LIST: "GET_ACCESS_LIST",
    REQ_TYPE_GET_NEIGHBORS: "GET_NEIGHBORS",
    REQ_TYPE_GET_OWNER_INFO: "GET_OWNER_INFO",
}


def derive_channel_secret(channel_name: str) -> bytes:
    """Derive channel secret from channel name.

    For public channels starting with '#', the secret is:
    SHA256(channel_name)[:16]

    Args:
        channel_name: Channel name (e.g., "#general", "#public")

    Returns:
        16-byte channel secret for AES-128
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(channel_name.encode("utf-8"))
    hash_bytes = digest.finalize()
    return hash_bytes[:16]  # First 16 bytes for AES-128


def compute_shared_secret(private_key_bytes: bytes, public_key_bytes: bytes) -> bytes:
    """Compute ECDH shared secret using X25519.

    MeshCore uses orlp/ed25519 library where the 64-byte private key is:
    - Bytes 0-31: Clamped scalar (the actual secret)
    - Bytes 32-63: Nonce seed (for signatures, not used in ECDH)

    Args:
        private_key_bytes: Your Ed25519 private key (64 bytes, orlp format)
        public_key_bytes: Their Ed25519 public key (32 bytes)

    Returns:
        Shared secret (32 bytes)
    """
    # Extract the scalar (first 32 bytes) - this is already clamped
    # MeshCore's ed25519_key_exchange uses this directly for X25519
    curve25519_sk = private_key_bytes[:32]

    # Convert Ed25519 public key to Curve25519 (X25519) public key
    # This uses libsodium's crypto_sign_ed25519_pk_to_curve25519
    curve25519_pk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(public_key_bytes)

    # Perform X25519 scalar multiplication (ECDH)
    shared_secret = nacl.bindings.crypto_scalarmult(curve25519_sk, curve25519_pk)

    return shared_secret


def verify_mac_and_decrypt(shared_secret: bytes, mac_and_ciphertext: bytes) -> bytes | None:
    """Verify MAC and decrypt AES-128 encrypted data.

    Args:
        shared_secret: The ECDH shared secret or channel key (16 or 32 bytes)
        mac_and_ciphertext: MAC (2 bytes) + encrypted data

    Returns:
        Decrypted plaintext if MAC is valid, None otherwise
    """
    if len(mac_and_ciphertext) < 2:
        return None

    # Extract MAC and ciphertext
    mac = mac_and_ciphertext[:2]
    ciphertext = mac_and_ciphertext[2:]

    # Use first 16 bytes of shared secret as AES-128 key
    aes_key = shared_secret[:16]

    # Decrypt ciphertext (AES-128 in ECB mode, as used by MeshCore)
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Verify MAC using HMAC-SHA256 with the full shared secret
    # For channel messages, shared_secret should already be 32 bytes (16-byte key + 16 zero padding)
    # For peer messages, shared_secret is the full 32-byte ECDH result
    computed_mac = compute_mac(shared_secret, ciphertext)

    if mac != computed_mac:
        return None  # MAC verification failed

    # Remove padding (trailing zeros)
    plaintext = plaintext.rstrip(b"\x00")

    return plaintext


def compute_mac(key: bytes, data: bytes) -> bytes:
    """Compute 2-byte HMAC-SHA256 MAC for data.

    MeshCore uses HMAC-SHA256 with the shared secret as the HMAC key,
    then truncates to 2 bytes.

    Args:
        key: Shared secret (32 bytes for peer messages, 16 bytes for channels)
        data: Data to MAC (the ciphertext)

    Returns:
        2-byte MAC
    """
    # Compute HMAC-SHA256
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    hmac_bytes = h.finalize()

    # Return first 2 bytes
    return hmac_bytes[:2]


def parse_txt_msg_plaintext(plaintext: bytes) -> dict[str, Any]:
    """Parse TXT_MSG decrypted plaintext structure.

    Format: [timestamp:4][txt_type_and_attempt:1][message:variable]
    - Upper 6 bits of byte 4: txt_type
    - Lower 2 bits of byte 4: attempt number (0-3)
    - For SIGNED_PLAIN: [timestamp:4][txt_type:1][sender_prefix:4][message:variable]

    Args:
        plaintext: Decrypted plaintext bytes

    Returns:
        Dict with parsed fields: txt_type, txt_type_name, txt_attempt, plaintext_message
    """
    result: dict[str, Any] = {}

    if len(plaintext) >= 5:
        timestamp = struct.unpack("<I", plaintext[:4])[0]
        txt_type_byte = plaintext[4]

        # Extract txt_type (upper 6 bits) and attempt (lower 2 bits)
        txt_type = (txt_type_byte >> 2) & 0x3F
        attempt = txt_type_byte & 0x03

        result["timestamp"] = timestamp
        result["datetime"] = datetime.fromtimestamp(timestamp).isoformat()
        result["txt_type"] = txt_type
        result["txt_type_name"] = TXT_TYPE_NAMES.get(txt_type, f"UNKNOWN_{txt_type}")
        result["txt_attempt"] = attempt

        # Parse message based on txt_type
        if txt_type == TXT_TYPE_SIGNED_PLAIN and len(plaintext) >= 9:
            # Signed plain text: includes 4-byte sender prefix
            sender_prefix = plaintext[5:9].hex()
            message_text = plaintext[9:].decode("utf-8", errors="replace")
            result["txt_signed_sender_prefix"] = sender_prefix
            result["txt_plaintext_message"] = message_text
        else:
            # Plain or CLI_DATA: message starts at byte 5
            message_text = plaintext[5:].decode("utf-8", errors="replace")
            result["txt_plaintext_message"] = message_text

    return result


def parse_req_plaintext(plaintext: bytes) -> dict[str, Any]:
    """Parse REQ decrypted plaintext structure.

    Format: [timestamp:4][req_type:1][req_data:variable]

    Args:
        plaintext: Decrypted plaintext bytes

    Returns:
        Dict with parsed fields: req_timestamp, req_type, req_type_name, req_data_hex
    """
    result: dict[str, Any] = {}

    if len(plaintext) >= 5:
        timestamp = struct.unpack("<I", plaintext[:4])[0]
        req_type = plaintext[4]

        result["req_timestamp"] = timestamp
        result["datetime"] = datetime.fromtimestamp(timestamp).isoformat()
        result["req_type"] = req_type
        result["req_type_name"] = REQ_TYPE_NAMES.get(req_type, f"UNKNOWN_0x{req_type:02x}")

        if len(plaintext) > 5:
            req_data = plaintext[5:]
            result["req_data_hex"] = req_data.hex()

    return result


def parse_response_plaintext(
    plaintext: bytes, contacts: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Parse RESPONSE decrypted plaintext structure.

    Format: [timestamp:4][response_data:variable]

    For GET_NEIGHBORS responses:
    [timestamp:4][neighbours_count:2][results_count:2][neighbor_entries:variable]
    Each neighbor entry: [pubkey:variable][heard_seconds_ago:4][snr:1]

    Args:
        plaintext: Decrypted plaintext bytes
        contacts: Optional contact map to resolve neighbor names

    Returns:
        Dict with parsed fields: resp_timestamp, resp_data_hex, and for GET_NEIGHBORS:
        resp_neighbours_total_count, resp_neighbours_results_count, resp_neighbours_list
    """
    result: dict[str, Any] = {}
    if contacts is None:
        contacts = {}

    if len(plaintext) >= 4:
        timestamp = struct.unpack("<I", plaintext[:4])[0]
        result["resp_timestamp"] = timestamp
        result["datetime"] = datetime.fromtimestamp(timestamp).isoformat()

        if len(plaintext) > 4:
            resp_data = plaintext[4:]
            result["resp_data_hex"] = resp_data.hex()

            # Try to parse as GET_NEIGHBORS response if it has the right structure
            # Format: [neighbours_count:2][results_count:2][entries...]
            if len(resp_data) >= 4:
                try:
                    neighbours_count = struct.unpack("<H", resp_data[0:2])[0]
                    results_count = struct.unpack("<H", resp_data[2:4])[0]

                    # Sanity check: results_count should be <= neighbours_count
                    # and not absurdly large
                    if 0 <= results_count <= neighbours_count <= 1000:
                        # Try to parse neighbor entries
                        entries_data = resp_data[4:]

                        # Calculate entry size: (total_data_len) / results_count
                        if results_count > 0 and len(entries_data) > 0:
                            entry_size = len(entries_data) // results_count

                            # Entry must be at least 5 bytes
                            # (min 1 byte pubkey + 4 bytes time + 1 byte snr)
                            if entry_size >= 5:
                                pubkey_prefix_len = entry_size - 5

                                neighbors = []
                                offset = 0

                                for _ in range(results_count):
                                    if offset + entry_size <= len(entries_data):
                                        # Extract neighbor entry
                                        pk_start = offset
                                        pk_end = offset + pubkey_prefix_len
                                        pubkey = entries_data[pk_start:pk_end]

                                        time_start = pk_end
                                        time_end = pk_end + 4
                                        heard_ago = struct.unpack(
                                            "<I", entries_data[time_start:time_end]
                                        )[0]

                                        snr_pos = time_end
                                        snr_byte = struct.unpack(
                                            "b", entries_data[snr_pos : snr_pos + 1]
                                        )[0]
                                        snr_float = snr_byte / 4.0

                                        # Match pubkey against contacts
                                        pubkey_hex = pubkey.hex()
                                        contact_name = None
                                        for contact_key, contact_info in contacts.items():
                                            # Match on prefix
                                            if contact_key.lower().startswith(pubkey_hex.lower()):
                                                contact_name = contact_info.get(
                                                    "adv_name", "Unknown"
                                                )
                                                break

                                        neighbor_entry = {
                                            "pubkey": pubkey_hex,
                                            "heard_seconds_ago": heard_ago,
                                            "snr": snr_float,
                                        }
                                        if contact_name:
                                            neighbor_entry["name"] = contact_name

                                        neighbors.append(neighbor_entry)

                                        offset += entry_size

                                # Only include neighbor parsing if we successfully
                                # parsed all entries
                                if len(neighbors) == results_count:
                                    result["resp_neighbours_total_count"] = neighbours_count
                                    result["resp_neighbours_results_count"] = results_count
                                    result["resp_neighbours_list"] = neighbors
                except (struct.error, ValueError):
                    # Not a GET_NEIGHBORS response, or parsing failed - just keep resp_data_hex
                    pass

    return result


def parse_path_plaintext(plaintext: bytes) -> dict[str, Any]:
    """Parse PATH decrypted plaintext structure.

    Format: [path_len:1][path:path_len][extra_type:1][extra:variable]
    - extra_type can be PAYLOAD_TYPE_ACK (0x03), PAYLOAD_TYPE_RESPONSE (0x01), or 0xFF (dummy)
    - For ACK: extra is [ack_crc:4]

    Args:
        plaintext: Decrypted plaintext bytes

    Returns:
        Dict with parsed fields: path_return_len, path_return_hops, path_extra_type, etc.
    """
    result: dict[str, Any] = {}

    if len(plaintext) >= 1:
        path_len = plaintext[0]
        result["path_return_len"] = path_len

        if len(plaintext) >= 1 + path_len + 1:
            # Extract path hops
            path_hops = [f"0x{b:02x}" for b in plaintext[1 : 1 + path_len]]
            result["path_return_hops"] = path_hops

            # Extract extra_type
            extra_type = plaintext[1 + path_len]
            result["path_extra_type"] = extra_type

            if extra_type == PAYLOAD_TYPE_ACK:
                result["path_extra_type_name"] = "ACK"
                # Parse ACK payload: [ack_crc:4]
                if len(plaintext) >= 1 + path_len + 1 + 4:
                    ack_crc = struct.unpack("<I", plaintext[1 + path_len + 1 : 1 + path_len + 5])[0]
                    result["path_extra_ack_crc"] = f"0x{ack_crc:08x}"
            elif extra_type == PAYLOAD_TYPE_RESPONSE:
                result["path_extra_type_name"] = "RESPONSE"
                if len(plaintext) > 1 + path_len + 1:
                    extra_payload = plaintext[1 + path_len + 1 :]
                    result["path_extra_payload_hex"] = extra_payload.hex()
            elif extra_type == 0xFF:
                result["path_extra_type_name"] = "DUMMY"
            else:
                result["path_extra_type_name"] = f"UNKNOWN_0x{extra_type:02x}"
                if len(plaintext) > 1 + path_len + 1:
                    extra_payload = plaintext[1 + path_len + 1 :]
                    result["path_extra_payload_hex"] = extra_payload.hex()

    return result


def parse_anon_req_plaintext(plaintext: bytes, recipient_type: str | None = None) -> dict[str, Any]:
    """Parse ANON_REQ decrypted plaintext structure.

    Format depends on recipient type:
    - ROOM: [timestamp:4][sync_since:4][password:up to 15 bytes]
    - Other: [timestamp:4][password:up to 15 bytes]
    - Generic: [tag:4][req_data:variable]

    Args:
        plaintext: Decrypted plaintext bytes
        recipient_type: Optional recipient type ('ROOM', 'REPEATER', 'SENSOR', None)

    Returns:
        Dict with parsed fields based on type
    """
    result: dict[str, Any] = {}

    if len(plaintext) >= 4:
        timestamp = struct.unpack("<I", plaintext[:4])[0]
        result["anon_req_timestamp"] = timestamp
        result["datetime"] = datetime.fromtimestamp(timestamp).isoformat()

        if recipient_type == "ROOM" and len(plaintext) >= 8:
            # Room login: [timestamp:4][sync_since:4][password:variable]
            sync_since = struct.unpack("<I", plaintext[4:8])[0]
            result["anon_room_sync_since"] = sync_since

            if len(plaintext) > 8:
                password = plaintext[8:].decode("utf-8", errors="replace").rstrip("\x00")
                result["anon_password"] = password
        elif recipient_type in ["REPEATER", "SENSOR"] and len(plaintext) > 4:
            # Repeater/Sensor login: [timestamp:4][password:variable]
            password = plaintext[4:].decode("utf-8", errors="replace").rstrip("\x00")
            result["anon_password"] = password
        elif len(plaintext) > 4:
            # Generic ANON_REQ: could be various formats
            # Try to parse as tag + data
            req_data = plaintext[4:]
            result["anon_req_data_hex"] = req_data.hex()

    return result


def parse_grp_txt_plaintext(plaintext: bytes) -> dict[str, Any]:
    """Parse GRP_TXT/GRP_DATA decrypted plaintext structure.

    Format: [timestamp:4][txt_type:1][message:variable]
    For txt_type=0: message is "sender_name: message_text"

    Args:
        plaintext: Decrypted plaintext bytes

    Returns:
        Dict with parsed fields: grp_timestamp, grp_txt_type, grp_sender_name, grp_message_text
    """
    result: dict[str, Any] = {}

    if len(plaintext) >= 5:
        timestamp = struct.unpack("<I", plaintext[:4])[0]
        txt_type = plaintext[4]
        message = plaintext[5:].decode("utf-8", errors="replace").rstrip("\x00")

        result["grp_timestamp"] = timestamp
        result["datetime"] = datetime.fromtimestamp(timestamp).isoformat()
        result["grp_txt_type"] = txt_type
        result["grp_txt_type_name"] = TXT_TYPE_NAMES.get(txt_type, f"UNKNOWN_{txt_type}")

        # For GRP_TXT with txt_type=0, message format is "sender_name: message_text"
        if txt_type == TXT_TYPE_PLAIN and ": " in message:
            parts = message.split(": ", 1)
            result["grp_sender_name"] = parts[0]
            result["grp_message_text"] = parts[1] if len(parts) > 1 else ""
            result["raw_message"] = message
        else:
            result["grp_message_text"] = message

    return result


def decrypt_packet_payload(
    packet_type: str,
    payload_hex: str,
    private_key_hex: str,
    contacts: dict[str, Any],
    debug: bool = False,
) -> dict[str, Any] | None:
    """Decrypt a meshcore packet payload.

    Args:
        packet_type: Type of packet (REQ, RESPONSE, TXT_MSG, etc.)
        payload_hex: Hex string of the packet payload
        private_key_hex: Your private key in hex (128 chars = 64 bytes)
        contacts: Dictionary of contacts (pubkey -> contact info)
        debug: Enable debug logging

    Returns:
        Dict with decrypted data and metadata, or None if decryption fails
    """
    payload = bytes.fromhex(payload_hex)
    private_key = bytes.fromhex(private_key_hex)

    if packet_type in ["REQ", "RESPONSE", "TXT_MSG", "PATH"]:
        # Format: [dest_hash:1][src_hash:1][MAC+encrypted]
        if len(payload) < 4:
            return {"error": "Payload too short (< 4 bytes)"}

        dest_hash = payload[0:1]
        src_hash = payload[1:2]  # Second byte is the source hash
        mac_and_data = payload[2:]

        if debug:
            print(
                f"[DEBUG] Decrypting {packet_type}: dest=0x{dest_hash.hex()}, src=0x{src_hash.hex()}, mac_and_data={len(mac_and_data)} bytes"
            )

        # Find contact matching src_hash
        matching_contact = None
        for pubkey, contact in contacts.items():
            if pubkey[:2].lower() == src_hash.hex().lower():
                matching_contact = (pubkey, contact)
                if debug:
                    print(
                        f"[DEBUG] Found matching contact: {contact.get('adv_name', 'Unknown')} (pubkey: {pubkey[:16]}...)"
                    )
                break

        if not matching_contact:
            err_msg = f"No matching contact found for src_hash 0x{src_hash.hex()}"
            if debug:
                print(f"[DEBUG] {err_msg}")
                print(f"[DEBUG] Available contacts: {[pk[:2] for pk in contacts.keys()]}")
            return {"error": err_msg}

        pubkey_hex, contact_info = matching_contact
        pubkey_bytes = bytes.fromhex(pubkey_hex)

        if debug:
            print(f"[DEBUG] Private key length: {len(private_key)} bytes")
            print(f"[DEBUG] Sender public key length: {len(pubkey_bytes)} bytes")
            # Extract public key from private key (last 32 bytes of 64-byte Ed25519 sk)
            if len(private_key) == 64:
                embedded_pubkey = private_key[32:64]
                print(
                    f"[DEBUG] Public key embedded in private key: {embedded_pubkey.hex()[:16]}..."
                )
                print(f"[DEBUG] Recipient hash from packet: 0x{dest_hash.hex()}")
                print(f"[DEBUG] Sender hash from packet: 0x{src_hash.hex()}")
                print(
                    f"[DEBUG] Does embedded pubkey match recipient? {embedded_pubkey.hex()[:2] == dest_hash.hex()}"
                )
            print(f"[DEBUG] Sender public key (from contacts): {pubkey_bytes.hex()[:16]}...")

        # Compute shared secret
        try:
            shared_secret = compute_shared_secret(private_key, pubkey_bytes)
            if debug:
                print(f"[DEBUG] Computed shared secret: {shared_secret.hex()[:32]}...")
        except Exception as e:
            err_msg = f"Failed to compute shared secret: {e}"
            if debug:
                print(f"[DEBUG] {err_msg}")
                import traceback

                traceback.print_exc()
            return {"error": err_msg}

        # Decrypt payload
        plaintext = verify_mac_and_decrypt(shared_secret, mac_and_data)

        if plaintext is None:
            err_msg = "MAC verification failed or decryption error"
            if debug:
                print(f"[DEBUG] {err_msg}")
                print(f"[DEBUG] MAC (from packet): {mac_and_data[:2].hex()}")
                # Compute what we expect the MAC to be
                aes_key = shared_secret[:16]
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

                cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
                decryptor = cipher.decryptor()
                test_plaintext = decryptor.update(mac_and_data[2:]) + decryptor.finalize()
                computed_mac = compute_mac(shared_secret, mac_and_data[2:])
                print(f"[DEBUG] MAC (computed): {computed_mac.hex()}")
                print(f"[DEBUG] Decrypted (before MAC check): {test_plaintext.hex()[:64]}...")
            return {"error": err_msg}

        if debug:
            print(f"[DEBUG] Successfully decrypted! Plaintext: {plaintext.hex()[:64]}...")

        # Base result
        result: dict[str, Any] = {
            "success": True,
            "dest_hash": dest_hash.hex(),
            "src_hash": src_hash.hex(),
            "contact_name": contact_info.get("adv_name", "Unknown"),
            "plaintext_hex": plaintext.hex(),
        }

        # Parse plaintext based on packet type
        if packet_type == "TXT_MSG":
            parsed = parse_txt_msg_plaintext(plaintext)
            result.update(parsed)
            # Keep legacy 'plaintext' field for backward compatibility
            if "txt_plaintext_message" in parsed:
                result["plaintext"] = parsed["txt_plaintext_message"]
        elif packet_type == "REQ":
            parsed = parse_req_plaintext(plaintext)
            result.update(parsed)
        elif packet_type == "RESPONSE":
            parsed = parse_response_plaintext(plaintext, contacts)
            result.update(parsed)
        elif packet_type == "PATH":
            parsed = parse_path_plaintext(plaintext)
            result.update(parsed)
        else:
            # Fallback: parse basic timestamp + message structure
            if len(plaintext) >= 5:
                timestamp = struct.unpack("<I", plaintext[:4])[0]
                msg_type = plaintext[4]
                message_text = plaintext[5:].decode("utf-8", errors="replace")

                result["timestamp"] = timestamp
                result["datetime"] = datetime.fromtimestamp(timestamp).isoformat()
                result["msg_type"] = msg_type
                result["plaintext"] = message_text
            else:
                result["plaintext"] = plaintext.decode("utf-8", errors="replace")

        return result

    elif packet_type == "ANON_REQ":
        # Format: [dest_hash:1][sender_pubkey:32][MAC+encrypted]
        if len(payload) < 35:
            return None

        dest_hash = payload[0:1]
        sender_pubkey = payload[1:33]
        mac_and_data = payload[33:]

        # Compute shared secret with sender's ephemeral key
        try:
            shared_secret = compute_shared_secret(private_key, sender_pubkey)
        except Exception as e:
            return {"error": f"Failed to compute shared secret: {e}"}

        # Decrypt payload
        plaintext = verify_mac_and_decrypt(shared_secret, mac_and_data)

        if plaintext is None:
            return {"error": "MAC verification failed or decryption error"}

        result = {
            "success": True,
            "dest_hash": dest_hash.hex(),
            "sender_pubkey": sender_pubkey.hex(),
            "plaintext_hex": plaintext.hex(),
        }

        # Parse ANON_REQ plaintext (we don't know recipient type, so pass None)
        parsed = parse_anon_req_plaintext(plaintext, recipient_type=None)
        result.update(parsed)

        # Keep legacy 'plaintext' field for backward compatibility
        if "anon_password" in parsed:
            result["plaintext"] = parsed["anon_password"]
        elif "anon_req_data_hex" in parsed:
            result["plaintext"] = plaintext.decode("utf-8", errors="replace")
        else:
            result["plaintext"] = plaintext.decode("utf-8", errors="replace")

        return result

    elif packet_type in ["GRP_TXT", "GRP_DATA"]:
        # Format: [channel_hash:1][MAC+encrypted]
        # Encrypted payload: [timestamp:4][txt_type:1]["sender: message"]
        # Note: Requires knowing the channel name to derive the secret
        if len(payload) < 3:
            return None

        channel_hash = payload[0]
        mac_and_data = payload[1:]

        return {
            "error": "Group message decryption requires channel name",
            "channel_hash": f"0x{channel_hash:02x}",
            "hint": "Use decrypt_group_message() with channel name",
        }

    else:
        return {"error": f"Unsupported packet type: {packet_type}"}


def decrypt_group_message(payload_hex: str, channel_names: list[str]) -> dict[str, Any] | None:
    """Decrypt a group message (GRP_TXT or GRP_DATA).

    Args:
        payload_hex: Hex string of the GRP_TXT/GRP_DATA payload
        channel_names: List of channel names to try (e.g., ["#general", "#public"])

    Returns:
        Dict with decrypted data and metadata, or None if decryption fails
    """
    payload = bytes.fromhex(payload_hex)

    if len(payload) < 3:
        return {"error": "Payload too short"}

    channel_hash = payload[0]
    mac_and_data = payload[1:]

    # Try each channel name
    for channel_name in channel_names:
        channel_secret = derive_channel_secret(channel_name)

        # Decrypt payload
        plaintext = verify_mac_and_decrypt(channel_secret + b"\x00" * 16, mac_and_data)

        if plaintext is not None:
            # Successfully decrypted!
            result = {
                "success": True,
                "channel_name": channel_name,
                "channel_hash": f"0x{channel_hash:02x}",
                "plaintext_hex": plaintext.hex(),
            }

            # Parse group message plaintext
            parsed = parse_grp_txt_plaintext(plaintext)
            result.update(parsed)

            # Keep legacy field names for backward compatibility
            if "grp_timestamp" in parsed:
                result["timestamp"] = parsed["grp_timestamp"]
            if "grp_txt_type" in parsed:
                result["txt_type"] = parsed["grp_txt_type"]
            if "grp_sender_name" in parsed:
                result["sender"] = parsed["grp_sender_name"]
            if "grp_message_text" in parsed:
                result["message"] = parsed["grp_message_text"]

            return result

    return {
        "error": "Failed to decrypt with any provided channel name",
        "channel_hash": f"0x{channel_hash:02x}",
        "tried_channels": channel_names,
    }

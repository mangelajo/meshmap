"""Cryptographic utilities for decrypting meshcore packets."""

from typing import Any

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


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
    digest.update(channel_name.encode('utf-8'))
    hash_bytes = digest.finalize()
    return hash_bytes[:16]  # First 16 bytes for AES-128


def compute_shared_secret(private_key_bytes: bytes, public_key_bytes: bytes) -> bytes:
    """Compute ECDH shared secret using X25519.

    Args:
        private_key_bytes: Your Ed25519 private key (64 bytes)
        public_key_bytes: Their Ed25519 public key (32 bytes)

    Returns:
        Shared secret (32 bytes)
    """
    # Note: Ed25519 keys need to be converted to X25519 for ECDH
    # This is a simplified version - actual conversion is more complex
    # See: https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519

    # Convert Ed25519 private key to X25519 (first 32 bytes)
    x25519_private = X25519PrivateKey.from_private_bytes(private_key_bytes[:32])

    # Convert Ed25519 public key to X25519
    x25519_public = X25519PublicKey.from_public_bytes(public_key_bytes)

    # Perform ECDH
    shared_secret = x25519_private.exchange(x25519_public)

    return shared_secret


def verify_mac_and_decrypt(
    shared_secret: bytes,
    mac_and_ciphertext: bytes
) -> bytes | None:
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
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Verify MAC using HMAC-SHA256 with the full shared secret
    # For channel messages, shared_secret should already be 32 bytes (16-byte key + 16 zero padding)
    # For peer messages, shared_secret is the full 32-byte ECDH result
    computed_mac = compute_mac(shared_secret, ciphertext)

    if mac != computed_mac:
        return None  # MAC verification failed

    # Remove padding (trailing zeros)
    plaintext = plaintext.rstrip(b'\x00')

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


def decrypt_packet_payload(
    packet_type: str,
    payload_hex: str,
    private_key_hex: str,
    contacts: dict[str, Any]
) -> dict[str, Any] | None:
    """Decrypt a meshcore packet payload.

    Args:
        packet_type: Type of packet (REQ, RESPONSE, TXT_MSG, etc.)
        payload_hex: Hex string of the packet payload
        private_key_hex: Your private key in hex (128 chars = 64 bytes)
        contacts: Dictionary of contacts (pubkey -> contact info)

    Returns:
        Dict with decrypted data and metadata, or None if decryption fails
    """
    payload = bytes.fromhex(payload_hex)
    private_key = bytes.fromhex(private_key_hex)

    if packet_type in ['REQ', 'RESPONSE', 'TXT_MSG', 'PATH']:
        # Format: [dest_hash:1][src_hash:1][MAC+encrypted]
        if len(payload) < 4:
            return None

        dest_hash = payload[0:1]
        src_hash = payload[0:1]  # Note: both hashes are 1 byte (prefix of pubkey)
        mac_and_data = payload[2:]

        # Find contact matching src_hash
        matching_contact = None
        for pubkey, contact in contacts.items():
            if pubkey[:2].lower() == src_hash.hex().lower():
                matching_contact = (pubkey, contact)
                break

        if not matching_contact:
            return {'error': 'No matching contact found for src_hash'}

        pubkey_hex, contact_info = matching_contact
        pubkey_bytes = bytes.fromhex(pubkey_hex)

        # Compute shared secret
        try:
            shared_secret = compute_shared_secret(private_key, pubkey_bytes)
        except Exception as e:
            return {'error': f'Failed to compute shared secret: {e}'}

        # Decrypt payload
        plaintext = verify_mac_and_decrypt(shared_secret, mac_and_data)

        if plaintext is None:
            return {'error': 'MAC verification failed or decryption error'}

        return {
            'success': True,
            'dest_hash': dest_hash.hex(),
            'src_hash': src_hash.hex(),
            'contact_name': contact_info.get('adv_name', 'Unknown'),
            'plaintext_hex': plaintext.hex(),
            'plaintext': plaintext.decode('utf-8', errors='replace'),
        }

    elif packet_type == 'ANON_REQ':
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
            return {'error': f'Failed to compute shared secret: {e}'}

        # Decrypt payload
        plaintext = verify_mac_and_decrypt(shared_secret, mac_and_data)

        if plaintext is None:
            return {'error': 'MAC verification failed or decryption error'}

        return {
            'success': True,
            'dest_hash': dest_hash.hex(),
            'sender_pubkey': sender_pubkey.hex(),
            'plaintext_hex': plaintext.hex(),
            'plaintext': plaintext.decode('utf-8', errors='replace'),
        }

    elif packet_type in ['GRP_TXT', 'GRP_DATA']:
        # Format: [channel_hash:1][MAC+encrypted]
        # Encrypted payload: [timestamp:4][txt_type:1]["sender: message"]
        # Note: Requires knowing the channel name to derive the secret
        if len(payload) < 3:
            return None

        channel_hash = payload[0]
        mac_and_data = payload[1:]

        return {
            'error': 'Group message decryption requires channel name',
            'channel_hash': f"0x{channel_hash:02x}",
            'hint': 'Use decrypt_group_message() with channel name'
        }

    else:
        return {'error': f'Unsupported packet type: {packet_type}'}


def decrypt_group_message(
    payload_hex: str,
    channel_names: list[str]
) -> dict[str, Any] | None:
    """Decrypt a group message (GRP_TXT or GRP_DATA).

    Args:
        payload_hex: Hex string of the GRP_TXT/GRP_DATA payload
        channel_names: List of channel names to try (e.g., ["#general", "#public"])

    Returns:
        Dict with decrypted data and metadata, or None if decryption fails
    """
    payload = bytes.fromhex(payload_hex)

    if len(payload) < 3:
        return {'error': 'Payload too short'}

    channel_hash = payload[0]
    mac_and_data = payload[1:]

    # Try each channel name
    for channel_name in channel_names:
        channel_secret = derive_channel_secret(channel_name)

        # Decrypt payload
        plaintext = verify_mac_and_decrypt(channel_secret + b'\x00' * 16, mac_and_data)

        if plaintext is not None:
            # Successfully decrypted!
            # Parse decrypted data: [timestamp:4][txt_type:1][message]
            if len(plaintext) >= 5:
                import struct
                timestamp = struct.unpack('<I', plaintext[:4])[0]
                txt_type = plaintext[4]
                message = plaintext[5:].decode('utf-8', errors='replace').rstrip('\x00')

                # For GRP_TXT, message format is "sender_name: message text"
                sender_name = "Unknown"
                message_text = message
                if ': ' in message:
                    parts = message.split(': ', 1)
                    sender_name = parts[0]
                    message_text = parts[1] if len(parts) > 1 else ""

                return {
                    'success': True,
                    'channel_name': channel_name,
                    'channel_hash': f"0x{channel_hash:02x}",
                    'timestamp': timestamp,
                    'txt_type': txt_type,
                    'sender': sender_name,
                    'message': message_text,
                    'raw_message': message,
                    'plaintext_hex': plaintext.hex(),
                }

    return {
        'error': 'Failed to decrypt with any provided channel name',
        'channel_hash': f"0x{channel_hash:02x}",
        'tried_channels': channel_names
    }

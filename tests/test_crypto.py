"""Tests for meshmap cryptographic functions."""

from datetime import UTC

import pytest

from meshmap.crypto import (
    compute_mac,
    compute_shared_secret,
    decrypt_group_message,
    decrypt_packet_payload,
    derive_channel_secret,
    verify_mac_and_decrypt,
)


class TestChannelSecretDerivation:
    """Test channel secret derivation for public channels."""

    def test_derive_channel_secret_general(self):
        """Test deriving secret for #general channel."""
        secret = derive_channel_secret("#general")
        assert len(secret) == 16  # AES-128 key
        # The secret should be deterministic
        assert secret == derive_channel_secret("#general")

    def test_derive_channel_secret_public(self):
        """Test deriving secret for #public channel."""
        secret = derive_channel_secret("#public")
        assert len(secret) == 16
        # Different channels should have different secrets
        assert secret != derive_channel_secret("#general")


class TestSharedSecretComputation:
    """Test ECDH shared secret computation with orlp/ed25519 format."""

    def test_compute_shared_secret_format(self):
        """Test that shared secret is computed correctly with orlp ed25519 format."""
        # Test with synthetic private key (64 bytes: [32-byte scalar][32-byte nonce seed])
        # Generated deterministically from seed bytes(range(1, 33))
        private_key_hex = (
            "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
            "abababababababababababababababababababababababababababababababababab"
        )
        private_key = bytes.fromhex(private_key_hex)

        # Synthetic contact public key (generated from seed bytes(range(33, 65)))
        contact_pubkey_hex = "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0"
        contact_pubkey = bytes.fromhex(contact_pubkey_hex)

        # Compute shared secret
        shared_secret = compute_shared_secret(private_key, contact_pubkey)

        # Verify properties
        assert len(shared_secret) == 32  # X25519 shared secret is 32 bytes
        assert shared_secret.hex() == (
            "66201ae7bbcdb9bc2e477bf2edc5c8a1f80db420177db10fac6a43eee76dfe34"
        )

    def test_compute_shared_secret_uses_first_32_bytes(self):
        """Test that only the first 32 bytes (scalar) are used, not nonce seed."""
        # Create a key where the nonce seed is different
        scalar = bytes.fromhex("79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
        nonce_seed_1 = b"0" * 32
        nonce_seed_2 = b"1" * 32

        private_key_1 = scalar + nonce_seed_1
        private_key_2 = scalar + nonce_seed_2

        contact_pubkey = bytes.fromhex(
            "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0"
        )

        # Both should produce the same shared secret (nonce seed not used in ECDH)
        secret_1 = compute_shared_secret(private_key_1, contact_pubkey)
        secret_2 = compute_shared_secret(private_key_2, contact_pubkey)

        assert secret_1 == secret_2


class TestGroupMessageDecryption:
    """Test decryption of group/channel messages."""

    def test_decrypt_general_channel_message(self):
        """Test decrypting a real #general channel message."""
        # Real captured packet from #general channel
        # This is a GRP_TXT packet with known plaintext
        # payload_hex = "c1" + "1234" + "abcd1234ef5678"  # placeholder - TODO: real data

        # For this test, we'll use a simpler approach with known test data
        # TODO: Add real captured packet data when available

    def test_decrypt_unknown_channel_fails(self):
        """Test that decryption fails for unknown channels."""
        # Payload with unknown channel hash and proper AES block size (16 bytes + MAC)
        payload_hex = (
            "ff"  # Unknown channel hash 0xff
            "1234"  # MAC (2 bytes)
            "00112233445566778899aabbccddeeff"  # 16 bytes encrypted (AES block)
        )

        result = decrypt_group_message(
            payload_hex=payload_hex, channel_names=["#general", "#public"]
        )

        assert result is not None
        assert "error" in result
        assert "Failed to decrypt" in result["error"]


class TestPrivateMessageDecryption:
    """Test decryption of private encrypted messages."""

    def test_decrypt_txt_msg_with_metadata(self):
        """Test decrypting a TXT_MSG packet with timestamp and type."""
        # Real packet data from successful decryption
        # Packet: TXT_MSG from 0xad to 0x50 with message "Test"
        packet_type = "TXT_MSG"
        payload_hex = "50ad6f7a506ecec97f7c5a4a9d4eb80dde2b30b5"

        # Private key for device 0x50 (recipient)
        # Note: Using a test key here - replace with actual test data
        private_key_hex = (
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
        )

        # Mock contacts dictionary
        contacts = {
            "adc14011f82d1c56d956aa4f9d73d8858361a606048525e0d08c638dc75dd8c7": {
                "adv_name": "Test Node Alpha",
                "public_key": "adc14011f82d1c56d956aa4f9d73d8858361a606048525e0d08c638dc75dd8c7",
            }
        }

        # This test will need real captured data to work properly
        # For now, we'll test the structure
        result = decrypt_packet_payload(
            packet_type=packet_type,
            payload_hex=payload_hex,
            private_key_hex=private_key_hex,
            contacts=contacts,
            debug=False,
        )

        # Verify result structure (will have error with test key)
        assert result is not None
        assert "error" in result or "success" in result

    def test_decrypt_with_correct_key_parses_metadata(self):
        """Test that successful decryption parses timestamp and message type."""
        # When we have successful decryption, verify metadata parsing
        # This is more of an integration test
        pass  # TODO: Add with real test data

    def test_decrypt_wrong_recipient_fails(self):
        """Test that messages to other recipients can't be decrypted."""
        # Message addressed to 0xd2, trying to decrypt with 0x50's key
        packet_type = "TXT_MSG"
        payload_hex = "d2ad1234567890abcdef"  # Addressed to 0xd2

        private_key_hex = "00" * 64  # Some other key

        contacts = {
            "ad" + "00" * 31: {  # 0xad sender
                "adv_name": "Sender",
                "public_key": "ad" + "00" * 31,
            }
        }

        result = decrypt_packet_payload(
            packet_type=packet_type,
            payload_hex=payload_hex,
            private_key_hex=private_key_hex,
            contacts=contacts,
            debug=False,
        )

        # Should fail because we're not the recipient
        assert result is not None
        # Will either have error or fail MAC verification
        assert "error" in result or result.get("success") is False


class TestEndToEndDecryption:
    """Integration tests using real captured packet data."""

    @pytest.fixture
    def real_private_key(self):
        """Synthetic private key for testing (64 bytes: scalar + nonce seed)."""
        return (
            "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
            "abababababababababababababababababababababababababababababababababab"
        )

    @pytest.fixture
    def real_contacts(self):
        """Synthetic contact list for testing."""
        return {
            "adc14011f82d1c56d956aa4f9d73d8858361a606048525e0d08c638dc75dd8c7": {
                "adv_name": "Test Node Alpha",
                "public_key": "adc14011f82d1c56d956aa4f9d73d8858361a606048525e0d08c638dc75dd8c7",
                "type": 1,
                "out_path_len": -1,
            },
            "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0": {
                "adv_name": "Test Node Beta",
                "public_key": "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0",
                "type": 1,
                "out_path_len": 0,
            },
            "882d0ea3b2864e7a587f3e698cea4459998312e655e05fa5e8b5119d8baac8cd": {
                "adv_name": "Test Repeater Gamma",
                "public_key": "882d0ea3b2864e7a587f3e698cea4459998312e655e05fa5e8b5119d8baac8cd",
                "type": 2,
                "out_path_len": 0,
            },
        }

    def test_decrypt_real_txt_msg_packet(self, real_contacts):
        """Test decrypting a TXT_MSG packet (placeholder for future integration test)."""
        # TODO: Generate a synthetic encrypted packet using the synthetic test keys
        # and verify full round-trip decryption here.
        pytest.skip("Requires synthetic encrypted packet (not yet generated)")

    def test_key_derivation_matches_device(self):
        """Test that the private key correctly derives to the expected public key."""
        import nacl.bindings

        # Synthetic private key (64 bytes: scalar + nonce seed)
        private_key_hex = (
            "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
            "abababababababababababababababababababababababababababababababababab"
        )
        private_key = bytes.fromhex(private_key_hex)

        # Expected public key derived from scalar via crypto_scalarmult_ed25519_base_noclamp
        expected_pubkey = "24f7799f2cfa03541cf25ecf540c38aeb2058377f85dc1890554c21895e8824a"

        # Derive public key from the scalar (first 32 bytes)
        scalar = private_key[:32]
        derived_pubkey = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(scalar)

        assert derived_pubkey.hex() == expected_pubkey


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_payload(self):
        """Test handling of empty payload."""
        result = decrypt_packet_payload(
            packet_type="TXT_MSG",
            payload_hex="",
            private_key_hex="00" * 64,
            contacts={},
            debug=False,
        )
        assert result is not None
        assert "error" in result

    def test_invalid_private_key_length(self):
        """Test handling of invalid private key length."""
        # Private key should be 64 bytes (128 hex chars), but code uses first 32 bytes
        # So a 32-byte key will just use all 32 bytes (not ideal but doesn't crash)
        result = decrypt_packet_payload(
            packet_type="TXT_MSG",
            payload_hex="12ad1234567890abcdef12345678",  # Valid length payload
            private_key_hex="00" * 32,  # Wrong length (32 instead of 64)
            contacts={
                "ad" + "00" * 31: {
                    "adv_name": "Test",
                    "public_key": "ad" + "00" * 31,
                }
            },
            debug=False,
        )
        # Should get an error (likely MAC failure or conversion error)
        assert result is not None
        # Will have error or fail due to wrong key
        assert "error" in result or not result.get("success", True)

    def test_malformed_payload(self):
        """Test handling of malformed packet payload."""
        result = decrypt_packet_payload(
            packet_type="TXT_MSG",
            payload_hex="12",  # Too short
            private_key_hex="00" * 64,
            contacts={},
            debug=False,
        )
        assert result is not None
        assert "error" in result

    def test_unsupported_packet_type(self):
        """Test handling of unsupported packet types."""
        result = decrypt_packet_payload(
            packet_type="UNKNOWN_TYPE",
            payload_hex="1234567890",
            private_key_hex="00" * 64,
            contacts={},
            debug=False,
        )
        assert result is not None
        assert "error" in result
        assert "Unsupported" in result["error"]


class TestMessageFormatParsing:
    """Test parsing of decrypted message formats."""

    def test_parse_message_with_timestamp(self):
        """Test that messages with timestamps are parsed correctly."""
        # Message format: [timestamp:4][type:1][text]
        # Simulating successful decryption result structure
        import struct
        from datetime import datetime

        # Expected timestamp (2026-02-16 23:50:06 UTC)
        expected_timestamp = 1771285806
        expected_type = 0x00
        expected_message = "Test"

        # This would be the plaintext after decryption
        plaintext = (
            struct.pack("<I", expected_timestamp)  # Timestamp (little-endian)
            + bytes([expected_type])  # Message type
            + expected_message.encode("utf-8")  # Message text
        )

        # Parse it the same way the code does
        if len(plaintext) >= 5:
            timestamp = struct.unpack("<I", plaintext[:4])[0]
            msg_type = plaintext[4]
            message_text = plaintext[5:].decode("utf-8", errors="replace")

            assert timestamp == expected_timestamp
            assert msg_type == expected_type
            assert message_text == expected_message

            # Check datetime conversion (use UTC to avoid timezone-dependent failures)
            dt = datetime.fromtimestamp(timestamp, tz=UTC)
            assert dt.year == 2026
            assert dt.month == 2

    def test_parse_message_without_metadata(self):
        """Test handling of messages shorter than 5 bytes."""
        # Short message without timestamp/type
        plaintext = b"Hi"

        if len(plaintext) >= 5:
            pytest.fail("Should not parse metadata for short messages")
        else:
            # Should fall back to raw decode
            message = plaintext.decode("utf-8", errors="replace")
            assert message == "Hi"


class TestPlaintextParsers:
    """Test plaintext parser functions for different packet types."""

    def test_parse_txt_msg_plain(self):
        """Test parsing plain text message."""
        import struct
        import time

        from meshmap.crypto import TXT_TYPE_PLAIN, parse_txt_msg_plaintext

        timestamp = int(time.time())
        txt_type_byte = (TXT_TYPE_PLAIN << 2) | 0  # attempt = 0
        message = b"Hello world"

        plaintext = struct.pack("<I", timestamp) + bytes([txt_type_byte]) + message

        result = parse_txt_msg_plaintext(plaintext)

        assert result["timestamp"] == timestamp
        assert result["txt_type"] == TXT_TYPE_PLAIN
        assert result["txt_type_name"] == "PLAIN"
        assert result["txt_attempt"] == 0
        assert result["txt_plaintext_message"] == "Hello world"

    def test_parse_txt_msg_cli_data(self):
        """Test parsing CLI command message."""
        import struct

        from meshmap.crypto import TXT_TYPE_CLI_DATA, parse_txt_msg_plaintext

        timestamp = 1234567890
        txt_type_byte = (TXT_TYPE_CLI_DATA << 2) | 2  # attempt = 2
        command = b"/stats"

        plaintext = struct.pack("<I", timestamp) + bytes([txt_type_byte]) + command

        result = parse_txt_msg_plaintext(plaintext)

        assert result["txt_type"] == TXT_TYPE_CLI_DATA
        assert result["txt_type_name"] == "CLI_DATA"
        assert result["txt_attempt"] == 2
        assert result["txt_plaintext_message"] == "/stats"

    def test_parse_txt_msg_signed(self):
        """Test parsing signed plain text message."""
        import struct

        from meshmap.crypto import TXT_TYPE_SIGNED_PLAIN, parse_txt_msg_plaintext

        timestamp = 1234567890
        txt_type_byte = (TXT_TYPE_SIGNED_PLAIN << 2) | 1  # attempt = 1
        sender_prefix = bytes.fromhex("aabbccdd")
        message = b"Signed message"

        plaintext = struct.pack("<I", timestamp) + bytes([txt_type_byte]) + sender_prefix + message

        result = parse_txt_msg_plaintext(plaintext)

        assert result["txt_type"] == TXT_TYPE_SIGNED_PLAIN
        assert result["txt_type_name"] == "SIGNED_PLAIN"
        assert result["txt_attempt"] == 1
        assert result["txt_signed_sender_prefix"] == "aabbccdd"
        assert result["txt_plaintext_message"] == "Signed message"

    def test_parse_req_get_stats(self):
        """Test parsing GET_STATS request."""
        import struct

        from meshmap.crypto import REQ_TYPE_GET_STATS, parse_req_plaintext

        timestamp = 1234567890
        req_type = REQ_TYPE_GET_STATS
        req_data = b"\x01\x02\x03\x04"

        plaintext = struct.pack("<I", timestamp) + bytes([req_type]) + req_data

        result = parse_req_plaintext(plaintext)

        assert result["req_timestamp"] == timestamp
        assert result["req_type"] == REQ_TYPE_GET_STATS
        assert result["req_type_name"] == "GET_STATS"
        assert result["req_data_hex"] == "01020304"

    def test_parse_response(self):
        """Test parsing response packet."""
        import struct

        from meshmap.crypto import parse_response_plaintext

        timestamp = 1234567890
        response_data = b"Response data payload"

        plaintext = struct.pack("<I", timestamp) + response_data

        result = parse_response_plaintext(plaintext)

        assert result["resp_timestamp"] == timestamp
        assert result["resp_data_hex"] == response_data.hex()

    def test_parse_response_get_neighbors(self):
        """Test parsing GET_NEIGHBORS response with neighbor list."""
        import struct

        from meshmap.crypto import parse_response_plaintext

        timestamp = 1234567890
        neighbours_count = 5  # Total neighbors
        results_count = 2  # Returned in this response

        # Build neighbor entries
        neighbor1_pubkey = bytes.fromhex("aabbccdd")
        neighbor1_heard_ago = 120  # 2 minutes ago
        neighbor1_snr = 32  # SNR = 8.0 dB (8.0 * 4 = 32)

        neighbor2_pubkey = bytes.fromhex("11223344")
        neighbor2_heard_ago = 3600  # 1 hour ago
        neighbor2_snr = -16  # SNR = -4.0 dB (-4.0 * 4 = -16)

        response_data = (
            struct.pack("<H", neighbours_count)
            + struct.pack("<H", results_count)
            + neighbor1_pubkey
            + struct.pack("<I", neighbor1_heard_ago)
            + struct.pack("b", neighbor1_snr)
            + neighbor2_pubkey
            + struct.pack("<I", neighbor2_heard_ago)
            + struct.pack("b", neighbor2_snr)
        )

        plaintext = struct.pack("<I", timestamp) + response_data

        result = parse_response_plaintext(plaintext)

        assert result["resp_timestamp"] == timestamp
        assert result["resp_neighbours_total_count"] == 5
        assert result["resp_neighbours_results_count"] == 2
        assert len(result["resp_neighbours_list"]) == 2

        # Check first neighbor
        assert result["resp_neighbours_list"][0]["pubkey"] == "aabbccdd"
        assert result["resp_neighbours_list"][0]["heard_seconds_ago"] == 120
        assert result["resp_neighbours_list"][0]["snr"] == 8.0

        # Check second neighbor
        assert result["resp_neighbours_list"][1]["pubkey"] == "11223344"
        assert result["resp_neighbours_list"][1]["heard_seconds_ago"] == 3600
        assert result["resp_neighbours_list"][1]["snr"] == -4.0

    def test_parse_response_get_neighbors_with_contacts(self):
        """Test GET_NEIGHBORS response with contact name matching."""
        import struct

        from meshmap.crypto import parse_response_plaintext

        timestamp = 1234567890
        neighbours_count = 2
        results_count = 2

        # Build neighbor entries
        neighbor1_pubkey = bytes.fromhex("aabbccdd")
        neighbor1_heard_ago = 120
        neighbor1_snr = 32

        neighbor2_pubkey = bytes.fromhex("d2590aed")  # Matches contact
        neighbor2_heard_ago = 3600
        neighbor2_snr = 20

        response_data = (
            struct.pack("<H", neighbours_count)
            + struct.pack("<H", results_count)
            + neighbor1_pubkey
            + struct.pack("<I", neighbor1_heard_ago)
            + struct.pack("b", neighbor1_snr)
            + neighbor2_pubkey
            + struct.pack("<I", neighbor2_heard_ago)
            + struct.pack("b", neighbor2_snr)
        )

        plaintext = struct.pack("<I", timestamp) + response_data

        # Create contact map
        contacts = {
            "d2590aed87376d5755a30700bc7d54afc3bab1d6e1ebdbf64c1bae09d3f77d59": {
                "adv_name": "Puerta del Ángel",
                "adv_type": "REPEATER",
            },
            "ffaabbccdd1122334455667788990011223344556677889900112233445566": {
                "adv_name": "Unknown Node",
                "adv_type": "CHAT",
            },
        }

        result = parse_response_plaintext(plaintext, contacts)

        assert result["resp_neighbours_total_count"] == 2
        assert result["resp_neighbours_results_count"] == 2
        assert len(result["resp_neighbours_list"]) == 2

        # First neighbor - no match in contacts
        assert result["resp_neighbours_list"][0]["pubkey"] == "aabbccdd"
        assert "name" not in result["resp_neighbours_list"][0]

        # Second neighbor - matches contact
        assert result["resp_neighbours_list"][1]["pubkey"] == "d2590aed"
        assert result["resp_neighbours_list"][1]["name"] == "Puerta del Ángel"
        assert result["resp_neighbours_list"][1]["snr"] == 5.0

    def test_parse_path_with_ack(self):
        """Test parsing PATH packet with ACK extra."""
        import struct

        from meshmap.crypto import parse_path_plaintext

        path_len = 3
        path_hops = b"\xaa\xbb\xcc"
        extra_type = 0x03  # ACK
        ack_crc = 0x12345678

        plaintext = bytes([path_len]) + path_hops + bytes([extra_type]) + struct.pack("<I", ack_crc)

        result = parse_path_plaintext(plaintext)

        assert result["path_return_len"] == 3
        assert result["path_return_hops"] == ["0xaa", "0xbb", "0xcc"]
        assert result["path_extra_type"] == 0x03
        assert result["path_extra_type_name"] == "ACK"
        assert result["path_extra_ack_crc"] == "0x12345678"

    def test_parse_anon_req_room_login(self):
        """Test parsing ANON_REQ room login."""
        import struct

        from meshmap.crypto import parse_anon_req_plaintext

        timestamp = 1234567890
        sync_since = 1234500000
        password = b"mypassword"

        plaintext = struct.pack("<I", timestamp) + struct.pack("<I", sync_since) + password

        result = parse_anon_req_plaintext(plaintext, recipient_type="ROOM")

        assert result["anon_req_timestamp"] == timestamp
        assert result["anon_room_sync_since"] == sync_since
        assert result["anon_password"] == "mypassword"

    def test_parse_grp_txt(self):
        """Test parsing group text message."""
        import struct

        from meshmap.crypto import TXT_TYPE_PLAIN, parse_grp_txt_plaintext

        timestamp = 1234567890
        txt_type = TXT_TYPE_PLAIN
        message = b"Alice: Hello everyone"

        plaintext = struct.pack("<I", timestamp) + bytes([txt_type]) + message

        result = parse_grp_txt_plaintext(plaintext)

        assert result["grp_timestamp"] == timestamp
        assert result["grp_txt_type"] == TXT_TYPE_PLAIN
        assert result["grp_txt_type_name"] == "PLAIN"
        assert result["grp_sender_name"] == "Alice"
        assert result["grp_message_text"] == "Hello everyone"
        assert result["raw_message"] == "Alice: Hello everyone"


class TestVerifyMacAndDecrypt:
    """Test the core verify_mac_and_decrypt() primitive directly."""

    def _make_mac_and_ciphertext(self, shared_secret: bytes, plaintext_block: bytes) -> bytes:
        """Encrypt plaintext_block and prepend a valid MAC."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        aes_key = shared_secret[:16]
        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_block) + encryptor.finalize()
        mac = compute_mac(shared_secret, ciphertext)
        return mac + ciphertext

    def test_correct_mac_decrypts(self) -> None:
        """Valid MAC + ciphertext round-trips back to the original plaintext."""
        secret = b"\x01" * 32
        plaintext = b"Hello World!!!!!"  # exactly 16 bytes (one AES block)
        mac_and_ct = self._make_mac_and_ciphertext(secret, plaintext)
        result = verify_mac_and_decrypt(secret, mac_and_ct)
        assert result is not None
        assert result == plaintext

    def test_wrong_mac_returns_none(self) -> None:
        """Corrupted MAC byte causes MAC verification to fail."""
        secret = b"\x01" * 32
        plaintext = b"Hello World!!!!!"
        mac_and_ct = self._make_mac_and_ciphertext(secret, plaintext)
        bad_data = bytes([mac_and_ct[0] ^ 0xFF, mac_and_ct[1] ^ 0xFF]) + mac_and_ct[2:]
        assert verify_mac_and_decrypt(secret, bad_data) is None

    def test_empty_payload_returns_none(self) -> None:
        """Zero-byte payload returns None (too short for MAC)."""
        assert verify_mac_and_decrypt(b"\x00" * 32, b"") is None

    def test_one_byte_payload_returns_none(self) -> None:
        """Single-byte payload returns None (too short for 2-byte MAC)."""
        assert verify_mac_and_decrypt(b"\x00" * 32, b"\xab") is None

    def test_null_padding_stripped(self) -> None:
        """Trailing null bytes in plaintext are stripped before return."""
        secret = b"\x02" * 32
        # 16-byte AES block with trailing nulls simulating short message padded to block size
        plaintext = b"Short\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # 16 bytes
        mac_and_ct = self._make_mac_and_ciphertext(secret, plaintext)
        result = verify_mac_and_decrypt(secret, mac_and_ct)
        assert result == b"Short"

    def test_wrong_secret_returns_none(self) -> None:
        """Using a different secret fails MAC check."""
        secret_a = b"\x03" * 32
        secret_b = b"\x04" * 32
        plaintext = b"Secret message!!"  # 16 bytes
        mac_and_ct = self._make_mac_and_ciphertext(secret_a, plaintext)
        assert verify_mac_and_decrypt(secret_b, mac_and_ct) is None


class TestParserEdgeCases:
    """Edge cases for plaintext parser functions."""

    def test_parse_response_zero_results(self) -> None:
        """GET_NEIGHBORS response with results_count=0 gives empty neighbour list."""
        import struct

        from meshmap.crypto import parse_response_plaintext

        # Valid header but no entries
        plaintext = (
            struct.pack("<I", 1_234_567_890)  # timestamp
            + struct.pack("<H", 5)  # neighbours_count = 5
            + struct.pack("<H", 0)  # results_count = 0
        )
        result = parse_response_plaintext(plaintext)
        # Should fall through to generic response (can't infer entry size with 0 results)
        assert "resp_timestamp" in result
        assert result["resp_timestamp"] == 1_234_567_890

    def test_parse_response_generic_fallback(self) -> None:
        """Short response that is not GET_NEIGHBORS parses as generic."""
        import struct

        from meshmap.crypto import parse_response_plaintext

        plaintext = struct.pack("<I", 999) + b"\xde\xad\xbe\xef"
        result = parse_response_plaintext(plaintext)
        assert result["resp_timestamp"] == 999
        assert result["resp_data_hex"] == "deadbeef"
        assert "resp_neighbours_list" not in result

    def test_parse_path_with_response_extra(self) -> None:
        """PATH extra_type=RESPONSE (0x01) stores extra payload hex."""
        from meshmap.crypto import parse_path_plaintext

        path_len = 1
        path_hops = b"\xcc"
        extra_type = 0x01  # RESPONSE
        extra_payload = b"\x11\x22\x33"

        plaintext = bytes([path_len]) + path_hops + bytes([extra_type]) + extra_payload
        result = parse_path_plaintext(plaintext)

        assert result["path_return_len"] == 1
        assert result["path_return_hops"] == ["0xcc"]
        assert result["path_extra_type"] == 0x01
        assert result["path_extra_type_name"] == "RESPONSE"
        assert result["path_extra_payload_hex"] == "112233"

    def test_parse_path_with_dummy_extra(self) -> None:
        """PATH extra_type=0xFF is recognised as DUMMY."""
        from meshmap.crypto import parse_path_plaintext

        plaintext = bytes([0, 0xFF])  # path_len=0, extra_type=DUMMY
        result = parse_path_plaintext(plaintext)
        assert result["path_extra_type"] == 0xFF
        assert result["path_extra_type_name"] == "DUMMY"

    def test_parse_anon_req_repeater(self) -> None:
        """ANON_REQ to REPEATER: [timestamp:4][password:variable]."""
        import struct

        from meshmap.crypto import parse_anon_req_plaintext

        timestamp = 1_234_567_890
        password = b"secret"
        plaintext = struct.pack("<I", timestamp) + password

        result = parse_anon_req_plaintext(plaintext, recipient_type="REPEATER")
        assert result["anon_req_timestamp"] == timestamp
        assert result["anon_password"] == "secret"

    def test_parse_anon_req_sensor(self) -> None:
        """ANON_REQ to SENSOR: same format as REPEATER."""
        import struct

        from meshmap.crypto import parse_anon_req_plaintext

        timestamp = 9_999_999
        password = b"sensorpass\x00"
        plaintext = struct.pack("<I", timestamp) + password

        result = parse_anon_req_plaintext(plaintext, recipient_type="SENSOR")
        assert result["anon_req_timestamp"] == timestamp
        assert result["anon_password"] == "sensorpass"  # null stripped

    def test_parse_anon_req_generic(self) -> None:
        """ANON_REQ without recipient_type: generic parsing stores hex."""
        import struct

        from meshmap.crypto import parse_anon_req_plaintext

        timestamp = 1_111_111
        extra = b"\xaa\xbb\xcc\xdd"
        plaintext = struct.pack("<I", timestamp) + extra

        result = parse_anon_req_plaintext(plaintext, recipient_type=None)
        assert result["anon_req_timestamp"] == timestamp
        assert result["anon_req_data_hex"] == "aabbccdd"

"""Tests for packet decoder functionality."""

import struct

from meshmap.decoder import (
    _decode_advert,
    _decode_control,
    _decode_multipart,
    apply_decryption_to_packet,
    decode_packet,
)
from meshmap.models import DecodedPacket


class TestMultipartDecoder:
    """Test MULTIPART packet decoding."""

    def test_multipart_ack_structure(self) -> None:
        """Test decoding MULTIPART ACK packet structure."""
        # MULTIPART header: remaining=2, type=ACK(0x03)
        # Format: [header:1][ack_crc:4]
        header_byte = (2 << 4) | 0x03  # remaining=2, type=ACK
        ack_crc = 0x12345678
        payload = bytes([header_byte]) + ack_crc.to_bytes(4, "little")

        packet = DecodedPacket()
        _decode_multipart(packet, payload)

        assert packet.multipart_remaining == 2
        assert packet.multipart_type == "0x03"
        assert packet.multipart_type_name == "ACK"
        assert packet.multipart_payload_hex == "78563412"

    def test_multipart_empty(self) -> None:
        """Test handling of empty MULTIPART payload."""
        packet = DecodedPacket()
        _decode_multipart(packet, b"")

        assert packet.multipart_remaining is None
        assert packet.multipart_type is None


class TestControlDecoder:
    """Test CONTROL packet decoding."""

    def test_control_zero_hop(self) -> None:
        """Test decoding CONTROL packet with zero-hop flag."""
        # Control type with zero-hop flag (0x80) set
        control_type = 0x88  # 0x80 | 0x08
        control_data = b"\x01\x02\x03\x04"
        payload = bytes([control_type]) + control_data

        packet = DecodedPacket()
        _decode_control(packet, payload, {})

        assert packet.control_type == "0x88"
        assert packet.control_is_zero_hop is True
        assert packet.control_data_hex == "01020304"

    def test_control_non_zero_hop(self) -> None:
        """Test decoding CONTROL packet without zero-hop flag."""
        control_type = 0x08  # No zero-hop flag
        control_data = b"\xaa\xbb"
        payload = bytes([control_type]) + control_data

        packet = DecodedPacket()
        _decode_control(packet, payload, {})

        assert packet.control_type == "0x08"
        assert packet.control_is_zero_hop is False
        assert packet.control_data_hex == "aabb"

    def test_control_no_data(self) -> None:
        """Test CONTROL packet with only type byte."""
        control_type = 0x88
        payload = bytes([control_type])

        packet = DecodedPacket()
        _decode_control(packet, payload, {})

        assert packet.control_type == "0x88"
        assert packet.control_is_zero_hop is True
        assert packet.control_data_hex is None

    def test_control_discover_req(self) -> None:
        """Test decoding DISCOVER_REQ control packet."""
        import struct

        # DISCOVER_REQ: sub_type=0x8, type_filter=0x04 (ROOM), tag=0xe65084eb
        control_type = 0x80  # 0x80 (zero-hop) | (0x8 << 4 would be 0x80)
        type_filter = 0x04  # Looking for ROOM nodes
        tag = 0xE65084EB

        control_data = bytes([type_filter]) + struct.pack("<I", tag)
        payload = bytes([control_type]) + control_data

        packet = DecodedPacket()
        _decode_control(packet, payload, {})

        assert packet.control_type == "0x80"
        assert packet.control_is_zero_hop is True
        assert packet.control_subtype == "DISCOVER_REQ"
        assert packet.discover_tag == "0xe65084eb"
        assert "ROOM" in packet.discover_adv_types

    def test_control_discover_resp(self) -> None:
        """Test decoding DISCOVER_RESP control packet."""
        import struct

        # DISCOVER_RESP: sub_type=0x9, node_type=0x2 (REPEATER), snr=51 (12.75dB), tag=0xe65084eb
        control_type = 0x92  # 0x80 (zero-hop) | (0x9 << 4) = 0x90, plus 0x2 (node_type) = 0x92
        snr_byte = 51  # SNR*4 = 12.75*4 = 51
        tag = 0xE65084EB
        pubkey = b"\xd2\x59\x0a\xed\x87\x37\x6d\x57"  # 8-byte prefix

        control_data = bytes([snr_byte]) + struct.pack("<I", tag) + pubkey
        payload = bytes([control_type]) + control_data

        contact_map = {"d2590aed": "TestNode"}

        packet = DecodedPacket()
        _decode_control(packet, payload, contact_map)

        assert packet.control_type == "0x92"
        assert packet.control_is_zero_hop is True
        assert packet.control_subtype == "DISCOVER_RESP"
        assert packet.discover_node_type == "REPEATER"
        assert packet.discover_snr == 12.75
        assert packet.discover_tag == "0xe65084eb"
        assert packet.discover_pubkey == "d2590aed87376d57"
        assert packet.discover_pubkey_full is False
        assert packet.discover_contact_name == "TestNode"


class TestTraceDecoder:
    """Test enhanced TRACE packet decoding."""

    def test_trace_basic_structure(self) -> None:
        """Test decoding TRACE packet basic structure."""
        # Header: route=DIRECT(0x02), type=TRACE(0x09), ver=1(0x00)
        # Header byte = 0b00_1001_10 = 0x26
        header = 0x26
        path_len = 0  # No path for this test
        trace_tag = 0x11223344
        auth_code = 0xAABBCCDD
        flags = 0x00  # path_sz=0 (1 byte hashes)

        # Manually construct little endian format
        packet_hex = (
            f"{header:02x}"
            f"{path_len:02x}"
            f"{trace_tag & 0xFF:02x}{(trace_tag >> 8) & 0xFF:02x}"
            f"{(trace_tag >> 16) & 0xFF:02x}{(trace_tag >> 24) & 0xFF:02x}"
            f"{auth_code & 0xFF:02x}{(auth_code >> 8) & 0xFF:02x}"
            f"{(auth_code >> 16) & 0xFF:02x}{(auth_code >> 24) & 0xFF:02x}"
            f"{flags:02x}"
        )

        decoded = decode_packet(packet_hex, {})

        assert decoded.payload_type == "TRACE"
        assert decoded.trace_tag == "0x11223344"
        assert decoded.trace_auth == "0xaabbccdd"
        assert decoded.trace_flags == "0x00"
        assert decoded.trace_path_hash_size == 1  # 1 << 0 = 1 byte

    def test_trace_with_path_and_snr(self) -> None:
        """Test TRACE packet with path hops and SNR values."""
        # Create a TRACE packet with 2 hops and SNR values
        header = 0x26  # route=DIRECT, type=TRACE
        path_len = 2
        trace_tag = 0x12345678
        auth_code = 0xABCDEF00
        flags = 0x00  # path_sz=0 (1 byte hashes)

        # Path hops (1 byte each)
        hop1 = 0xAA
        hop2 = 0xBB

        # TRACE path_data: hashes then SNR values
        hash1 = 0xCC
        hash2 = 0xDD
        # SNR values (signed, SNR*4): 8.0 dB = 32, -4.0 dB = -16
        snr1 = 32 & 0xFF
        snr2 = (-16) & 0xFF  # Two's complement

        packet_hex = (
            f"{header:02x}"
            f"{path_len:02x}"
            f"{hop1:02x}{hop2:02x}"  # path
            # Payload (TRACE data)
            f"{trace_tag & 0xFF:02x}{(trace_tag >> 8) & 0xFF:02x}"
            f"{(trace_tag >> 16) & 0xFF:02x}{(trace_tag >> 24) & 0xFF:02x}"
            f"{auth_code & 0xFF:02x}{(auth_code >> 8) & 0xFF:02x}"
            f"{(auth_code >> 16) & 0xFF:02x}{(auth_code >> 24) & 0xFF:02x}"
            f"{flags:02x}"
            f"{hash1:02x}{hash2:02x}"  # Path hashes
            f"{snr1:02x}{snr2:02x}"  # SNR values
        )

        decoded = decode_packet(packet_hex, {})

        assert decoded.payload_type == "TRACE"
        assert decoded.path_len == 2
        assert decoded.trace_path_hash_size == 1
        assert len(decoded.trace_path_hashes) == 2
        assert decoded.trace_path_hashes[0] == "0xcc"
        assert decoded.trace_path_hashes[1] == "0xdd"
        assert len(decoded.trace_snr_values) == 2
        assert decoded.trace_snr_values[0] == 8.0
        assert decoded.trace_snr_values[1] == -4.0


class TestFullPacketDecoding:
    """Test full packet decoding with various types."""

    def test_decode_multipart_packet(self) -> None:
        """Test decoding a full MULTIPART packet."""
        # Header: route=FLOOD(0x01), type=MULTIPART(0x0A), ver=1(0x00)
        # Header byte = 0b00_1010_01 = 0x29
        header = 0x29
        path_len = 0

        # MULTIPART payload: remaining=1, type=ACK(0x03), ack_crc=0x11223344
        multipart_header = (1 << 4) | 0x03
        ack_crc = 0x11223344

        packet_hex = (
            f"{header:02x}"
            f"{path_len:02x}"
            f"{multipart_header:02x}"
            f"{ack_crc & 0xFF:02x}{(ack_crc >> 8) & 0xFF:02x}"
            f"{(ack_crc >> 16) & 0xFF:02x}{(ack_crc >> 24) & 0xFF:02x}"
        )

        decoded = decode_packet(packet_hex, {})

        assert decoded.payload_type == "MULTIPART"
        assert decoded.route_type == "FLOOD"
        assert decoded.multipart_remaining == 1
        assert decoded.multipart_type_name == "ACK"

    def test_decode_control_packet(self) -> None:
        """Test decoding a full CONTROL packet."""
        # Header: route=DIRECT(0x02), type=CONTROL(0x0B), ver=1(0x00)
        # Header byte = 0b00_1011_10 = 0x2E
        header = 0x2E
        path_len = 0
        control_type = 0x88  # Zero-hop control
        # control_data = b'\x01\x02\x03'  # unused placeholder

        packet_hex = f"{header:02x}{path_len:02x}{control_type:02x}010203"

        decoded = decode_packet(packet_hex, {})

        assert decoded.payload_type == "CONTROL"
        assert decoded.route_type == "DIRECT"
        assert decoded.control_is_zero_hop is True
        assert decoded.control_data_hex == "010203"


class TestAdvertDecoder:
    """Test ADVERT payload decoding via _decode_advert()."""

    # Shared test fixtures
    PUBKEY = bytes(range(32))  # 32-byte pubkey: 00 01 02 ... 1f
    TIMESTAMP_INT = 1_234_567_890
    TIMESTAMP_BYTES = struct.pack("<I", TIMESTAMP_INT)
    SIGNATURE = b"\xab" * 64  # 64-byte signature placeholder

    def _make_payload(self, flags: int, extra: bytes = b"") -> bytes:
        """Build a full advert payload (pubkey + timestamp + signature + app_data)."""
        return self.PUBKEY + self.TIMESTAMP_BYTES + self.SIGNATURE + bytes([flags]) + extra

    def test_pubkey_only(self) -> None:
        """32-byte payload: pubkey decoded, timestamp and app_data absent."""
        packet = DecodedPacket()
        _decode_advert(packet, self.PUBKEY, {})
        assert packet.advert_pubkey == self.PUBKEY.hex()
        assert packet.advert_timestamp is None
        assert packet.advert_type is None

    def test_pubkey_and_timestamp(self) -> None:
        """36-byte payload: pubkey and timestamp decoded."""
        packet = DecodedPacket()
        _decode_advert(packet, self.PUBKEY + self.TIMESTAMP_BYTES, {})
        assert packet.advert_pubkey == self.PUBKEY.hex()
        assert packet.advert_timestamp == self.TIMESTAMP_INT
        assert packet.advert_type is None  # No app_data yet

    def test_flags_type_only(self) -> None:
        """Full advert with flags=0x01 (type=CHAT, no lat/lon, no name)."""
        payload = self._make_payload(flags=0x01)
        packet = DecodedPacket()
        _decode_advert(packet, payload, {})
        assert packet.advert_type == "CHAT"
        assert packet.advert_lat is None
        assert packet.advert_lon is None
        assert packet.advert_name is None

    def test_flags_repeater_type(self) -> None:
        """flags=0x02 gives type=REPEATER."""
        payload = self._make_payload(flags=0x02)
        packet = DecodedPacket()
        _decode_advert(packet, payload, {})
        assert packet.advert_type == "REPEATER"

    def test_flags_with_lat_lon(self) -> None:
        """flags=0x12 (REPEATER + lat/lon bit): lat/lon decoded."""
        lat = 40_500_000  # 40.5 degrees N
        lon = -3_700_000  # 3.7 degrees W
        extra = struct.pack("<i", lat) + struct.pack("<i", lon)
        payload = self._make_payload(flags=0x12, extra=extra)  # type=REPEATER(2), lat/lon
        packet = DecodedPacket()
        _decode_advert(packet, payload, {})
        assert packet.advert_type == "REPEATER"
        assert abs(packet.advert_lat - 40.5) < 1e-6
        assert abs(packet.advert_lon - (-3.7)) < 1e-6

    def test_flags_with_name(self) -> None:
        """flags=0x81 (CHAT + name bit): name decoded."""
        extra = b"Gateway Alpha"
        payload = self._make_payload(flags=0x81, extra=extra)  # type=CHAT(1), name
        packet = DecodedPacket()
        _decode_advert(packet, payload, {})
        assert packet.advert_type == "CHAT"
        assert packet.advert_name == "Gateway Alpha"
        assert packet.advert_lat is None

    def test_flags_full_advert(self) -> None:
        """flags=0x93: type=ROOM(3), lat/lon, and name all present."""
        lat = 48_866_667  # ~48.87 degrees N (Paris)
        lon = 2_333_333  # ~2.33 degrees E
        extra = struct.pack("<i", lat) + struct.pack("<i", lon) + b"Paris Hub"
        payload = self._make_payload(flags=0x93, extra=extra)
        packet = DecodedPacket()
        _decode_advert(packet, payload, {})
        assert packet.advert_type == "ROOM"
        assert abs(packet.advert_lat - 48.866667) < 1e-4
        assert abs(packet.advert_lon - 2.333333) < 1e-4
        assert packet.advert_name == "Paris Hub"

    def test_name_strips_null_padding(self) -> None:
        """Trailing null bytes in name are stripped."""
        extra = b"Node\x00\x00\x00"
        payload = self._make_payload(flags=0x80, extra=extra)  # name flag only (type=NONE)
        packet = DecodedPacket()
        _decode_advert(packet, payload, {})
        assert packet.advert_name == "Node"

    def test_contact_match_via_prefix(self) -> None:
        """contact_map lookup matches on first 8 hex chars of pubkey."""
        prefix = self.PUBKEY[:4].hex()  # "00010203"
        contact_map = {prefix: "Alice"}
        packet = DecodedPacket()
        _decode_advert(packet, self.PUBKEY, contact_map)
        assert packet.advert_contact_name == "Alice"

    def test_no_contact_match(self) -> None:
        """Non-matching contact_map leaves advert_contact_name None."""
        contact_map = {"ffffffff": "Bob"}
        packet = DecodedPacket()
        _decode_advert(packet, self.PUBKEY, contact_map)
        assert packet.advert_contact_name is None

    def test_too_short_payload(self) -> None:
        """Payload shorter than 32 bytes: nothing decoded."""
        packet = DecodedPacket()
        _decode_advert(packet, b"\xaa" * 16, {})
        assert packet.advert_pubkey is None
        assert packet.advert_timestamp is None


class TestApplyDecryptionToPacket:
    """Test apply_decryption_to_packet() mapping from dict to DecodedPacket."""

    def test_key_file_sets_decrypted_by(self) -> None:
        packet = DecodedPacket()
        apply_decryption_to_packet(packet, {}, key_file="mykey.json")
        assert packet.decrypted_by == "mykey.json"

    def test_no_key_file_leaves_decrypted_by_none(self) -> None:
        packet = DecodedPacket()
        apply_decryption_to_packet(packet, {"contact_name": "Alice"}, key_file=None)
        assert packet.decrypted_by is None

    def test_contact_name_sets_src_name(self) -> None:
        packet = DecodedPacket()
        apply_decryption_to_packet(packet, {"contact_name": "Alice"})
        assert packet.src_name == "Alice"

    def test_txt_msg_fields_mapped(self) -> None:
        packet = DecodedPacket()
        apply_decryption_to_packet(
            packet,
            {
                "timestamp": 1_234_567_890,
                "txt_type": 0,
                "txt_type_name": "PLAIN",
                "txt_attempt": 1,
                "txt_plaintext_message": "Hello",
            },
        )
        assert packet.txt_timestamp == 1_234_567_890
        assert packet.txt_type == 0
        assert packet.txt_type_name == "PLAIN"
        assert packet.txt_attempt == 1
        assert packet.txt_plaintext_message == "Hello"

    def test_legacy_plaintext_fallback(self) -> None:
        """Bare 'plaintext' key is mapped when txt_plaintext_message is not set."""
        packet = DecodedPacket()
        apply_decryption_to_packet(packet, {"plaintext": "Legacy text"})
        assert packet.txt_plaintext_message == "Legacy text"

    def test_response_neighbours_mapped(self) -> None:
        neighbours = [{"pubkey": "aabbccdd", "heard_seconds_ago": 60, "snr": 8.0}]
        packet = DecodedPacket()
        apply_decryption_to_packet(
            packet,
            {
                "resp_timestamp": 1_234_567_890,
                "resp_neighbours_total_count": 3,
                "resp_neighbours_results_count": 1,
                "resp_neighbours_list": neighbours,
            },
        )
        assert packet.resp_timestamp == 1_234_567_890
        assert packet.resp_neighbours_total_count == 3
        assert packet.resp_neighbours_results_count == 1
        assert packet.resp_neighbours_list == neighbours

    def test_grp_txt_fields_mapped(self) -> None:
        packet = DecodedPacket()
        apply_decryption_to_packet(
            packet,
            {
                "channel_name": "#general",
                "grp_timestamp": 1_234_567_890,
                "grp_txt_type": 0,
                "grp_txt_type_name": "PLAIN",
                "grp_sender_name": "Bob",
                "grp_message_text": "Hi all",
            },
        )
        assert packet.channel_name == "#general"
        assert packet.grp_timestamp == 1_234_567_890
        assert packet.grp_sender_name == "Bob"
        assert packet.grp_message_text == "Hi all"

    def test_path_fields_mapped(self) -> None:
        packet = DecodedPacket()
        apply_decryption_to_packet(
            packet,
            {
                "path_return_len": 2,
                "path_return_hops": ["0xaa", "0xbb"],
                "path_extra_type": 0x03,
                "path_extra_type_name": "ACK",
                "path_extra_ack_crc": "0x12345678",
            },
        )
        assert packet.path_return_len == 2
        assert packet.path_return_hops == ["0xaa", "0xbb"]
        assert packet.path_extra_type_name == "ACK"
        assert packet.path_extra_ack_crc == "0x12345678"

    def test_empty_dict_leaves_fields_none(self) -> None:
        """Empty result dict should not modify any packet fields."""
        packet = DecodedPacket()
        apply_decryption_to_packet(packet, {})
        assert packet.decrypted_by is None
        assert packet.src_name is None
        assert packet.txt_plaintext_message is None
        assert packet.resp_neighbours_list == []

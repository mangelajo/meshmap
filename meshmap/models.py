"""Data models for meshmap packet structures."""

from dataclasses import dataclass, field
from typing import Any

# SNR display thresholds (dB)
SNR_GREEN = 2  # >= green (good signal)
SNR_YELLOW = -7  # >= yellow (marginal), < red (poor signal)


def snr_color(snr: float) -> str:
    """Return a Rich color name for the given SNR value."""
    if snr >= SNR_GREEN:
        return "green"
    if snr >= SNR_YELLOW:
        return "yellow"
    return "red"


@dataclass
class HopInfo:
    """Information about a single hop in a packet path."""

    hash: str
    contacts: list[str] = field(default_factory=list)


@dataclass
class SignalInfo:
    """RF signal information."""

    rssi: int
    snr: int
    timestamp: str


@dataclass
class AdvertData:
    """Parsed ADVERT app_data structure."""

    type: str
    name: str | None = None
    lat: float | None = None
    lon: float | None = None
    extra1: int | None = None
    extra2: int | None = None


@dataclass
class DecryptionResult:
    """Result of packet decryption attempt."""

    success: bool
    error: str | None = None
    contact_name: str | None = None
    sender: str | None = None
    message: str | None = None
    plaintext: str | None = None
    plaintext_hex: str | None = None
    channel_name: str | None = None
    timestamp: int | None = None
    raw_message: str | None = None


@dataclass
class DecodedPacket:
    """Decoded meshcore packet structure."""

    # Header information
    header_hex: str | None = None
    route_type: str | None = None
    route_type_hex: str | None = None
    payload_type: str | None = None
    payload_type_hex: str | None = None
    payload_ver: int | None = None

    # Transport and path
    transport_codes: list[str] = field(default_factory=list)
    path_len: int | None = None
    path_hops: list[HopInfo] = field(default_factory=list)

    # Addresses
    src_hash: str | None = None
    src_name: str | None = None
    dest_hash: str | None = None
    dest_name: str | None = None

    # Payload
    payload_len: int | None = None
    payload_hex: str | None = None

    # Encryption
    mac: str | None = None
    encrypted_len: int | None = None
    encrypted_data_hex: str | None = None

    # ADVERT specific
    advert_pubkey: str | None = None
    advert_contact_name: str | None = None
    advert_timestamp: int | None = None
    advert_signature: str | None = None
    advert_type: str | None = None
    advert_name: str | None = None
    advert_lat: float | None = None
    advert_lon: float | None = None
    advert_extra1: int | None = None
    advert_extra2: int | None = None
    advert_app_data_hex: str | None = None
    advert_app_data_len: int | None = None

    # ANON_REQ specific
    anon_sender_pubkey: str | None = None
    anon_sender_name: str | None = None

    # Group message specific
    channel_hash: str | None = None
    channel_name: str | None = None

    # ACK specific
    ack_crc: str | None = None

    # TRACE specific
    trace_tag: str | None = None
    trace_auth: str | None = None
    trace_flags: str | None = None
    trace_path_data: str | None = None
    trace_path_hash_size: int | None = None
    trace_current_offset: int | None = None
    trace_path_hashes: list[str] = field(default_factory=list)
    trace_snr_values: list[float] = field(default_factory=list)

    # MULTIPART specific
    multipart_remaining: int | None = None
    multipart_type: str | None = None
    multipart_type_name: str | None = None
    multipart_payload_hex: str | None = None

    # CONTROL specific
    control_type: str | None = None
    control_is_zero_hop: bool | None = None
    control_data_hex: str | None = None
    control_subtype: str | None = None

    # CONTROL DISCOVER_REQ fields
    discover_type_filter: str | None = None
    discover_adv_types: list[str] = field(default_factory=list)
    discover_tag: str | None = None
    discover_since: int | None = None
    discover_since_datetime: str | None = None

    # CONTROL DISCOVER_RESP fields
    discover_node_type: str | None = None
    discover_snr: float | None = None
    discover_pubkey: str | None = None
    discover_pubkey_full: bool | None = None
    discover_contact_name: str | None = None

    # Decryption metadata
    decrypted_by: str | None = None
    decrypted_datetime: str | None = None
    decrypted_plaintext_hex: str | None = None

    # Decrypted TXT_MSG fields
    txt_timestamp: int | None = None
    txt_type: int | None = None
    txt_type_name: str | None = None
    txt_attempt: int | None = None
    txt_signed_sender_prefix: str | None = None
    txt_plaintext_message: str | None = None

    # Decrypted REQ fields
    req_timestamp: int | None = None
    req_type: int | None = None
    req_type_name: str | None = None
    req_data_hex: str | None = None

    # Decrypted RESPONSE fields
    resp_timestamp: int | None = None
    resp_data_hex: str | None = None
    resp_neighbours_total_count: int | None = None
    resp_neighbours_results_count: int | None = None
    resp_neighbours_list: list[dict[str, Any]] = field(default_factory=list)

    # Decrypted PATH fields
    path_return_len: int | None = None
    path_return_hops: list[str] = field(default_factory=list)
    path_extra_type: int | None = None
    path_extra_type_name: str | None = None
    path_extra_payload_hex: str | None = None
    path_extra_ack_crc: str | None = None

    # Decrypted ANON_REQ fields
    anon_req_timestamp: int | None = None
    anon_req_tag: str | None = None
    anon_room_sync_since: int | None = None
    anon_password: str | None = None
    anon_req_data_hex: str | None = None

    # Decrypted GRP_TXT/GRP_DATA fields
    grp_timestamp: int | None = None
    grp_txt_type: int | None = None
    grp_txt_type_name: str | None = None
    grp_sender_name: str | None = None
    grp_message_text: str | None = None

    # Errors
    decode_error: str | None = None
    decode_traceback: str | None = None

    # Raw data
    total_bytes: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in self.__dict__.items() if v is not None}

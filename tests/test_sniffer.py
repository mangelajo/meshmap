"""Tests for PacketSniffer dynamic name learning and graph updates."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from meshmap.models import DecodedPacket
from meshmap.sniffer import PacketSniffer


def _make_mesh_mock() -> MagicMock:
    """Create a mock MeshCore with contacts support."""
    mesh = MagicMock()
    mesh.contacts = {}
    mesh.ensure_contacts = AsyncMock()
    mesh.subscribe = MagicMock(return_value="sub-handle")
    mesh.unsubscribe = MagicMock()
    return mesh


def _advert_decoded(
    pubkey: str = "aabbccdd11223344",
    name: str | None = "TestNode",
    advert_type: str | None = "REPEATER",
    lat: float | None = 40.0,
    lon: float | None = -74.0,
) -> DecodedPacket:
    """Build a DecodedPacket that looks like a decoded ADVERT."""
    pkt = DecodedPacket()
    pkt.advert_pubkey = pubkey
    pkt.advert_name = name
    pkt.advert_type = advert_type
    pkt.advert_lat = lat
    pkt.advert_lon = lon
    pkt.payload_type = "ADVERT"
    return pkt


def _make_event() -> MagicMock:
    """Create a mock RF packet event."""
    event = MagicMock()
    event.payload = {"rssi": -70, "snr": 5.0, "raw_hex": "0000", "payload_length": 0}
    return event


async def _attach_and_get_callback(sniffer: PacketSniffer, mesh: MagicMock):
    """Attach the sniffer and return the on_packet callback."""
    await sniffer.attach(private_keys=None, channel_names=None)
    return mesh.subscribe.call_args[0][1]


class TestContactMapLearning:
    """Test that ADVERT packets dynamically update the contact map."""

    def test_advert_adds_to_contact_map(self) -> None:
        """An ADVERT with pubkey+name should be learned into the contact map."""

        async def run() -> None:
            mesh = _make_mesh_mock()
            sniffer = PacketSniffer(mesh, debug=False)
            on_packet = await _attach_and_get_callback(sniffer, mesh)

            decoded = _advert_decoded(pubkey="aabbccdd11223344", name="AlphaNode")
            with patch("meshmap.sniffer.decoder.decode_packet", return_value=decoded):
                await on_packet(_make_event())

            assert sniffer._contact_map["aabbccdd"] == "AlphaNode"

        asyncio.run(run())

    def test_advert_does_not_overwrite_existing_contact(self) -> None:
        """If a contact already exists, ADVERT should not overwrite it."""

        async def run() -> None:
            mesh = _make_mesh_mock()
            mesh.contacts = {"aabbccdd11223344aabbccdd11223344": {"adv_name": "OriginalName"}}
            sniffer = PacketSniffer(mesh, debug=False)
            on_packet = await _attach_and_get_callback(sniffer, mesh)

            assert sniffer._contact_map["aabbccdd"] == "OriginalName"

            decoded = _advert_decoded(pubkey="aabbccdd11223344", name="NewName")
            with patch("meshmap.sniffer.decoder.decode_packet", return_value=decoded):
                await on_packet(_make_event())

            assert sniffer._contact_map["aabbccdd"] == "OriginalName"

        asyncio.run(run())

    def test_advert_without_name_does_not_update(self) -> None:
        """An ADVERT without a name should not add to contact map."""

        async def run() -> None:
            mesh = _make_mesh_mock()
            sniffer = PacketSniffer(mesh, debug=False)
            on_packet = await _attach_and_get_callback(sniffer, mesh)

            decoded = _advert_decoded(name=None)
            with patch("meshmap.sniffer.decoder.decode_packet", return_value=decoded):
                await on_packet(_make_event())

            assert "aabbccdd" not in sniffer._contact_map

        asyncio.run(run())


class TestGraphUpsertFromAdvert:
    """Test that ADVERT packets update the graph when one is provided."""

    def test_advert_upserts_graph_node(self) -> None:
        """When a graph is provided, ADVERT packets should call upsert_node."""

        async def run() -> None:
            mesh = _make_mesh_mock()
            graph = MagicMock()
            sniffer = PacketSniffer(mesh, debug=False, graph=graph)
            on_packet = await _attach_and_get_callback(sniffer, mesh)

            decoded = _advert_decoded(
                pubkey="aabbccdd11223344",
                name="GraphNode",
                advert_type="REPEATER",
                lat=40.123,
                lon=-74.456,
            )
            with patch("meshmap.sniffer.decoder.decode_packet", return_value=decoded):
                await on_packet(_make_event())

            graph.upsert_node.assert_called_once_with(
                "aabbccdd11223344",
                "GraphNode",
                "repeater",
                40.123,
                -74.456,
            )

        asyncio.run(run())

    def test_no_graph_skips_upsert(self) -> None:
        """When no graph is provided, no upsert should happen (no exception)."""

        async def run() -> None:
            mesh = _make_mesh_mock()
            sniffer = PacketSniffer(mesh, debug=False, graph=None)
            on_packet = await _attach_and_get_callback(sniffer, mesh)

            decoded = _advert_decoded()
            with patch("meshmap.sniffer.decoder.decode_packet", return_value=decoded):
                await on_packet(_make_event())

        asyncio.run(run())

    def test_advert_without_name_skips_graph_upsert(self) -> None:
        """ADVERT without a name should not upsert to graph."""

        async def run() -> None:
            mesh = _make_mesh_mock()
            graph = MagicMock()
            sniffer = PacketSniffer(mesh, debug=False, graph=graph)
            on_packet = await _attach_and_get_callback(sniffer, mesh)

            decoded = _advert_decoded(name=None)
            with patch("meshmap.sniffer.decoder.decode_packet", return_value=decoded):
                await on_packet(_make_event())

            graph.upsert_node.assert_not_called()

        asyncio.run(run())

    def test_advert_type_lowercased_for_graph(self) -> None:
        """The advert_type should be lowercased when passed to graph.upsert_node."""

        async def run() -> None:
            mesh = _make_mesh_mock()
            graph = MagicMock()
            sniffer = PacketSniffer(mesh, debug=False, graph=graph)
            on_packet = await _attach_and_get_callback(sniffer, mesh)

            decoded = _advert_decoded(advert_type="CLIENT")
            with patch("meshmap.sniffer.decoder.decode_packet", return_value=decoded):
                await on_packet(_make_event())

            call_args = graph.upsert_node.call_args[0]
            assert call_args[2] == "client"

        asyncio.run(run())

    def test_advert_none_type_becomes_unknown(self) -> None:
        """If advert_type is None, graph should get 'unknown'."""

        async def run() -> None:
            mesh = _make_mesh_mock()
            graph = MagicMock()
            sniffer = PacketSniffer(mesh, debug=False, graph=graph)
            on_packet = await _attach_and_get_callback(sniffer, mesh)

            decoded = _advert_decoded(advert_type=None)
            with patch("meshmap.sniffer.decoder.decode_packet", return_value=decoded):
                await on_packet(_make_event())

            call_args = graph.upsert_node.call_args[0]
            assert call_args[2] == "unknown"

        asyncio.run(run())


class TestPacketSnifferInit:
    """Test PacketSniffer constructor."""

    def test_default_graph_is_none(self) -> None:
        """Graph should default to None."""
        mesh = _make_mesh_mock()
        sniffer = PacketSniffer(mesh)
        assert sniffer.graph is None

    def test_graph_stored(self) -> None:
        """Graph should be stored when provided."""
        mesh = _make_mesh_mock()
        graph = MagicMock()
        sniffer = PacketSniffer(mesh, graph=graph)
        assert sniffer.graph is graph

"""Tests for AsyncRtuOverTcpTransport."""

import asyncio
from collections.abc import Callable
from typing import Any, Never
from unittest.mock import AsyncMock, MagicMock

import pytest
from tmodbus.exceptions import ModbusConnectionError
from tmodbus.pdu import ReadHoldingRegistersPDU
from tmodbus.transport.async_rtu_over_tcp import AsyncRtuOverTcpTransport


class TestAsyncRtuOverTcpTransportInit:
    """Test initialization and parameter validation."""

    def test_init_with_defaults(self) -> None:
        """Test initialization with default parameters."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        assert transport.host == "192.168.1.100"
        assert transport.port == 502
        assert transport.timeout == 10.0
        assert transport.connect_timeout == 10.0
        assert transport.connection_kwargs == {}

    def test_init_with_custom_parameters(self) -> None:
        """Test initialization with custom parameters."""
        transport = AsyncRtuOverTcpTransport(
            "example.com",
            port=1502,
            timeout=5.0,
            connect_timeout=3.0,
            ssl=True,
            local_addr=("127.0.0.1", 0),
        )

        assert transport.host == "example.com"
        assert transport.port == 1502
        assert transport.timeout == 5.0
        assert transport.connect_timeout == 3.0
        assert transport.connection_kwargs == {"ssl": True, "local_addr": ("127.0.0.1", 0)}

    def test_init_with_invalid_port_zero(self) -> None:
        """Test initialization with port 0 raises ValueError."""
        with pytest.raises(ValueError, match="Port must be an integer between 1-65535"):
            AsyncRtuOverTcpTransport("192.168.1.100", port=0)

    def test_init_with_invalid_port_too_high(self) -> None:
        """Test initialization with port > 65535 raises ValueError."""
        with pytest.raises(ValueError, match="Port must be an integer between 1-65535"):
            AsyncRtuOverTcpTransport("192.168.1.100", port=65536)

    def test_init_with_invalid_timeout(self) -> None:
        """Test initialization with invalid timeout raises ValueError."""
        with pytest.raises(ValueError, match="Timeout must be a positive number"):
            AsyncRtuOverTcpTransport("192.168.1.100", timeout=0)

    def test_init_with_negative_timeout(self) -> None:
        """Test initialization with negative timeout raises ValueError."""
        with pytest.raises(ValueError, match="Timeout must be a positive number"):
            AsyncRtuOverTcpTransport("192.168.1.100", timeout=-1.0)

    def test_init_with_invalid_connect_timeout(self) -> None:
        """Test initialization with invalid connect timeout raises ValueError."""
        with pytest.raises(ValueError, match="Connect timeout must be a positive number"):
            AsyncRtuOverTcpTransport("192.168.1.100", connect_timeout=0)

    def test_init_with_negative_connect_timeout(self) -> None:
        """Test initialization with negative connect timeout raises ValueError."""
        with pytest.raises(ValueError, match="Connect timeout must be a positive number"):
            AsyncRtuOverTcpTransport("192.168.1.100", connect_timeout=-5.0)


@pytest.fixture
async def mock_transport_and_mock_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[MagicMock, MagicMock]:
    """Fixture to create transport and mock protocol."""
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    mock_protocol = MagicMock()

    async def mock_create_connection(_factory: Callable[[], Any], **_kwargs: Any) -> tuple[MagicMock, MagicMock]:
        return mock_transport, mock_protocol

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_connection", mock_create_connection)

    return mock_transport, mock_protocol


class TestAsyncRtuOverTcpTransportConnection:
    """Test connection management."""

    @pytest.mark.usefixtures("mock_transport_and_mock_protocol")
    async def test_open_connection_success(self) -> None:
        """Test successful connection opening."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")
        await transport.open()

        assert transport.is_open() is True
        assert transport._transport is not None
        assert transport._protocol is not None

    async def test_open_connection_already_open(
        self, monkeypatch: pytest.MonkeyPatch, mock_transport_and_mock_protocol: tuple[MagicMock, MagicMock]
    ) -> None:
        """Test opening an already open connection."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")
        mock_transport, _ = mock_transport_and_mock_protocol

        call_count = 0

        async def mock_create_connection(factory: Callable[[], Any], **_kwargs: Any) -> tuple[MagicMock, MagicMock]:
            nonlocal call_count
            call_count += 1
            protocol = factory()
            return mock_transport, protocol

        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "create_connection", mock_create_connection)

        await transport.open()
        await transport.open()  # Open again

        # Should only create connection once
        assert call_count == 1
        assert transport.is_open() is True

    async def test_open_connection_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test connection timeout."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        async def mock_create_connection(*_args: Any, **_kwargs: Any) -> Never:
            raise TimeoutError

        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "create_connection", mock_create_connection)

        with pytest.raises(TimeoutError):
            await transport.open()

        assert transport.is_open() is False

    async def test_open_connection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test connection error handling."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        async def mock_create_connection(*_args: Any, **_kwargs: Any) -> Never:
            msg = "Connection refused"
            raise OSError(msg)

        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "create_connection", mock_create_connection)

        with pytest.raises(ModbusConnectionError):
            await transport.open()

        assert transport.is_open() is False

    async def test_close_connection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test closing an open connection."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        mock_transport = MagicMock()
        mock_transport.is_closing.return_value = False

        async def mock_create_connection(factory: Callable[[], Any], **_kwargs: Any) -> tuple[MagicMock, MagicMock]:
            protocol = factory()
            return mock_transport, protocol

        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "create_connection", mock_create_connection)

        await transport.open()
        await transport.close()

        mock_transport.close.assert_called_once()

    async def test_close_already_closed(self) -> None:
        """Test closing an already closed connection."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        # Should not raise any error
        await transport.close()

    async def test_close_connection_is_closing(
        self,
        mock_transport_and_mock_protocol: tuple[MagicMock, MagicMock],
    ) -> None:
        """Test closing a connection that is already closing."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        mock_transport, _ = mock_transport_and_mock_protocol
        await transport.open()

        # Now set it as closing
        mock_transport.is_closing.return_value = True

        await transport.close()

        # close() should not be called on the transport
        mock_transport.close.assert_not_called()

    async def test_close_with_exception(
        self,
        mock_transport_and_mock_protocol: tuple[MagicMock, MagicMock],
    ) -> None:
        """Test close handles exceptions gracefully."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        mock_transport, _ = mock_transport_and_mock_protocol
        msg = "Close error"
        mock_transport.close.side_effect = Exception(msg)

        await transport.open()

        # Should not raise, just log the error
        await transport.close()

    async def test_is_open_when_closed(self) -> None:
        """Test is_open returns False when connection is closed."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        assert transport.is_open() is False

    @pytest.mark.usefixtures("mock_transport_and_mock_protocol")
    async def test_is_open_when_open(self) -> None:
        """Test is_open returns True when connection is open."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")
        await transport.open()

        assert transport.is_open() is True

    async def test_is_open_when_closing(self, mock_transport_and_mock_protocol: tuple[MagicMock, MagicMock]) -> None:
        """Test is_open returns False when connection is closing."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")
        mock_transport, _ = mock_transport_and_mock_protocol

        await transport.open()

        # Set as closing
        mock_transport.is_closing.return_value = True

        assert transport.is_open() is False


class TestAsyncRtuOverTcpTransportConnectionLost:
    """Test connection lost callback."""

    async def test_on_connection_lost_with_exception(self) -> None:
        """Test connection lost callback with exception."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        transport._transport = MagicMock()
        transport._protocol = MagicMock()

        # Simulate connection lost with exception
        exc = ConnectionResetError("Connection reset")
        transport._on_connection_lost(exc)

        assert transport._transport is None
        assert transport._protocol is None

    async def test_on_connection_lost_without_exception(self) -> None:
        """Test connection lost callback without exception."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        transport._transport = MagicMock()
        transport._protocol = MagicMock()

        # Simulate clean connection close
        transport._on_connection_lost(None)

        assert transport._transport is None
        assert transport._protocol is None


class TestAsyncRtuOverTcpTransportSendReceive:
    """Test send and receive operations."""

    async def test_send_and_receive_success(
        self, mock_transport_and_mock_protocol: tuple[MagicMock, MagicMock]
    ) -> None:
        """Test successful send and receive."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        mock_transport, mock_protocol = mock_transport_and_mock_protocol
        mock_transport.is_closing.return_value = False

        expected_response = [1, 2, 3]
        mock_protocol.send_and_receive = AsyncMock(return_value=expected_response)

        await transport.open()

        pdu = ReadHoldingRegistersPDU(0, 3)
        result = await transport.send_and_receive(1, pdu)

        assert result == expected_response
        mock_protocol.send_and_receive.assert_called_once_with(1, pdu)

    async def test_send_and_receive_when_not_connected(self) -> None:
        """Test send and receive when not connected."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        pdu = ReadHoldingRegistersPDU(0, 3)

        with pytest.raises(ModbusConnectionError, match="Transport is not connected"):
            await transport.send_and_receive(1, pdu)

    @pytest.mark.usefixtures("mock_transport_and_mock_protocol")
    async def test_send_and_receive_when_protocol_is_none(self) -> None:
        """Test send and receive when protocol is None."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")
        await transport.open()

        # Manually set protocol to None to simulate edge case
        transport._protocol = None

        pdu = ReadHoldingRegistersPDU(0, 3)

        with pytest.raises(ModbusConnectionError, match="Transport is not connected"):
            await transport.send_and_receive(1, pdu)

    async def test_send_and_receive_protocol_exception(
        self, mock_transport_and_mock_protocol: tuple[MagicMock, MagicMock]
    ) -> None:
        """Test send and receive when protocol raises exception."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        _, mock_protocol = mock_transport_and_mock_protocol
        msg = "Protocol error"
        mock_protocol.send_and_receive = AsyncMock(side_effect=ModbusConnectionError(msg))

        await transport.open()

        pdu = ReadHoldingRegistersPDU(0, 3)

        with pytest.raises(ModbusConnectionError, match="Protocol error"):
            await transport.send_and_receive(1, pdu)


class TestAsyncRtuOverTcpTransportIntegration:
    """Integration tests for complete workflows."""

    async def test_complete_workflow(self, mock_transport_and_mock_protocol: tuple[MagicMock, MagicMock]) -> None:
        """Test complete workflow: open, send/receive, close."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100", port=502)

        mock_transport, mock_protocol = mock_transport_and_mock_protocol
        expected_response = [100, 200]
        mock_protocol.send_and_receive = AsyncMock(return_value=expected_response)

        # Open connection
        assert transport.is_open() is False
        await transport.open()
        assert transport.is_open() is True

        # Send and receive
        pdu = ReadHoldingRegistersPDU(0, 2)
        result = await transport.send_and_receive(1, pdu)
        assert result == expected_response

        # Close connection
        await transport.close()
        mock_transport.close.assert_called_once()

    @pytest.mark.usefixtures("mock_transport_and_mock_protocol")
    async def test_connection_lost_during_operation(self) -> None:
        """Test behavior when connection is lost during operation."""
        transport = AsyncRtuOverTcpTransport("192.168.1.100")

        await transport.open()

        # Simulate connection lost
        msg = "Connection lost"
        transport._on_connection_lost(ConnectionResetError(msg))

        # Verify state after connection lost
        assert transport._transport is None
        assert transport._protocol is None
        assert transport.is_open() is False

        # Verify we can't send after connection lost
        pdu = ReadHoldingRegistersPDU(0, 2)
        with pytest.raises(ModbusConnectionError, match="Transport is not connected"):
            await transport.send_and_receive(1, pdu)

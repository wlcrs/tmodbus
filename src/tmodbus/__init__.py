"""tModbus library."""

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Unpack

from .client.async_client import AsyncModbusClient
from .transport import (
    AsyncAsciiTransport,
    AsyncRtuOverTcpTransport,
    AsyncRtuTransport,
    AsyncSmartTransport,
    AsyncTcpTransport,
)
from .transport.async_rtu import PySerialOptions

if TYPE_CHECKING:
    from tenacity import AsyncRetrying

try:
    from ._version import __version__
except ImportError:  # pragma: no cover
    __version__ = "0.0.0"


def create_async_tcp_client(  # noqa: PLR0913
    host: str,
    port: int = 502,
    *,
    unit_id: int,
    timeout: float = 10.0,
    connect_timeout: float = 10.0,
    wait_between_requests: float = 0.0,
    wait_after_connect: float = 0.0,
    auto_reconnect: "bool | AsyncRetrying" = True,
    on_reconnected: Callable[[], Awaitable[None] | None] | None = None,
    response_retry_strategy: "AsyncRetrying | None" = None,
    retry_on_device_busy: bool = True,
    retry_on_device_failure: bool = False,
    **connection_kwargs: Any,
) -> AsyncModbusClient:
    """Create an asynchronous TCP Modbus client with automatic reconnect and request retry functionality.

    Args:
        host: The IP address or hostname of the Modbus server.
        port: The port number of the Modbus server (default is 502).
        unit_id: The unit ID to use for requests.
        timeout: Timeout in seconds, default 10.0s
        connect_timeout: Timeout for establishing connection, default 10.0s
        wait_between_requests: Wait time between requests in seconds (default: 0.0s)
        wait_after_connect: Wait time after connection establishment in seconds (default: 0.0s)
        auto_reconnect: Whether to automatically reconnect on connection loss (default: True).
                        Can be a custom AsyncRetrying instance when more control is needed.
        on_reconnected: Callback to be called after a successful reconnection.
        response_retry_strategy: Retry strategy for handling failed requests (default: None).
        retry_on_device_busy: Whether to retry on device busy errors (default: True).
                              Can be a custom AsyncRetrying instance when more control is needed.
        retry_on_device_failure: Whether to retry on device failure errors (default: False).
                                 Can be a custom AsyncRetrying instance when more control is needed.
        connection_kwargs: Additional connection parameters passed to `asyncio.open_connection` (e.g., SSL context)

    Returns:
        An instance of AsyncModbusClient configured for TCP transport.

    """
    smart_transport = AsyncSmartTransport(
        AsyncTcpTransport(
            host,
            port,
            timeout=timeout,
            connect_timeout=connect_timeout,
            **connection_kwargs,
        ),
        wait_between_requests=wait_between_requests,
        wait_after_connect=wait_after_connect,
        auto_reconnect=auto_reconnect,
        on_reconnected=on_reconnected,
        response_retry_strategy=response_retry_strategy,
        retry_on_device_busy=retry_on_device_busy,
        retry_on_device_failure=retry_on_device_failure,
    )
    return AsyncModbusClient(smart_transport, unit_id=unit_id)


def create_async_rtu_client(  # noqa: PLR0913
    port: str,
    *,
    unit_id: int,
    wait_between_requests: float = 0.0,
    wait_after_connect: float = 0.0,
    auto_reconnect: "bool | AsyncRetrying" = True,
    on_reconnected: Callable[[], Awaitable[None] | None] | None = None,
    response_retry_strategy: "AsyncRetrying | None" = None,
    retry_on_device_busy: bool = True,
    retry_on_device_failure: bool = False,
    **pyserial_options: Unpack[PySerialOptions],
) -> AsyncModbusClient:
    """Create an asynchronous RTU Modbus client with automatic reconnect and request retry functionality.

    Args:
        port: The port number of the Modbus server (default is 502).
        unit_id: The unit ID to use for requests.
        timeout: Timeout in seconds, default 10.0s
        connect_timeout: Timeout for establishing connection, default 10.0s
        wait_between_requests: Wait time between requests in seconds (default: 0.0s)
        wait_after_connect: Wait time after connection establishment in seconds (default: 0.0s)
        auto_reconnect: Whether to automatically reconnect on connection loss (default: True).
                        Can be a custom AsyncRetrying instance when more control is needed.
        on_reconnected: Callback to be called after a successful reconnection.
        response_retry_strategy: Retry strategy for handling failed requests (default: None).
        retry_on_device_busy: Whether to retry on device busy errors (default: True).
                              Can be a custom AsyncRetrying instance when more control is needed.
        retry_on_device_failure: Whether to retry on device failure errors (default: False).
                                 Can be a custom AsyncRetrying instance when more control is needed.
        pyserial_options: Additional connection parameters passed to `pyserial` (e.g., SSL context)

    Returns:
        An instance of AsyncModbusClient configured for TCP transport.

    """
    smart_transport = AsyncSmartTransport(
        AsyncRtuTransport(
            port,
            **pyserial_options,
        ),
        wait_between_requests=wait_between_requests,
        wait_after_connect=wait_after_connect,
        auto_reconnect=auto_reconnect,
        on_reconnected=on_reconnected,
        response_retry_strategy=response_retry_strategy,
        retry_on_device_busy=retry_on_device_busy,
        retry_on_device_failure=retry_on_device_failure,
    )
    return AsyncModbusClient(smart_transport, unit_id=unit_id)


def create_async_ascii_client(  # noqa: PLR0913
    port: str,
    *,
    unit_id: int,
    wait_between_requests: float = 0.0,
    wait_after_connect: float = 0.0,
    auto_reconnect: "bool | AsyncRetrying" = True,
    on_reconnected: Callable[[], Awaitable[None] | None] | None = None,
    response_retry_strategy: "AsyncRetrying | None" = None,
    retry_on_device_busy: bool = True,
    retry_on_device_failure: bool = False,
    **pyserial_options: Unpack[PySerialOptions],
) -> AsyncModbusClient:
    """Create an asynchronous ASCII Modbus client with automatic reconnect and request retry functionality.

    Args:
        port: The port number of the Modbus server (default is 502).
        unit_id: The unit ID to use for requests.
        timeout: Timeout in seconds, default 10.0s
        connect_timeout: Timeout for establishing connection, default 10.0s
        wait_between_requests: Wait time between requests in seconds (default: 0.0s)
        wait_after_connect: Wait time after connection establishment in seconds (default: 0.0s)
        auto_reconnect: Whether to automatically reconnect on connection loss (default: True).
                        Can be a custom AsyncRetrying instance when more control is needed.
        on_reconnected: Callback to be called after a successful reconnection.
        response_retry_strategy: Retry strategy for handling failed requests (default: None).
        retry_on_device_busy: Whether to retry on device busy errors (default: True).
                              Can be a custom AsyncRetrying instance when more control is needed.
        retry_on_device_failure: Whether to retry on device failure errors (default: False).
                                 Can be a custom AsyncRetrying instance when more control is needed.
        pyserial_options: Additional connection parameters passed to `pyserial` (e.g., SSL context)

    Returns:
        An instance of AsyncModbusClient configured for TCP transport.

    """
    smart_transport = AsyncSmartTransport(
        AsyncAsciiTransport(
            port,
            **pyserial_options,
        ),
        wait_between_requests=wait_between_requests,
        wait_after_connect=wait_after_connect,
        auto_reconnect=auto_reconnect,
        on_reconnected=on_reconnected,
        response_retry_strategy=response_retry_strategy,
        retry_on_device_busy=retry_on_device_busy,
        retry_on_device_failure=retry_on_device_failure,
    )
    return AsyncModbusClient(smart_transport, unit_id=unit_id)


def create_async_rtu_over_tcp_client(  # noqa: PLR0913
    host: str,
    port: int = 502,
    *,
    unit_id: int,
    timeout: float = 10.0,
    connect_timeout: float = 10.0,
    wait_between_requests: float = 0.0,
    wait_after_connect: float = 0.0,
    auto_reconnect: "bool | AsyncRetrying" = True,
    on_reconnected: Callable[[], Awaitable[None] | None] | None = None,
    response_retry_strategy: "AsyncRetrying | None" = None,
    retry_on_device_busy: bool = True,
    retry_on_device_failure: bool = False,
    **connection_kwargs: Any,
) -> AsyncModbusClient:
    """Create an asynchronous RTU over TCP Modbus client with automatic reconnect and request retry functionality.

    Args:
        host: The IP address or hostname of the Modbus server.
        port: The port number of the Modbus server (default is 502).
        unit_id: The unit ID to use for requests.
        timeout: Timeout in seconds, default 10.0s
        connect_timeout: Timeout for establishing connection, default 10.0s
        wait_between_requests: Wait time between requests in seconds (default: 0.0s)
        wait_after_connect: Wait time after connection establishment in seconds (default: 0.0s)
        auto_reconnect: Whether to automatically reconnect on connection loss (default: True).
                        Can be a custom AsyncRetrying instance when more control is needed.
        on_reconnected: Callback to be called after a successful reconnection.
        response_retry_strategy: Retry strategy for handling failed requests (default: None).
        retry_on_device_busy: Whether to retry on device busy errors (default: True).
                              Can be a custom AsyncRetrying instance when more control is needed.
        retry_on_device_failure: Whether to retry on device failure errors (default: False).
                                 Can be a custom AsyncRetrying instance when more control is needed.
        connection_kwargs: Additional connection parameters passed to `asyncio.open_connection` (e.g., SSL context)

    Returns:
        An instance of AsyncModbusClient configured for RTU over TCP transport.

    """
    smart_transport = AsyncSmartTransport(
        AsyncRtuOverTcpTransport(
            host,
            port,
            timeout=timeout,
            connect_timeout=connect_timeout,
            **connection_kwargs,
        ),
        wait_between_requests=wait_between_requests,
        wait_after_connect=wait_after_connect,
        auto_reconnect=auto_reconnect,
        on_reconnected=on_reconnected,
        response_retry_strategy=response_retry_strategy,
        retry_on_device_busy=retry_on_device_busy,
        retry_on_device_failure=retry_on_device_failure,
    )
    return AsyncModbusClient(smart_transport, unit_id=unit_id)


__all__ = [
    "AsyncModbusClient",
    "AsyncRtuTransport",
    "AsyncSmartTransport",
    "AsyncTcpTransport",
    "create_async_rtu_client",
    "create_async_tcp_client",
]

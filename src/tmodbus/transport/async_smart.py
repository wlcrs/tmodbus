"""Async Smart Transport Layer.

This transport layer lives on top of the RTU or TCP transport layer
and implements the following smart features:

- Wait time between requests to avoid overwhelming the device
- Wait time after connection establishment to allow device to be ready
- Automatic reconnection on connection loss
"""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, TypeVar

try:
    from tenacity import (
        AsyncRetrying,
        RetryCallState,
        RetryError,
        retry_any,
        retry_if_exception_type,
        stop_after_delay,
        wait_exponential,
    )
except ImportError as ex:  # pragma: no cover
    msg = "tenacity is required for Smart Transport functionality.Install with 'pip install tmodbus[smart]'"
    raise ImportError(msg) from ex

from tmodbus.exceptions import (
    ModbusConnectionError,
    RequestRetryFailedError,
    ServerDeviceBusyError,
    ServerDeviceFailureError,
)
from tmodbus.pdu import BaseClientPDU

from .async_base import AsyncBaseTransport

if TYPE_CHECKING:
    from tenacity.retry import RetryBaseT

logger = logging.getLogger(__name__)


RT = TypeVar("RT")


DEFAULT_RECONNECT_RETRY_STRATEGY = AsyncRetrying(
    stop=stop_after_delay(60),
    wait=wait_exponential(min=0.1, max=10),
)

DEFAULT_RESPONSE_RETRY_STRATEGY = AsyncRetrying(
    stop=stop_after_delay(60),
    wait=wait_exponential(min=0.1, max=10),
    reraise=True,  # Reraise the last exception if all retries are exhausted
)


class AsyncSmartTransport(AsyncBaseTransport):
    """Smart Transport Layer.

    This transport layer is built on top of RTU or TCP transport layers,
    adding features such as wait time between requests, wait time after connection,
    and automatic reconnection on connection loss.
    """

    _communication_lock: asyncio.Lock = asyncio.Lock()
    _should_be_connected: bool = False
    _must_reconnect: bool = False

    auto_reconnect: AsyncRetrying | None = None
    response_retry_strategy: AsyncRetrying

    def __init__(  # noqa: C901, PLR0913
        self,
        base_transport: "AsyncBaseTransport",
        *,
        wait_between_requests: float = 0.0,
        wait_after_connect: float = 0.0,
        auto_reconnect: bool | AsyncRetrying = True,
        on_reconnected: Callable[[], Awaitable[None] | None] | None = None,
        response_retry_strategy: AsyncRetrying | None = None,
        retry_on_device_busy: bool = True,
        retry_on_device_failure: bool = False,
    ) -> None:
        """Initialize Smart Transport Layer.

        Args:
            base_transport: Underlying transport layer instance (AsyncRtuTransport, AsyncTcpTransport, etc.)
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

        """
        self.base_transport = base_transport
        if wait_between_requests < 0:
            msg = "wait_between_requests must be a positive value"
            raise ValueError(msg)
        self.wait_between_requests = wait_between_requests

        if wait_after_connect < 0:
            msg = "wait_after_connect must be a positive value"
            raise ValueError(msg)
        self.wait_after_connect = wait_after_connect

        if isinstance(auto_reconnect, bool) and auto_reconnect:
            auto_reconnect = DEFAULT_RECONNECT_RETRY_STRATEGY
        if auto_reconnect:
            self.auto_reconnect = auto_reconnect.copy(
                retry=retry_if_exception_type((ModbusConnectionError, TimeoutError))
            )

        if not auto_reconnect and on_reconnected:
            msg = "on_reconnected callback provided but auto_reconnect is disabled"
            raise ValueError(msg)
        self.on_reconnected = on_reconnected

        retry_functions: list[RetryBaseT] = []

        if not response_retry_strategy:
            response_retry_strategy = DEFAULT_RESPONSE_RETRY_STRATEGY
        elif response_retry_strategy.retry:
            retry_functions.append(response_retry_strategy.retry)

        if auto_reconnect:
            retry_functions.append(self._retry_with_new_connection_if_needed)

        if retry_on_device_busy:
            retry_functions.append(retry_if_exception_type(ServerDeviceBusyError))

        if retry_on_device_failure:
            retry_functions.append(retry_if_exception_type(ServerDeviceFailureError))

        self.response_retry_strategy = response_retry_strategy.copy(retry=retry_any(*retry_functions))  # type: ignore[arg-type]

        self._last_request_finished_at: float | None = None

    async def open(self) -> None:
        """Open Transport Connection.

        Establishes connection with Modbus device and waits for the specified time
        to allow the device to be ready.

        Raises:
            ConnectionError: When connection cannot be established

        """
        async with self._communication_lock:
            await self._open()

    async def _open(self) -> None:
        """Open Transport Connection without Lock.

        This method is used internally when the lock is already held.
        """
        await self.base_transport.open()
        if self.wait_after_connect > 0:
            logger.debug("Waiting %.2f seconds after TCP connection before sending data", self.wait_after_connect)
            await asyncio.sleep(self.wait_after_connect)

        self._should_be_connected = True

    async def close(self) -> None:
        """Close Transport Connection.

        Closes connection with Modbus device and releases related resources.
        """
        async with self._communication_lock:
            try:
                await self.base_transport.close()
            finally:
                self._should_be_connected = False

    def is_open(self) -> bool:
        """Check Connection Status.

        Returns:
            True if connection was established and should still be available.
            False otherwise.

        """
        return (self.auto_reconnect and self._should_be_connected) or self.base_transport.is_open()

    async def _do_auto_reconnect(self) -> None:
        """Reconnect to the Modbus device."""
        assert isinstance(self.auto_reconnect, AsyncRetrying)
        if self.base_transport.is_open():
            logger.debug("Closing existing connection before reconnecting.")
            await self.base_transport.close()
        else:
            logger.debug("No existing connection to close before reconnecting.")

        try:
            async for attempt in self.auto_reconnect:
                with attempt:
                    logger.info("Attempting to reconnect.")
                    await self._open()
        except RetryError as e:
            msg = (
                f"Failed to reconnect after {attempt.retry_state.attempt_number} attempts "
                f"over {attempt.retry_state.seconds_since_start} seconds"
            )
            raise ModbusConnectionError(msg) from e

        if self.on_reconnected:
            result = self.on_reconnected()
            if asyncio.iscoroutine(result):
                await result

    async def _reconnect_send_and_receive(self, unit_id: int, pdu: BaseClientPDU[RT]) -> RT:
        """Reconnect if necessary, then try to Send PDU and Receive Response."""
        # If auto_reconnect is enabled and the connection is not open, try to reconnect
        if self.auto_reconnect:
            if self._must_reconnect:
                logger.info("Forcing reconnection due to previous connection error.")
                await self._do_auto_reconnect()
                self._must_reconnect = False
            if not self.base_transport.is_open():
                logger.info("Connection lost. Attempting to reconnect...")
                await self._do_auto_reconnect()

        # If a wait time between requests is configured, enforce it
        if self.wait_between_requests > 0 and self._last_request_finished_at is not None:
            wait_needed = self.wait_between_requests - (time.monotonic() - self._last_request_finished_at)
            if wait_needed > 0:
                logger.debug(
                    "Waiting %.2fs before sending next request to respect %.2fs wait between requests",
                    wait_needed,
                    self.wait_between_requests,
                )
                await asyncio.sleep(wait_needed)

        return await self.base_transport.send_and_receive(unit_id, pdu)

    async def send_and_receive(self, unit_id: int, pdu: BaseClientPDU[RT]) -> RT:
        """Send PDU and Receive Response."""
        # Ensure that only one request is processed at a time
        async with self._communication_lock:
            try:
                async for attempt in self.response_retry_strategy:
                    with attempt:
                        response = await self._reconnect_send_and_receive(unit_id, pdu)

                    if attempt.retry_state.outcome and not attempt.retry_state.outcome.failed:
                        attempt.retry_state.set_result(response)
            except RetryError as e:
                msg = (
                    f"Failed to get a valid response after {attempt.retry_state.attempt_number} attempts "
                    f"over {attempt.retry_state.seconds_since_start} seconds"
                )
                raise RequestRetryFailedError(msg) from e
            else:
                return response
            finally:
                self._last_request_finished_at = time.monotonic()

    def _retry_with_new_connection_if_needed(self, retry_state: RetryCallState) -> bool:
        """Retry with a new connection if the connection was lost."""
        if retry_state.outcome and retry_state.outcome.failed:
            exception = retry_state.outcome.exception()
            if isinstance(exception, ModbusConnectionError):
                logger.warning(
                    "Received an %s error. Closing the connection to force a reconnect.", type(exception).__name__
                )
                self._must_reconnect = True
                return True
        return False

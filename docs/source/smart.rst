###############################
 Smart Transport & Retry Logic
###############################

The :class:`~tmodbus.transport.AsyncSmartTransport` class is a high-level transport
wrapper designed to make Modbus communication resilient against flaky physical links,
network jitter, intermediary proxy behaviors, and slow device microcontrollers (MCUs).

It sits directly between client logic (such as
:class:`~tmodbus.client.AsyncModbusClient`) and an underlying transport implementation
(such as :class:`~tmodbus.transport.AsyncTcpTransport` or
:class:`~tmodbus.transport.AsyncRtuTransport`).

**********
 Overview
**********

In industrial and IoT environments, Modbus communication frequently encounters
challenges:

- **Unstable links**: Serial adapters drop frames, and Wi-Fi/Ethernet links drop
  connections.
- **Intermediary proxies**: Tools such as ``modbus-proxy`` or Ethernet-to-RS485 gateways
  accept TCP connections instantly (<1 ms), even when the downstream serial device or
  MCU is offline or unresponsive. In this scenario, socket connection succeeds
  immediately, but PDU transactions time out.
- **Microcontroller timing constraints**: Certain devices crash or drop packets if
  queried too rapidly, or require a warm-up period immediately after opening a
  connection.
- **Device busy states**: Devices executing internal calibration or flash writes may
  return a Modbus Exception Code 0x06
  (:class:`~tmodbus.exceptions.ServerDeviceBusyError`), which warrants a retry rather
  than failing the transaction.

:class:`~tmodbus.transport.AsyncSmartTransport` solves these issues through a
**dual-tier retry architecture**, **automatic reconnection on transport failures**, and
**hardware pacing**.

******************************
 Dual-Tier Retry Architecture
******************************

The retry and reconnection logic in :class:`~tmodbus.transport.AsyncSmartTransport`
operates at two distinct levels, powered by `tenacity
<https://tenacity.readthedocs.io/>`_:

.. list-table::
    :header-rows: 1
    :widths: 20 35 45

    - - Tier
      - Configuration
      - Scope & Purpose
    - - **Tier 1: Request Level**
      - ``response_retry_strategy`` (:class:`~tenacity.AsyncRetrying`)
      - Governs attempts to send a PDU and receive a response within a single
        :meth:`~tmodbus.transport.AsyncSmartTransport.send_and_receive` call. Retries on
        transport failures, device busy errors, or optional device failure errors with
        backoff.
    - - **Tier 2: Connection Level**
      - ``auto_reconnect`` (:class:`~tenacity.AsyncRetrying`)
      - Governs establishing or re-establishing the underlying TCP/serial socket in
        :meth:`~tmodbus.transport.AsyncSmartTransport._do_auto_reconnect`. If
        establishing the connection fails (e.g., connection refused), retries according
        to its configured strategy.

Tier 1: Request-Level Retries
=============================

When :meth:`~tmodbus.transport.AsyncSmartTransport.send_and_receive` is called, it
executes inside a loop controlled by ``response_retry_strategy``:

- **Default Strategy**: Retries for up to 60 seconds with exponential backoff between
  0.1s and 10s:

  .. code-block:: python

      from tenacity import AsyncRetrying, stop_after_delay, wait_exponential

      AsyncRetrying(
          stop=stop_after_delay(60),
          wait=wait_exponential(min=0.1, max=10),
      )

- **Retried Exceptions**: A retry is triggered when:

  1. A **transport failure** occurs (``TimeoutError``,
     :class:`~tmodbus.exceptions.ModbusConnectionError`, or standard
     :class:`ConnectionError`). The transport is marked as requiring reconnection
     (``_must_reconnect = True``), and the underlying socket is closed. On the
     subsequent retry attempt, a fresh connection is established.
  2. A :class:`~tmodbus.exceptions.ServerDeviceBusyError` is raised (enabled by default
     via ``retry_on_device_busy=True``).
  3. A :class:`~tmodbus.exceptions.ServerDeviceFailureError` is raised (optional,
     enabled via ``retry_on_device_failure=True``).
  4. Any custom exception condition configured on the user-supplied
     ``response_retry_strategy``.

If all attempts in ``response_retry_strategy`` are exhausted, a
:class:`~tmodbus.exceptions.RequestRetryFailedError` is raised wrapping the last
underlying error.

Tier 2: Connection-Level Reconnection
=====================================

The connection layer operates whenever a new socket connection must be established:

1. **Initial Connection / Manual Reconnect**: When opening the underlying socket (via
   :meth:`~tmodbus.transport.AsyncSmartTransport.open`), the transport attempts to
   connect.
2. **Automatic Reconnection**: When ``auto_reconnect`` is enabled, if a transport
   failure occurred previously (flagged by ``_must_reconnect``) or if the underlying
   transport is closed,
   :meth:`~tmodbus.transport.AsyncSmartTransport._do_auto_reconnect` is invoked. It
   closes any lingering connection and iterates over ``auto_reconnect``. If the
   connection cannot be established (e.g., TCP connection refused), it retries according
   to ``auto_reconnect``'s wait and stop conditions.
3. **Handling Intermediary Proxies & Stalled MCUs**: In setups where a local proxy (like
   ``modbus-proxy``) accepts TCP connections instantly even when the downstream device
   is unresponsive, the initial PDU send times out (``TimeoutError``). Because
   ``TimeoutError`` is treated as a transport failure, ``AsyncSmartTransport``
   immediately:

   - Marks the transport for reconnection (``_must_reconnect = True``).
   - Closes the existing socket.
   - Allows ``response_retry_strategy`` to apply its backoff delay (preventing
     high-frequency polling cycles) and retry the request on a fresh connection.

******************
 Failure Taxonomy
******************

Errors handled by :class:`~tmodbus.transport.AsyncSmartTransport` are classified into
two categories:

.. list-table::
    :header-rows: 1
    :widths: 25 35 40

    - - Category
      - Exception Types
      - Transport Reaction
    - - **Transport Failures**
      - ``TimeoutError``, :class:`~tmodbus.exceptions.ModbusConnectionError`,
        :class:`ConnectionError`
      - Marks ``_must_reconnect = True``; closes underlying transport; retries with a
        fresh connection according to ``response_retry_strategy``.
    - - **Application Responses**
      - Subclasses of :class:`~tmodbus.exceptions.ModbusResponseError` (e.g.,
        ``ServerDeviceBusyError``)
      - Device is responsive. If ``retry_on_device_busy`` is enabled, retried by
        ``response_retry_strategy`` without closing or reconnecting the socket.

*******************
 Lifecycle Diagram
*******************

The following diagram illustrates the lifecycle of a request entering
:meth:`~tmodbus.transport.AsyncSmartTransport.send_and_receive`:

.. mermaid::

    flowchart TD
        Start([send_and_receive called]) --> Lock[Acquire _communication_lock]
        Lock --> OuterLoop[response_retry_strategy attempt loop]

        OuterLoop --> CheckNeedReconnect{Reconnection needed?<br/>_must_reconnect OR !is_open}

        CheckNeedReconnect -- Yes --> DoReconnect[_do_auto_reconnect: open socket]
        CheckNeedReconnect -- No --> CheckPacing{wait_between_requests > 0?}

        DoReconnect --> ReconnectSuccess{Connected?}
        ReconnectSuccess -- No --> RaiseConnError([Raise ModbusConnectionError])
        ReconnectSuccess -- Yes --> CheckPacing

        CheckPacing -- Yes --> SleepPacing[asyncio.sleep pacing delay]
        CheckPacing -- No --> SendPDU[base_transport.send_and_receive]
        SleepPacing --> SendPDU

        SendPDU --> ResultType{Transaction Outcome}

        ResultType -- "Success (Valid PDU)" --> UpdatePacing[Update _last_request_finished_at]
        UpdatePacing --> ReleaseLock[Release _communication_lock]
        ReleaseLock --> ReturnResponse([Return decoded response])

        ResultType -- "ModbusResponseError (e.g. DeviceBusy)" --> CheckBusyRetry{retry_on_device_busy?}
        CheckBusyRetry -- Yes --> OuterLoop
        CheckBusyRetry -- No --> RaiseAppError([Raise ModbusResponseError])

        ResultType -- "Transport Failure (Timeout, ConnError)" --> HandleFail[Set _must_reconnect = True]
        HandleFail --> CloseSocket[Close base transport]
        CloseSocket --> CheckRetry{response_retry_strategy has attempts?}
        CheckRetry -- Yes --> OuterLoop
        CheckRetry -- No --> RaiseRetryFailed([Raise RequestRetryFailedError])

************************
 Hardware Pacing Delays
************************

Certain Modbus RTU devices and embedded microcontrollers require delays to prevent
buffer overruns or allow internal state machines to settle:

Wait Between Requests
=====================

The ``wait_between_requests`` parameter (in seconds) enforces a mandatory quiet period
between the completion of one transaction and the transmission of the next.

Even if multiple coroutines or background tasks call
:meth:`~tmodbus.transport.AsyncSmartTransport.send_and_receive` simultaneously, the
transport's internal ``_communication_lock`` ensures that each request waits until the
required quiet interval has elapsed since the previous request finished.

Wait After Connect
==================

The ``wait_after_connect`` parameter (in seconds) introduces an intentional delay
immediately after the physical connection is opened (e.g. after a TCP handshake or
serial port opening), before any Modbus frames are sent. This accommodates devices that
need time to boot up or initialize their communication buffers.

****************
 Callback Hooks
****************

:class:`~tmodbus.transport.AsyncSmartTransport` provides distinct hooks for observing
and reacting to connection events:

1. **``on_connection_lost``**: A callable ``Callable[[Exception | None], None]``
   forwarded directly to the underlying transport protocol. It fires immediately the
   moment a socket or serial port disconnects. This callback operates even if
   ``auto_reconnect`` is disabled.
2. **``on_reconnected``**: A callable or coroutine ``Callable[[], Awaitable[None] |
   None]`` invoked immediately after a successful reconnection is established, before
   any pending PDU is transmitted. This is ideal for re-authenticating or restoring
   device configuration registers.

***************
 Code Examples
***************

Standard Usage
==============

Wrapping a TCP transport with default smart settings:

.. code-block:: python

    import asyncio
    from tmodbus.client import AsyncModbusClient
    from tmodbus.transport import AsyncSmartTransport, AsyncTcpTransport


    async def main() -> None:
        # Create base transport
        base_transport = AsyncTcpTransport(host="192.168.1.100", port=502)

        # Wrap with smart transport
        smart_transport = AsyncSmartTransport(
            base_transport,
            wait_between_requests=0.05,  # 50ms pacing between requests
            wait_after_connect=0.5,  # 500ms warm-up after connect
            auto_reconnect=True,  # default exponential backoff
            retry_on_device_busy=True,  # retry if device returns 0x06
        )

        client = AsyncModbusClient(smart_transport, unit_id=1)
        await client.connect()

        try:
            registers = await client.read_holding_registers(start_address=0, quantity=10)
            print("Registers:", registers)
        finally:
            await client.disconnect()


    if __name__ == "__main__":
        asyncio.run(main())

Custom Reconnection Strategy
============================

To configure constant fixed-interval reconnection instead of exponential backoff:

.. code-block:: python

    from tenacity import AsyncRetrying, stop_after_delay, wait_fixed
    from tmodbus.transport import AsyncSmartTransport, AsyncTcpTransport

    # Reconnect every 5 seconds, giving up after 5 minutes
    custom_reconnect = AsyncRetrying(
        stop=stop_after_delay(300),
        wait=wait_fixed(5.0),
    )

    smart_transport = AsyncSmartTransport(
        AsyncTcpTransport(host="192.168.1.100", port=502),
        auto_reconnect=custom_reconnect,
    )

Monitoring Reconnection Events
==============================

Using ``on_reconnected`` and ``on_connection_lost``:

.. code-block:: python

    import logging
    from tmodbus.transport import AsyncSmartTransport, AsyncTcpTransport

    logger = logging.getLogger(__name__)


    async def handle_reconnected() -> None:
        logger.info("Transport successfully reconnected. Ready to send requests.")


    def handle_connection_lost(exc: Exception | None) -> None:
        logger.warning("Underlying connection dropped: %s", exc)


    smart_transport = AsyncSmartTransport(
        AsyncTcpTransport(host="192.168.1.100", port=502),
        on_reconnected=handle_reconnected,
        on_connection_lost=handle_connection_lost,
    )

########
 Server
########

tModbus provides asynchronous Modbus server implementations that listen for incoming
Modbus requests, decode them into request PDUs, delegate them to a request handler, and
send back the encoded response.

The following server classes are available:

- :class:`~tmodbus.server.AsyncTcpServer`: Modbus TCP Server.
- :class:`~tmodbus.server.AsyncRtuServer`: Modbus RTU Server (over serial).
- :class:`~tmodbus.server.AsyncAsciiServer`: Modbus ASCII Server (over serial).
- :class:`~tmodbus.server.AsyncRtuOverTcpServer`: Modbus RTU over TCP Server.

*********************************************
 Recommended Dispatcher: ModbusRequestRouter
*********************************************

The recommended way to structure your server's request handling is using the
:class:`~tmodbus.server.ModbusRequestRouter` class.

`ModbusRequestRouter` maps incoming Modbus function codes/PDU types to specific handler
functions. The key advantage of the router is **full static type safety**: Python type
checkers (like mypy and pyright) will check and enforce that each registered handler
returns the correct response payload type for its specific request PDU (e.g. returning a
list of integers `list[int]` for a `ReadHoldingRegistersPDU`).

Here is a complete example of setting up a TCP server using `ModbusRequestRouter`:

.. code-block:: python

    import asyncio
    from tmodbus.pdu import ReadHoldingRegistersPDU, WriteSingleRegisterPDU
    from tmodbus.server import AsyncTcpServer, ModbusRequestRouter
    from tmodbus.exceptions import IllegalDataAddressError

    # Our data store: 100 registers initialized to 0
    REGISTER_STORE = [0] * 100

    router = ModbusRequestRouter()


    # The decorator registers the handler for ReadHoldingRegistersPDU requests
    # and mypy validates that this function returns a list[int]
    @router.register(ReadHoldingRegistersPDU)
    async def handle_read_holding_registers(
        unit_id: int, request: ReadHoldingRegistersPDU
    ) -> list[int]:
        addr = request.start_address
        qty = request.quantity
        if addr + qty > len(REGISTER_STORE):
            # pass the function code into the exception, as it must be
            # encoded into the Modbus response PDU.
            raise IllegalDataAddressError(request.function_code)
        return REGISTER_STORE[addr : addr + qty]


    # mypy validates that this function returns an int (the written register value)
    @router.register(WriteSingleRegisterPDU)
    async def handle_write_single_register(
        unit_id: int, request: WriteSingleRegisterPDU
    ) -> int:
        addr = request.address
        val = request.value
        if addr >= len(REGISTER_STORE):
            raise IllegalDataAddressError(request.function_code)
        REGISTER_STORE[addr] = val
        return val


    async def main() -> None:
        # Pass the router as the server's handler
        server = AsyncTcpServer(host="127.0.0.1", port=5020, handler=router)
        print("Starting server on 127.0.0.1:5020...")
        await server.serve_forever()


    if __name__ == "__main__":
        asyncio.run(main())

*************************************
 Implementing ModbusHandler Directly
*************************************

If you do not want to use the router, the server will accept any callable that conforms
to the :class:`~tmodbus.server.ModbusHandler` protocol.

The protocol is defined as:

.. code-block:: python

    from typing import Protocol, Any
    from collections.abc import Awaitable
    from tmodbus.pdu import BasePDU


    class ModbusHandler(Protocol):
        def __call__[T](self, unit_id: int, request: BasePDU[T], /) -> Awaitable[T]:
            """Process a Modbus request and return the response value."""
            ...

        def supports_unit_id(self, unit_id: int, /) -> bool:
            """Check if the handler supports the given unit ID."""
            return True

Understanding supports_unit_id
==============================

The `supports_unit_id` check is only important for **serial-based servers** (Modbus RTU
and Modbus ASCII).

On a serial line (RS-485 bus), multiple devices (servers) are connected to the same
physical bus. When a client/master sends a request, every server on the bus receives the
raw byte stream. Each server must check the unit ID in the header: - If the server
supports/owns that unit ID (or if it is unit ID 0 for broadcast requests), it processes
the request and replies. - If the server does **not** support the unit ID, it **must
ignore the request completely** (not even responding with an error), to allow the
correct server to respond and prevent bus contention.

In contrast, Modbus TCP is a point-to-point IP connection, so unit ID filtering is
usually not critical unless the server acts as a gateway to a serial network.

If you implement the handler as a normal Python function, you can attach the
`supports_unit_id` attribute directly to the function object after its definition.

*************************
 Direct Handler Examples
*************************

Here are two examples demonstrating how to build a direct handler as a normal Python
function.

Example 1: A Simple Single-Request Function Handler
===================================================

This simple function only handles reading holding registers. It attaches the
`supports_unit_id` check to the function object after its definition to limit responses
to unit ID 1.

.. code-block:: python

    from typing import Any
    from tmodbus.exceptions import IllegalFunctionError
    from tmodbus.pdu import BasePDU, ReadHoldingRegistersPDU


    async def simple_handler(unit_id: int, request: BasePDU[Any]) -> Any:
        if isinstance(request, ReadHoldingRegistersPDU):
            # Return list of register values (e.g. 16-bit integers)
            return [42] * request.quantity

        # Raise exception for unsupported function codes
        raise IllegalFunctionError(request.function_code)


    # Attach the unit ID support check to the function (crucial for serial lines)
    simple_handler.supports_unit_id = lambda unit_id: unit_id == 1

Example 2: A Function Handler Using Match/Case with Classes
===========================================================

Python 3.10+ match/case pattern matching on class types is an excellent way to route and
process different request types inside a single function handler.

.. code-block:: python

    from typing import Any
    from tmodbus.exceptions import IllegalDataAddressError, IllegalFunctionError
    from tmodbus.pdu import (
        BasePDU,
        ReadHoldingRegistersPDU,
        WriteSingleRegisterPDU,
    )

    # Local register memory store
    registers = [0] * 100


    async def match_case_handler(unit_id: int, request: BasePDU[Any]) -> Any:
        match request:
            case ReadHoldingRegistersPDU(start_address=addr, quantity=qty):
                if addr + qty > len(registers):
                    # pass the function code into the exception, as it must be
                    # encoded into the Modbus response PDU.
                    raise IllegalDataAddressError(request.function_code)
                return registers[addr : addr + qty]

            case WriteSingleRegisterPDU(address=addr, value=val):
                if addr >= len(registers):
                    raise IllegalDataAddressError(request.function_code)
                registers[addr] = val
                return val

            case _:
                raise IllegalFunctionError(request.function_code)


    # Attach the unit ID check. Here we support unit IDs 1, 2, and 3
    match_case_handler.supports_unit_id = lambda unit_id: unit_id in (1, 2, 3)

***************************************
 Request Context & Connection Metadata
***************************************

When handling requests, you might need information about the client connection that
isn't included in the standard Modbus frame (for example, the client's network IP
address or their TLS certificate).

tModbus supports automatically passing connection and request metadata to your handlers.
If a registered router handler or custom callable accepts at least three positional
arguments, the server will automatically pass a :class:`~tmodbus.server.RequestContext`
object as the third argument:

.. code-block:: python

    from tmodbus.server import RequestContext, ModbusRequestRouter
    from tmodbus.pdu import ReadHoldingRegistersPDU

    router = ModbusRequestRouter()


    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(
        unit_id: int,
        request: ReadHoldingRegistersPDU,
        context: RequestContext,  # Automatically injected
    ) -> list[int]:
        # Access connection metadata
        if context.peer_addr:
            ip, port = context.peer_addr[:2]
            print(f"Request from client {ip}:{port}")
        return [42] * request.quantity

The `RequestContext` object has the following fields:

- ``peer_addr``: A tuple containing client IP address and port (e.g. ``("127.0.0.1",
  54321)``) if available.
- ``client_cert``: A :class:`cryptography.x509.Certificate` containing the parsed client
  x.509 certificate when connected over TLS.

*************************************************
 Modbus/TCP Security (mbaps) & Mutual TLS (mTLS)
*************************************************

The standard Modbus/TCP Security protocol (**mbaps**), defined in the
*MB-TCP-Security-v36_2021-07-30* specification, secures Modbus communication by running
the protocol over TLS (using the standard port **802**).

To build a specification-compliant secure server, you must configure an
:class:`ssl.SSLContext` that requires **mutual TLS (mTLS)** and minimum TLS version 1.2.

Setting up a Secure Server
==========================

Here is a complete setup for a secure server utilizing mutual TLS and role validation:

.. code-block:: python

    import ssl
    from tmodbus.pdu import ReadHoldingRegistersPDU
    from tmodbus.server import AsyncTcpServer, ModbusRequestRouter, RequestContext
    from tmodbus.server.security import extract_modbus_role
    from tmodbus.exceptions import IllegalFunctionError

    router = ModbusRequestRouter()


    @router.register(ReadHoldingRegistersPDU)
    async def handle_secure_read(
        unit_id: int,
        request: ReadHoldingRegistersPDU,
        context: RequestContext,
    ) -> list[int]:
        # 1. Access the raw cryptography client cert from context
        cert = context.client_cert
        if not cert:
            raise IllegalFunctionError(request.function_code)

        # 2. Use tModbus helper to extract the role extension OID 1.3.6.1.4.1.50316.802.1
        role = extract_modbus_role(cert)

        # 3. Perform Role-Based Access Control (RBAC)
        if role not in {"Operator", "Admin"}:
            # R-31: Specification requires raising Illegal Function (0x01) for unauthorized access
            raise IllegalFunctionError(request.function_code)

        return [1, 2, 3]


    async def main() -> None:
        # Build TLS Server Context requiring mutual authentication
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
        ctx.load_verify_locations(cafile="ca.crt")

        ctx.verify_mode = ssl.CERT_REQUIRED  # Enforce mTLS client cert validation
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # Mandate TLS version >= 1.2

        # Start secure server on Standard Security Port 802
        server = AsyncTcpServer(host="0.0.0.0", port=802, handler=router, ssl_context=ctx)
        await server.serve_forever()

Role-Based Authorization (RBAC)
===============================

Under the mbaps specification, client roles are stored in the client certificate as a
custom x.509 extension with the Modbus.org Private Enterprise OID
``1.3.6.1.4.1.50316.802.1`` encoded as an ASN.1 UTF8String.

The :func:`~tmodbus.server.security.extract_modbus_role` utility extracts this role
value. If the extension is absent, it returns ``None``.

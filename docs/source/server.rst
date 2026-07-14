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

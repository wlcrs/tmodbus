"""Example of an Async TCP Modbus Server."""

import asyncio
import logging
from typing import Any

from tmodbus.exceptions import IllegalDataAddressError, IllegalFunctionError
from tmodbus.pdu import BasePDU, ReadHoldingRegistersPDU, WriteMultipleRegistersPDU, WriteSingleRegisterPDU
from tmodbus.server import AsyncTcpServer

# Set up logging to see the server output
logging.basicConfig(level=logging.INFO)

# Our simple data store: 100 registers initialized to 0
REGISTER_STORE = [0] * 100


async def my_modbus_handler(unit_id: int, request: BasePDU[Any]) -> list[int] | int:
    """Handle incoming Modbus requests.

    This simple example implements read/write for holding registers.
    """
    # Reject anything that isn't for unit ID 1
    if unit_id != 1:
        raise IllegalFunctionError(1, request.function_code)

    if isinstance(request, ReadHoldingRegistersPDU):
        addr = getattr(request, "start_address", 0)
        qty = getattr(request, "quantity", 0)
        if addr + qty > len(REGISTER_STORE):
            raise IllegalDataAddressError(2, request.function_code)
        return REGISTER_STORE[addr : addr + qty]
    if isinstance(request, WriteSingleRegisterPDU):
        addr = request.address
        val = request.value
        if addr >= len(REGISTER_STORE):
            raise IllegalDataAddressError(2, request.function_code)
        REGISTER_STORE[addr] = val
        return val
    if isinstance(request, WriteMultipleRegistersPDU):
        addr = getattr(request, "start_address", 0)
        vals = getattr(request, "values", [])
        if addr + len(vals) > len(REGISTER_STORE):
            raise IllegalDataAddressError(2, request.function_code)
        REGISTER_STORE[addr : addr + len(vals)] = vals
        return len(vals)

    # If the request is for an unsupported function code, return ILLEGAL_FUNCTION
    raise IllegalFunctionError(1, request.function_code)


async def main() -> None:
    """Run the Modbus TCP Server."""
    # Create the server on localhost port 5020 (to avoid needing root privileges for port 502)
    server = AsyncTcpServer(host="127.0.0.1", port=5020, handler=my_modbus_handler)

    # Run the server forever
    print("Starting Modbus TCP Server on 127.0.0.1:5020")
    print("Press Ctrl+C to stop.")
    await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped.")

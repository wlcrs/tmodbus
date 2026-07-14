"""Example of an Async TCP Modbus Server."""

import asyncio
import logging

from tmodbus.exceptions import IllegalDataAddressError
from tmodbus.pdu import ReadHoldingRegistersPDU, WriteMultipleRegistersPDU, WriteSingleRegisterPDU
from tmodbus.server import AsyncTcpServer, ModbusRequestRouter

# Set up logging to see the server output
logging.basicConfig(level=logging.INFO)

# Our simple data store: 100 registers initialized to 0
REGISTER_STORE = [0] * 100

router = ModbusRequestRouter()


@router.register(ReadHoldingRegistersPDU, unit_id=1)
async def handle_read_holding_registers(_unit_id: int, request: ReadHoldingRegistersPDU) -> list[int]:
    """Handle incoming Read Holding Registers request."""
    addr = request.start_address
    qty = request.quantity
    if addr + qty > len(REGISTER_STORE):
        raise IllegalDataAddressError(request.function_code)
    return REGISTER_STORE[addr : addr + qty]


@router.register(WriteSingleRegisterPDU, unit_id=1)
async def handle_write_single_register(_unit_id: int, request: WriteSingleRegisterPDU) -> int:
    """Handle incoming Write Single Register request."""
    addr = request.address
    val = request.value
    if addr >= len(REGISTER_STORE):
        raise IllegalDataAddressError(request.function_code)
    REGISTER_STORE[addr] = val
    return val


@router.register(WriteMultipleRegistersPDU, unit_id=1)
async def handle_write_multiple_registers(_unit_id: int, request: WriteMultipleRegistersPDU) -> int:
    """Handle incoming Write Multiple Registers request."""
    addr = request.start_address
    vals = request.values
    if addr + len(vals) > len(REGISTER_STORE):
        raise IllegalDataAddressError(request.function_code)
    REGISTER_STORE[addr : addr + len(vals)] = vals
    return len(vals)


async def main() -> None:
    """Run the Modbus TCP Server."""
    # Create the server on localhost port 5020 (to avoid needing root privileges for port 502)
    server = AsyncTcpServer(host="127.0.0.1", port=5020, handler=router)

    # Run the server forever
    print("Starting Modbus TCP Server on 127.0.0.1:5020")
    print("Press Ctrl+C to stop.")
    await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped.")

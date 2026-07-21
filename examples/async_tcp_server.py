"""Example of an Async TCP Modbus Server."""

import asyncio
import ipaddress
import logging

from tmodbus.exceptions import IllegalDataAddressError
from tmodbus.pdu import ReadHoldingRegistersPDU, WriteMultipleRegistersPDU, WriteSingleRegisterPDU
from tmodbus.server import AsyncTcpServer, ModbusRequestRouter, RequestContext

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


@router.register(ReadHoldingRegistersPDU, unit_id=2)
async def handle_read_client_ip(
    _unit_id: int,
    request: ReadHoldingRegistersPDU,
    context: RequestContext,
) -> list[int]:
    """Handle incoming request to read the client's IP address.

    This context-aware handler reads the peer address from RequestContext,
    encodes the IP bytes into 16-bit register values, and returns them.
    (e.g., "127.0.0.1" is packed as [32512, 1] which is 0x7f00, 0x0001).
    """
    ip_str = "127.0.0.1"
    if context.peer_addr:
        ip_str = context.peer_addr[0]

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        packed_bytes = list(ip_obj.packed)
        # Pack every 2 bytes into a 16-bit register
        registers = [(packed_bytes[i] << 8) | packed_bytes[i + 1] for i in range(0, len(packed_bytes), 2)]

        # Match the requested quantity by padding or slicing
        if len(registers) < request.quantity:
            registers.extend([0] * (request.quantity - len(registers)))
        return registers[: request.quantity]
    except ValueError:
        return [0] * request.quantity


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

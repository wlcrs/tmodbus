"""Example of an asynchronous RTU Modbus client using tmodbus."""

import asyncio

from tmodbus import create_async_rtu_client
from tmodbus.exceptions import InvalidResponseError, ModbusConnectionError, ModbusResponseError


async def example_rtu_client() -> None:
    """Asynchronous RTU Modbus client example."""
    # Replace with your Modbus server's IP and por
    port = "/dev/ttyUSB0"
    baudrate = 9600  # Adjust baudrate as needed

    unit_id = 1  # Modbus unit ID of the target device

    # The create_async_rtu_client function returns an instance of AsyncModbusClient
    client = create_async_rtu_client(port, baudrate=baudrate, unit_id=unit_id)

    try:
        await client.connect()
        # Read 2 holding registers starting at address 100
        coils_response = await client.read_holding_registers(start_address=100, quantity=2)

        print("Contents of holding registers 100 and 101: ", coils_response)

        # Write value 123 to holding register at address 1
        await client.write_single_register(address=1, value=123)

        # Write values [10, 20, 30] to holding registers starting at address 10
        await client.write_multiple_registers(start_address=10, values=[10, 20, 30])

    except ModbusResponseError as e:
        print(f"The server responded with error code {e.error_code:#04x} for function {e.function_code:#04x}")
    except InvalidResponseError as e:
        print(f"Received invalid response: {e}")
    except ModbusConnectionError as e:
        print(f"A connection error occurred: {e}")
    finally:
        await client.disconnect()

    # Alternatively, you can use the client as an async context manager
    # which automatically handles connection and disconnection
    async with create_async_rtu_client(port, baudrate=baudrate, unit_id=unit_id) as client2:
        print("Status of coils 0-7: ", await client2.read_coils(start_address=0, quantity=8))


if __name__ == "__main__":
    asyncio.run(example_rtu_client())

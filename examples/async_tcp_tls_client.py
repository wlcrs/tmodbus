"""Example of an asynchronous TCP Modbus client over an SSL connection using tmodbus."""

import asyncio
import ssl

from tmodbus import create_async_tcp_client
from tmodbus.exceptions import InvalidResponseError, ModbusConnectionError, ModbusResponseError


async def example_tcp_client() -> None:
    """Asynchronous TCP Modbus client example."""
    # Replace with your Modbus server's IP and port
    host = "127.0.0.1"
    port = 502

    unit_id = 1  # Modbus unit ID of the target device

    # You can pass any additional parameters supported by `asyncio.open_connection`
    # For example, to use an SSL context, you can set `ssl=True` or provide a custom SSLContext

    # The create_async_tcp_client function returns an instance of AsyncModbusClient
    client = create_async_tcp_client(host, port, unit_id=unit_id, ssl=True)

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
    # which automatically handles connection and disconnection.
    # We also demonstrate passing of a custom SSL context here.

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_default_certs(purpose=ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED

    async with create_async_tcp_client(host, port, unit_id=unit_id, ssl=ssl_context) as client2:
        print("Status of coils 0-7: ", await client2.read_coils(start_address=0, quantity=8))


if __name__ == "__main__":
    asyncio.run(example_tcp_client())

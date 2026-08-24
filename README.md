# tModbus

[![Homepage](https://img.shields.io/badge/Homepage-2088ff?logo=github&logoColor=white)](https://github.com/wlcrs/tmodbus)
[![Documentation](https://img.shields.io/badge/Documentation-2D963D?logo=read-the-docs&logoColor=white)](https://tmodbus.readthedocs.io)
[![GitHub License](https://img.shields.io/github/license/wlcrs/tmodbus)](https://github.com/wlcrs/tmodbus/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/wlcrs/tmodbus.svg)](https://github.com/wlcrs/tmodbus/releases)
[![Python Versions](https://img.shields.io/pypi/pyversions/tmodbus)](https://pypi.org/p/tmodbus/)
[![Testing](https://github.com/wlcrs/tmodbus/actions/workflows/tests.yml/badge.svg)](https://github.com/wlcrs/tmodbus/actions/workflows/tests.yml)
## About

A modern Python Modbus library that is fully **t**yped and well-**t**ested.

Modbus is based on the [_master/slave_](https://en.wikipedia.org/wiki/Master%E2%80%93slave_(technology)) communication pattern.
We choose to use the terminology _client_ and _server_ instead, as it is more clear.

## Features

- Pure Python library with minimal dependencies
- Fully **t**yped
- Full **t**est coverage
- Support for Modbus TCP, RTU, ASCII, RTU-over-TCP and UDP clients
- Support for Modbus TCP, RTU, ASCII, RTU-over-TCP and UDP servers
- Support for TCP over SSL/TLS client and server connections, including Modbus/TCP Security (mbaps) with mutual authentication and role-based access control (RBAC)
- Auto reconnect and retry functionality (which can be enabled optionally)
- Extensible with custom Modbus functions and exception codes
- Open source (BSD)

## Supported function codes

* Read coils (`0x01`)
* Read discrete inputs (`0x02`)
* Read holding registers (`0x03`)
* Read input registers (`0x04`)
* Write single coil (`0x05`)
* Write single register (`0x06`)
* Read exception status (`0x07`, serial line only)
* Diagnostics (`0x08`, serial line only — all 15 standard sub-functions supported)
* Get comm event counter (`0x0B`, serial line only)
* Get comm event log (`0x0C`, serial line only)
* Write multiple coils (`0x0F`)
* Write multiple registers (`0x10`)
* Report server ID (`0x11`, serial line only)
* Read file record (`0x14`)
* Write file record (`0x15`)
* Mask write register (`0x16`)
* Read/write multiple registers (`0x17`)
* Read FIFO queue (`0x18`)
* Read device identification (`0x2B / 0x0E`)

## Server Implementations

`tModbus` includes asynchronous Modbus server implementations across all supported transports:

* `AsyncTcpServer`: Modbus TCP server (supports plain TCP and SSL/TLS / Modbus Security)
* `AsyncRtuServer`: Modbus RTU server over serial port
* `AsyncAsciiServer`: Modbus ASCII server over serial port
* `AsyncRtuOverTcpServer`: Modbus RTU over TCP server
* `AsyncUdpServer`: Modbus UDP server

### Key Server Features

* **Type-Safe Dispatcher (`ModbusRequestRouter`)**: Map request PDU classes directly to async handlers. Static type checkers (e.g., mypy, pyright) validate that handler return types match the expected Modbus response payload.
* **Unit ID Filtering**: Register handlers for specific unit IDs (slave addresses) or use wildcards to handle requests for all unit IDs.
* **Context Awareness (`RequestContext`)**: Handlers can optionally receive connection metadata such as the client's peer IP address and TLS client certificate.
* **Modbus/TCP Security (mbaps)**: Supports mutual TLS (mTLS) authentication and role extraction (`extract_modbus_role`) for Role-Based Access Control (RBAC).
* **Standard Exception Handling**: Raising exceptions such as `IllegalDataAddressError` or `IllegalDataValueError` automatically encodes and returns the appropriate Modbus exception response PDU.

## Examples

### Async TCP Client

```python
import asyncio

from tmodbus import create_async_tcp_client


async def main() -> None:
    """Show example of reading a Modbus register."""
    async with create_async_tcp_client("127.0.0.1", 502, unit_id=1) as client:
        response = await client.read_holding_registers(start_address=100, quantity=2)
        print("Contents of holding registers 100 and 101: ", response)


if __name__ == "__main__":
    asyncio.run(main())
```

### Async TCP Server

```python
import asyncio

from tmodbus.exceptions import IllegalDataAddressError
from tmodbus.pdu import ReadHoldingRegistersPDU, WriteSingleRegisterPDU
from tmodbus.server import AsyncTcpServer, ModbusRequestRouter

# Simple in-memory register store: 100 registers
REGISTER_STORE = [0] * 100

router = ModbusRequestRouter()


@router.register(ReadHoldingRegistersPDU, unit_id=1)
async def handle_read_holding_registers(_unit_id: int, request: ReadHoldingRegistersPDU) -> list[int]:
    """Handle incoming Read Holding Registers requests."""
    addr = request.start_address
    qty = request.quantity
    if addr + qty > len(REGISTER_STORE):
        raise IllegalDataAddressError(request.function_code)
    return REGISTER_STORE[addr : addr + qty]


@router.register(WriteSingleRegisterPDU, unit_id=1)
async def handle_write_single_register(_unit_id: int, request: WriteSingleRegisterPDU) -> int:
    """Handle incoming Write Single Register requests."""
    if request.address >= len(REGISTER_STORE):
        raise IllegalDataAddressError(request.function_code)
    REGISTER_STORE[request.address] = request.value
    return request.value


async def main() -> None:
    """Run the Modbus TCP Server."""
    server = AsyncTcpServer(host="127.0.0.1", port=5020, handler=router)
    print("Starting Modbus TCP Server on 127.0.0.1:5020...")
    await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
```

Various client and server examples (including RTU, ASCII, RTU-over-TCP, UDP, and Modbus Security over TLS) can be found in the [examples](./examples) folder.

## Dependencies

**async-serial**

This library uses [serialx](https://puddly.github.io/serialx/) to
access the serial port when using async RTU or ASCII.

Use `pip install tmodbus[async-serial]` to install.

## Changelog & releases

This repository keeps a change log using [GitHub's releases](https://github.com/wlcrs/tmodbus/releases)
functionality. The format of the log is based on
[Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

Releases are based on [Semantic Versioning](http://semver.org/spec/v2.0.0.html), and use the format
of `MAJOR.MINOR.PATCH`. In a nutshell, the version will be incremented
based on the following:

- `MAJOR`: Incompatible or major changes.
- `MINOR`: Backwards-compatible new features and enhancements.
- `PATCH`: Backwards-compatible bugfixes and package updates.

## Contributing

This is an active open-source project. We are always open to people who want to
use the code or contribute to it.

We've set up a separate document for our
[contribution guidelines](.github/CONTRIBUTING.md).

Thank you for being involved! :heart_eyes:

### Setting up a development environment

This Python project is fully managed using the [uv] dependency manager.

You need at least:

- Python 3.12+
- [uv][uv-install]

To install all packages, including all development requirements:

```bash
uv sync  --all-extras --dev
```

As this repository uses the [pre-commit][pre-commit] framework, all changes
are linted and tested with each commit. You can run all checks and tests
manually, using the following command:

```bash
uv run pre-commit run --all-files
```

To run just the Python tests:

```bash
uv run pytest
```


## Protocol-Specification

- [Modbus Application Protocol Specification v1.1b3 (PDF)](./docs/specifications/Modbus_Application_Protocol_V1_1b3.pdf)
- [Modbus over serial line specification and implementation guide v1.02 (PDF)](./docs/specifications//Modbus_over_serial_line_V1_02.pdf)
- [Modbus Messaging on TCP/IP Implementation Guide v1.0b (PDF)](./docs/specifications/Modbus_Messaging_Implementation_Guide_V1_0b.pdf)


[uv-install]: https://docs.astral.sh/uv/getting-started/installation/
[uv]: https://docs.astral.sh/uv/
[pre-commit]: https://pre-commit.com/

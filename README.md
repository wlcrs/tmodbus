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
- Support for Modbus TCP, RTU, ASCII and RTU-over-TCP clients
- Support for TCP over SSL connections
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
* Read exception status (`0x07`)
* Write multiple coils (`0x0F`)
* Write multiple registers (`0x10`)
* Report server ID (`0x11`)
* Read file record (`0x14`)
* Write file record (`0x15`)
* Mask write register (`0x16`)
* Read/write multiple registers (`0x17`)
* Read FIFO queue (`0x18`)
* Read device identification (`0x2B / 0x0E`)

## Examples

A simple example of an Async TCP client:

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

Various examples for Modbus RTU and TCP can be found in the [examples](./examples) folder.

## Dependencies

**async-serial**

This library uses [pyserial-asyncio-fast](https://pypi.org/project/pyserial-asyncio-fast/) to
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

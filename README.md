# tModbus

A modern Python Modbus library that is fully **t**yped and well-**t**ested.

Modbus is based on the [_master/slave_](https://en.wikipedia.org/wiki/Master%E2%80%93slave_(technology)) communication pattern.
We choose to use the terminology _client_ and _server_ instead, as it is more clear.

## Features

- Pure Python library with minimal dependencies
- Fully **t**yped
- Full **t**est coverage
- Support for both Modbus TCP and RTU clients
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
* Write multiple coils (`0x0f`)
* Write multiple registers (`0x10`)
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

**async-rtu**

This library uses [pyserial-asyncio-fast](https://pypi.org/project/pyserial-asyncio-fast/) to
access the serial port when using async RTU.

Use `pip install tmodbus[async-rtu]` to install.

**smart**

This library uses [tenacity](https://github.com/jd/tenacity) to implement the reconnect and retry-logic,
giving you access to a powerful API to customize the retry behavior of this library.

Use `pip install tmodbus[smart]` to install.

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

## Protocol-Specification

- [Modbus Application Protocol Specification v1.1b3 (PDF)](http://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
- [Modbus over serial line specification and implementation guide v1.02 (PDF)](http://modbus.org/docs/Modbus_over_serial_line_V1_02.pdf)
- [Modbus Messaging on TCP/IP Implementation Guide v1.0b (PDF)](http://modbus.org/docs/Modbus_Messaging_Implementation_Guide_V1_0b.pdf)

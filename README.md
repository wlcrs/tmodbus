# tModbus

A modern Python Modbus library that is fully **t**yped and well-**t**ested.

Modbus is based on the [_master/slave_](https://en.wikipedia.org/wiki/Master%E2%80%93slave_(technology)) communication pattern. 
We choose to use the terminology _client_ and _server_ instead, as it is more clear.

## Features

- Pure Python library with minimal dependencies
- Fully typed
- Support for both Modbus TCP and RTU clients
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

## Versioning

This library follows the [Semantic Versioning](https://semver.org/) specification.

## Protocol-Specification

- [Modbus Application Protocol Specification v1.1b3 (PDF)](http://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
- [Modbus over serial line specification and implementation guide v1.02 (PDF)](http://modbus.org/docs/Modbus_over_serial_line_V1_02.pdf)
- [Modbus Messaging on TCP/IP Implementation Guide v1.0b (PDF)](http://modbus.org/docs/Modbus_Messaging_Implementation_Guide_V1_0b.pdf)



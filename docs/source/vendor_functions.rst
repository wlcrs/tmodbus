Vendor functions
================

This library makes it easy to add support for vendor-specific Modbus functions.
Vendor functions are custom Modbus functions that are not part of the standard Modbus specification.
They are typically used by manufacturers to implement proprietary features in their devices.

To add support for a vendor-specific function, you need to create a new PDU class that inherits
from :class:`tmodbus.pdu.BaseClientPDU` or :class:`tmodbus.pdu.BaseSubFunctionClientPDU`, depending on
whether the function uses sub-function codes.

After creating the PDU class, you need to register it using the :func:`tmodbus.pdu.register_pdu_class` function.

We suggest that you inspect the source code of existing PDUs in the :mod:`tmodbus.pdu` module to see how they are
implemented. For example, you can look at the :class:`tmodbus.pdu.device.ReadDeviceIdentificationPDU` class, which
implements the standard Modbus function code 0x2B with sub-function code 0x0E.


Example implementation
----------------------

This is an example of how to implement a vendor-specific Modbus function.

This vendor uses function code 0x41 with sub-function code 0x24 to request a login challenge from a device.

The request PDU has the following format:

.. list-table::
    :header-rows: 1
    :widths: 20 20 30 30

    * - Function Code
      - Sub-function Code
      - Data Length (1)
      - Value (1)
    * - 0x41
      - 0x24
      - 0x01
      - 0x00

The response PDU has the following format:

.. list-table::
    :header-rows: 1
    :widths: 20 20 30 30

    * - Function Code
      - Sub-function Code
      - Data Length (1)
      - Challenge (16)
    * - 0x41
      - 0x24
      - 0x11
      - <16 bytes>

Example code:
+++++++++++++

Note that the use of the `LoginChallenge` class is a bit contrived in this example,
but it shows how you can return a complex object from the `decode_response` method.

.. code-block:: python

    import struct
    from dataclasses import dataclass

    from tmodbus.pdu import BaseSubFunctionClientPDU, register_pdu_class

    @dataclass(frozen=True)
    class LoginChallenge:
        """Login challenge response."""

        challenge: bytes  # 16 bytes

    @dataclass(frozen=True)
    class LoginRequestChallengePDU(BaseSubFunctionClientPDU[LoginChallenge]):
    """Modbus PDU to request a login challenge."""

    function_code = 0x41
    sub_function_code = 0x24
    rtu_byte_count_pos = 3

    def encode_request(self) -> bytes:
        """Encode LoginRequestChallengePDU."""
        data_length = 1
        value = 0
        return struct.pack(">BBBB", self.function_code, self.sub_function_code, data_length, value)

    def decode_response(self, response: bytes) -> bytes:
        """Decode LoginRequestChallengePDU response."""
        response_header_struct = struct.Struct(">BBB")
        (function_code, sub_function_code, response_content_length) = response_header_struct.unpack_from(response, 0)

        if function_code != self.function_code:
            msg = f"Invalid function code: expected {self.function_code:#04x}, received {function_code:#04x}"
            raise ValueError(msg)

        if sub_function_code != self.sub_function_code:
            msg = (
                f"Unexpected sub function code: expected {self.sub_function_code:#04x}, received {sub_function_code:#04x}"
            )
            raise ValueError(msg)

        expected_response_content_length = 17
        if expected_response_content_length != response_content_length:
            msg = (
                f"Invalid response content length length: expected {expected_response_content_length}, "
                f"received {response_content_length}"
            )
            raise ValueError(msg)

        inverter_challenge_length = 16
        return LoginChallenge(
            challenge=response[response_header_struct.size : response_header_struct.size + inverter_challenge_length]
        )


    register_pdu_class(LoginRequestChallengePDU)


Using your custom PDU
----------------------

To use your custom PDU, you can create an instance of it and pass it to the
:func:`tmodbus.client.AsyncModbusClient.execute` method.


.. code-block:: python

    import asyncio
    from tmodbus import create_async_tcp_client

    async def main():
        async with create_async_tcp_client(host="localhost", port=502) as client:
            pdu = LoginRequestChallengePDU()
            response : LoginChallenge = await client.execute(pdu)
            print(f"Received challenge: {response.challenge.hex()}")

    if __name__ == "__main__":
        asyncio.run(main())

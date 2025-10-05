Batch reading registers
=======================

Parsing multiple registers with `Struct`
----------------------------------------

When reading a large number of registers, it is often more efficient to read them in batches rather than one at a time.
The `AsyncModbusClient` class provides methods to read multiple registers in a single request.

For this, we leverage the :class:`struct.Struct` class from the Python standard library to define the data structure of the registers we want to read.
You can pass any `struct.Struct` object into the :meth:`~tmodbus.pdu.holding_registers_struct.HoldingRegisterReadMixin.read_struct_format` method.


For example, if we want to read 10 consecutive holding registers starting from address 100, and interpret them as two 32-bit integers followed by a 32-bit float, we can do the following:

.. code-block:: python

    import asyncio
    import struct

    from tmodbus import create_async_tcp_client

    async def main() -> None:
        """Show example of reading a batch of Modbus registers."""
        register_format = ">iif"  # Big-endian: 2x int32, 1x float32 # codespell:ignore iif
        async with create_async_tcp_client("127.0.0.1", 502, unit_id=1) as client:
            response = await client.read_struct_format(
                start_address=100,
                format_struct=register_format,
            )
            int1, int2, float1 = response
            print(f"Read values: int1={int1}, int2={int2}, float1={float1}")

    if __name__ == "__main__":
        asyncio.run(main())

As one Modbus register is 16 bits (2 bytes), the above example reads a total of 6 registers (4 bytes for each int32 and float32, totaling 12 bytes).

Word ordering
-------------

Modbus defines registers as 16-bit values, but many devices use 32-bit or 64-bit values that span multiple registers.
While the order of the bytes within each register is defined by the Modbus specification (big-endian), the order for values spanning multiple registers (word order)
is not standardized and can vary between devices.

The `AsyncModbusClient` class allows you to specify the word order when reading structured data. You can set the `word_order` attribute to either `"big"` or `"little"` to control
the order of the registers.

By default, the word order is set to `"big"`, meaning that the first register read will be the most significant word.

This library includes an utility class :class:`~tmodbus.utils.WordOrderAwareStruct` that extends `struct.Struct` to handle word order automatically.
So even if your device uses little-endian word order, you can still use the same struct format string as you would for big-endian.

.. note::

   The `word_order` attribute only affects methods that read or write structured data using `struct.Struct`, such as
   :meth:`~tmodbus.pdu.holding_registers_struct.HoldingRegisterReadMixin.read_struct_format` and
   :meth:`~tmodbus.pdu.holding_registers_struct.HoldingRegisterWriteMixin.write_struct_format`, and all the methods that build on them
   (like :meth:`~tmodbus.pdu.holding_registers_struct.HoldingRegisterReadMixin.read_uint32`, and :meth:`~tmodbus.pdu.holding_registers_struct.HoldingRegisterWriteMixin.write_float`).
   It does not affect methods that read or write raw registers, such as :meth:`~tmodbus.client.AsyncModbusClient.read_holding_registers` or :meth:`~tmodbus.client.AsyncModbusClient.write_multiple_registers`.

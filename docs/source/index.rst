tModbus
=======

A modern Python Modbus library that is fully **typed** and well- **tested**.

Modbus is based on the `master/slave <https://en.wikipedia.org/wiki/Master%E2%80%93slave_(technology)>`__ communication pattern.
We choose to use the terminology *client* and *server* instead, as it is more clear.

A simple example
----------------

.. code-block:: python

   import asyncio

   from tmodbus import create_async_tcp_client


   async def main() -> None:
      """Show example of reading a Modbus register."""
      async with create_async_tcp_client("127.0.0.1", 502, unit_id=1) as client:
         response = await client.read_holding_registers(start_address=100, quantity=2)
         print("Contents of holding registers 100 and 101: ", response)


   if __name__ == "__main__":
      asyncio.run(main())

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   api
   architecture
   examples
   vendor_functions

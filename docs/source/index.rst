tModbus
=======

.. image:: https://img.shields.io/badge/Homepage-2088ff?logo=github&logoColor=white
   :target: https://github.com/wlcrs/tmodbus
   :alt: Homepage

.. image:: https://img.shields.io/badge/Documentation-2D963D?logo=read-the-docs&logoColor=white
   :target: https://tmodbus.readthedocs.io
   :alt: Documentation

.. image:: https://img.shields.io/github/license/wlcrs/tmodbus
   :target: https://github.com/wlcrs/tmodbus/blob/main/LICENSE
   :alt: GitHub License

.. image:: https://img.shields.io/github/v/release/wlcrs/tmodbus.svg
   :target: https://github.com/wlcrs/tmodbus/releases
   :alt: Release

.. image:: https://img.shields.io/pypi/pyversions/tmodbus
   :target: https://pypi.org/p/tmodbus/
   :alt: Python Versions

.. image:: https://github.com/wlcrs/tmodbus/actions/workflows/tests.yml/badge.svg
   :target: https://github.com/wlcrs/tmodbus/actions/workflows/tests.yml
   :alt: Testing

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

   batch_reading
   vendor_functions

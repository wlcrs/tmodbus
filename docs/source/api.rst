API
===

General
-------

.. autofunction:: tmodbus.create_async_tcp_client

.. autofunction:: tmodbus.create_async_rtu_client

Client layer
------------

.. automodule:: tmodbus.client
    :members:

Transport layer
---------------
.. automodule:: tmodbus.transport
    :members:

PDU layer
---------
.. automodule:: tmodbus.pdu
    :members:

Exceptions
----------

When the server responds with an error, tModbus will raise the corresponding subclass of :class:`~tmodbus.exceptions.ModbusResponseError`:

- 0x01 Illegal function: :class:`~tmodbus.exceptions.IllegalFunctionError`
- 0x02 Illegal data address: :class:`~tmodbus.exceptions.IllegalDataAddressError`
- 0x03 Illegal data value: :class:`~tmodbus.exceptions.IllegalDataValueError`
- 0x04 Slave device failure: :class:`~tmodbus.exceptions.SlaveDeviceFailureError`
- 0x05 Acknowledge: :class:`~tmodbus.exceptions.AcknowledgeError`
- 0x06 Slave device busy: :class:`~tmodbus.exceptions.SlaveDeviceBusyError`
- 0x08 Memory parity error: :class:`~tmodbus.exceptions.MemoryParityError`
- 0x0A Gateway path unavailable: :class:`~tmodbus.exceptions.GatewayPathUnavailableError`
- 0x0B Gateway target device failed to respond: :class:`~tmodbus.exceptions.GatewayTargetDeviceFailedToRespondError`.

If an unknown exception code is returned, a generic :class:`~tmodbus.exceptions.ModbusResponseError` will be raised.

When the server responds with an invalid response, tModbus will raise the corresponding subclass of :class:`~tmodbus.exceptions.ModbusInvalidResponseError`:

- RTU Frame Error: :class:`~tmodbus.exceptions.RTUFrameError`
- Invalid CRC: :class:`~tmodbus.exceptions.CRCError`
- Header mismatch: :class:`~tmodbus.exceptions.HeaderMismatchError`
- Function code mismatch: :class:`~tmodbus.exceptions.FunctionCodeError`

.. automodule:: tmodbus.exceptions
    :members:
    :show-inheritance:

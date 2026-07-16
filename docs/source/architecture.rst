##############
 Architecture
##############

The architecture of the tModbus library was designed with simplicity and modularity in
mind.

The library consists of the following layers:

- **Client / Server layer**: This layer represents the two endpoints of Modbus
  communication. Users can act as a **client** using convenience interfaces to read and
  write data, or run a **server** to listen for and process incoming requests.
- **Transport layer**: This layer handles communication over underlying protocols (e.g.,
  TCP, RTU, ASCII) for both clients and servers, abstracting the stream/packet
  transmission.
- **PDU layer**: This layer is responsible for constructing, parsing, encoding, and
  decoding Modbus Protocol Data Units (PDUs), ensuring conformity to the Modbus
  specification.

*********
 Diagram
*********

.. mermaid::

    classDiagram
        class AsyncModbusClient {
           transport : AsyncModbusTransport
           unit_id : int

           +connect()
           +disconnect()
           connected: bool
           +read_~~xyz~~()
           +write_~~xyz~~()
        }

        AsyncModbusClient *-- AsyncBaseTransport
        class AsyncBaseTransport {
             +open()
             +is_open() bool
             +close()
             +send_and_receive(unit_id:int, pdu: BaseClientPDU~RT~) RT
         }

         note for BaseClientPDU "Used in AsyncBaseTransport.send_and_receive method"

         class BaseClientPDU~RT~ {
             +encode_request() bytes
             +decode_response(data: bytes) RT
         }

************************
 Overview of the layers
************************

Client or Server layer
======================

tModbus supports both roles in the Modbus communication pattern:

- **Client**: The main client class is :class:`tmodbus.AsyncModbusClient`. It provides
  convenience methods for connecting to a Modbus server (handled by the transport layer)
  and for reading and writing data (combining transport and PDU layer functionality).
- **Server**: The server implementations (:class:`~tmodbus.server.AsyncTcpServer`,
  :class:`~tmodbus.server.AsyncRtuServer`, etc.) act as the listener endpoint, receiving
  requests from clients, decoding them via the PDU layer, delegating to a custom handler
  conforming to the :class:`~tmodbus.server.ModbusHandler` protocol, and
  encoding/sending the response.

Transport layer
===============

The transport layer is implemented in the :mod:`tmodbus.transport` module. It provides
the :class:`tmodbus.transport.AsyncModbusTransport` base class, which defines the
interface for transport implementations.

The specific transport protocols are implemented in the following classes:

- :class:`tmodbus.transport.AsyncTcpTransport`: Implements Modbus over TCP.
- :class:`tmodbus.transport.AsyncRtuTransport`: Implements Modbus over RTU.
- :class:`tmodbus.transport.AsyncAsciiTransport`: Implements Modbus over ASCII.
- :class:`tmodbus.transport.AsyncRtuOverTcpTransport`: Implements Modbus RTU over TCP.

Additionally, the transport layer also features the
:class:`tmodbus.transport.AsyncSmartTransport` class, which implements intelligent
reconnect and retry logic to create a very robust transport which is capable of handling
unstable underlying connections. It must be used as a wrapper around one of the specific
transport implementations. It uses `tenacity <https://tenacity.readthedocs.io/>`_ under
the hood to provide this functionality and to make it easy for the end-user (you!) to
specify the retry- and stop-conditions.

PDU layer
=========

The PDU layer is responsible for constructing and parsing Modbus Protocol Data Units
(PDUs). It handles the encoding and decoding of Modbus messages, ensuring that they
conform to the Modbus specification.

It has been designed to be easily extensible, allowing for the support of
vendor-specific function codes and custom PDUs. If you want to add support for a custom
PDU, you can create a new class that inherits from :class:`tmodbus.pdu.BaseClientPDU`
and implements the required methods.

It is used by the :func:`tmodbus.transport.AsyncBaseTransport.send_and_receive` method
to encode the request and decode the response.

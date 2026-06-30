"""Conformance tests against the Modbus Application Protocol Specification V1.1b3.

The vectors below are the worked examples from section 6 of the specification.
They pin tmodbus to the exact bytes the specification puts on the wire, covering
three things for every function code:

- ``encode_request``: the client produces the request bytes from the example.
- ``decode_response``: the client decodes the example response to its values.
- ``get_expected_response_data_length``: the value the RTU and RTU-over-TCP
  transports use to frame a response. It must equal the length of the response
  data part (everything after the function code, before the CRC).

It also covers two cross-cutting behaviours: server-side symmetry (a request or
response survives an encode/decode round-trip unchanged) and the exception
responses defined in section 7, decoded through the RTU transport.

Where the specification example contains device specific content (Read Device
Identification, Report Server ID), a representative example in the documented
format is used instead and is marked as such.
"""

import asyncio
import struct
import time
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest
from tmodbus.const import ExceptionCode, FunctionCode
from tmodbus.exceptions import (
    AcknowledgeError,
    GatewayPathUnavailableError,
    GatewayTargetDeviceFailedToRespondError,
    IllegalDataAddressError,
    IllegalDataValueError,
    IllegalFunctionError,
    MemoryParityError,
    ModbusResponseError,
    ServerDeviceBusyError,
    ServerDeviceFailureError,
    UnknownModbusResponseError,
)
from tmodbus.pdu import (
    FileRecord,
    FileRecordRequest,
    MaskWriteRegisterPDU,
    ReadCoilsPDU,
    ReadDeviceIdentificationPDU,
    ReadDiscreteInputsPDU,
    ReadExceptionStatusPDU,
    ReadFifoQueuePDU,
    ReadFileRecordPDU,
    ReadHoldingRegistersPDU,
    ReadInputRegistersPDU,
    ReadWriteMultipleRegistersPDU,
    WriteFileRecordPDU,
    WriteMultipleCoilsPDU,
    WriteMultipleRegistersPDU,
    WriteSingleCoilPDU,
    WriteSingleRegisterPDU,
)
from tmodbus.pdu.base import BaseClientPDU, BasePDU
from tmodbus.transport.async_ascii import ModbusAsciiProtocol, build_ascii_frame
from tmodbus.transport.async_rtu import ModbusRtuProtocol
from tmodbus.transport.async_tcp import ModbusTcpProtocol
from tmodbus.utils.crc import calculate_crc16


def _hex(value: str) -> bytes:
    """Parse a spaced hex string into bytes."""
    return bytes.fromhex(value.replace(" ", ""))


def _bits(data: bytes, count: int) -> list[bool]:
    """Expand bytes to a list of coil booleans (least significant bit first)."""
    return [bool(byte & (1 << bit)) for byte in data for bit in range(8)][:count]


# --- Request encoding (client side) -----------------------------------------


def test_read_coils_request() -> None:
    """0x01 Read Coils, read 19 coils starting at address 19."""
    assert ReadCoilsPDU(0x0013, 0x0013).encode_request() == _hex("01 0013 0013")


def test_read_discrete_inputs_request() -> None:
    """0x02 Read Discrete Inputs, read 22 inputs starting at address 196."""
    assert ReadDiscreteInputsPDU(0x00C4, 0x0016).encode_request() == _hex("02 00C4 0016")


def test_read_holding_registers_request() -> None:
    """0x03 Read Holding Registers, read 3 registers starting at address 107."""
    assert ReadHoldingRegistersPDU(0x006B, 0x0003).encode_request() == _hex("03 006B 0003")


def test_read_input_registers_request() -> None:
    """0x04 Read Input Registers, read 1 register at address 8."""
    assert ReadInputRegistersPDU(0x0008, 0x0001).encode_request() == _hex("04 0008 0001")


def test_write_single_coil_request() -> None:
    """0x05 Write Single Coil, set coil 172 to ON."""
    assert WriteSingleCoilPDU(0x00AC, value=True).encode_request() == _hex("05 00AC FF00")


def test_write_single_register_request() -> None:
    """0x06 Write Single Register, write 0x0003 to register 1."""
    assert WriteSingleRegisterPDU(0x0001, 0x0003).encode_request() == _hex("06 0001 0003")


def test_write_multiple_coils_request() -> None:
    """0x0F Write Multiple Coils, write 10 coils starting at address 19."""
    coils = _bits(_hex("CD 01"), 10)
    assert WriteMultipleCoilsPDU(0x0013, coils).encode_request() == _hex("0F 0013 000A 02 CD 01")


def test_write_multiple_registers_request() -> None:
    """0x10 Write Multiple Registers, write 2 registers starting at address 1."""
    pdu = WriteMultipleRegistersPDU(0x0001, [0x000A, 0x0102])
    assert pdu.encode_request() == _hex("10 0001 0002 04 000A 0102")


def test_mask_write_register_request() -> None:
    """0x16 Mask Write Register on address 4, AND 0x00F2, OR 0x0025."""
    assert MaskWriteRegisterPDU(0x0004, 0x00F2, 0x0025).encode_request() == _hex("16 0004 00F2 0025")


def test_read_write_multiple_registers_request() -> None:
    """0x17 Read/Write Multiple Registers, read 6 from 3, write 3 to 14."""
    pdu = ReadWriteMultipleRegistersPDU(
        read_start_address=0x0003,
        read_quantity=0x0006,
        write_start_address=0x000E,
        write_values=[0x00FF, 0x00FF, 0x00FF],
    )
    assert pdu.encode_request() == _hex("17 0003 0006 000E 0003 06 00FF 00FF 00FF")


def test_read_fifo_queue_request() -> None:
    """0x18 Read FIFO Queue at pointer address 0x04DE."""
    assert ReadFifoQueuePDU(0x04DE).encode_request() == _hex("18 04DE")


def test_read_file_record_request() -> None:
    """0x14 Read File Record, two sub-requests."""
    pdu = ReadFileRecordPDU(
        [
            FileRecordRequest(file_number=0x0004, record_number=0x0001, record_length=0x0002),
            FileRecordRequest(file_number=0x0003, record_number=0x0009, record_length=0x0002),
        ]
    )
    assert pdu.encode_request() == _hex("14 0E 06 0004 0001 0002 06 0003 0009 0002")


def test_write_file_record_request() -> None:
    """0x15 Write File Record, single record of 3 registers."""
    pdu = WriteFileRecordPDU([FileRecord(file_number=0x0004, record_number=0x0007, data=_hex("06AF 04BE 100D"))])
    assert pdu.encode_request() == _hex("15 0D 06 0004 0007 0003 06AF 04BE 100D")


def test_read_exception_status_request() -> None:
    """0x07 Read Exception Status has no payload."""
    assert ReadExceptionStatusPDU().encode_request() == _hex("07")


def test_read_device_identification_request() -> None:
    """0x2B / 0x0E Read Device Identification, basic stream from object 0."""
    assert ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00).encode_request() == _hex("2B 0E 01 00")


# --- Response decoding (client side) ----------------------------------------


def test_read_coils_response() -> None:
    """0x01 response: byte count 3, status CD 6B 05 (19 coils)."""
    coils = ReadCoilsPDU(0x0013, 0x0013).decode_response(_hex("01 03 CD 6B 05"))
    assert coils == _bits(_hex("CD 6B 05"), 19)


def test_read_discrete_inputs_response() -> None:
    """0x02 response: byte count 3, status AC DB 35 (22 inputs)."""
    inputs = ReadDiscreteInputsPDU(0x00C4, 0x0016).decode_response(_hex("02 03 AC DB 35"))
    assert inputs == _bits(_hex("AC DB 35"), 22)


def test_read_holding_registers_response() -> None:
    """0x03 response: 3 registers 0x022B, 0x0000, 0x0064."""
    values = ReadHoldingRegistersPDU(0x006B, 0x0003).decode_response(_hex("03 06 022B 0000 0064"))
    assert values == [0x022B, 0x0000, 0x0064]


def test_read_input_registers_response() -> None:
    """0x04 response: 1 register 0x000A."""
    assert ReadInputRegistersPDU(0x0008, 0x0001).decode_response(_hex("04 02 000A")) == [0x000A]


def test_write_single_coil_response() -> None:
    """0x05 response echoes the request."""
    assert WriteSingleCoilPDU(0x00AC, value=True).decode_response(_hex("05 00AC FF00")) is True


def test_write_single_register_response() -> None:
    """0x06 response echoes the request, returning the written value."""
    assert WriteSingleRegisterPDU(0x0001, 0x0003).decode_response(_hex("06 0001 0003")) == 0x0003


def test_write_multiple_coils_response() -> None:
    """0x0F response: address and quantity, returning the count written."""
    coils = _bits(_hex("CD 01"), 10)
    assert WriteMultipleCoilsPDU(0x0013, coils).decode_response(_hex("0F 0013 000A")) == 10


def test_write_multiple_registers_response() -> None:
    """0x10 response: address and quantity, returning the count written."""
    pdu = WriteMultipleRegistersPDU(0x0001, [0x000A, 0x0102])
    assert pdu.decode_response(_hex("10 0001 0002")) == 2


def test_mask_write_register_response() -> None:
    """0x16 response echoes the request masks."""
    result = MaskWriteRegisterPDU(0x0004, 0x00F2, 0x0025).decode_response(_hex("16 0004 00F2 0025"))
    assert result == (0x00F2, 0x0025)


def test_read_write_multiple_registers_response() -> None:
    """0x17 response: byte count 12, 6 registers read."""
    pdu = ReadWriteMultipleRegistersPDU(
        read_start_address=0x0003,
        read_quantity=0x0006,
        write_start_address=0x000E,
        write_values=[0x00FF, 0x00FF, 0x00FF],
    )
    values = pdu.decode_response(_hex("17 0C 00FE 0ACD 0001 0003 000D 00FF"))
    assert values == [0x00FE, 0x0ACD, 0x0001, 0x0003, 0x000D, 0x00FF]


def test_read_fifo_queue_response() -> None:
    """0x18 response: byte count 6, FIFO count 2, values 0x01B8, 0x1234."""
    assert ReadFifoQueuePDU(0x04DE).decode_response(_hex("18 0006 0002 01B8 1234")) == [0x01B8, 0x1234]


def test_read_file_record_response() -> None:
    """0x14 response: two records of 2 registers each."""
    pdu = ReadFileRecordPDU(
        [
            FileRecordRequest(file_number=0x0004, record_number=0x0001, record_length=0x0002),
            FileRecordRequest(file_number=0x0003, record_number=0x0009, record_length=0x0002),
        ]
    )
    records = pdu.decode_response(_hex("14 0C 05 06 0DFE 0020 05 06 33CD 0040"))
    assert records == [_hex("0DFE 0020"), _hex("33CD 0040")]


def test_read_exception_status_response() -> None:
    """0x07 response carries a single status byte 0x6D."""
    assert ReadExceptionStatusPDU().decode_response(_hex("07 6D")) == 0x6D


def test_read_device_identification_response() -> None:
    """0x2B / 0x0E response in the format of specification section 6.21.

    The object values are device specific, so a representative basic response
    with three objects is used.
    """
    response = _hex("2B 0E 01 01 00 00 03") + b"\x00\x03ABC" + b"\x01\x02XY" + b"\x02\x031.0"
    decoded = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00).decode_response(response)
    assert decoded.number_of_objects == 3
    assert decoded.more is False
    assert decoded.objects == {0x00: b"ABC", 0x01: b"XY", 0x02: b"1.0"}


# --- RTU response framing length --------------------------------------------
#
# The transport calls get_expected_response_data_length with everything after
# the function code. It must return the length of that data part so the frame
# (unit id + function code + data + CRC) is read in full.

_DEVICE_ID_RESPONSE = _hex("2B 0E 01 01 00 00 03") + b"\x00\x03ABC" + b"\x01\x02XY" + b"\x02\x031.0"

_FRAMING_VECTORS: list[tuple[str, type[BaseClientPDU[Any]], bytes]] = [
    ("0x01 Read Coils", ReadCoilsPDU, _hex("01 03 CD 6B 05")),
    ("0x02 Read Discrete Inputs", ReadDiscreteInputsPDU, _hex("02 03 AC DB 35")),
    ("0x03 Read Holding Registers", ReadHoldingRegistersPDU, _hex("03 06 022B 0000 0064")),
    ("0x04 Read Input Registers", ReadInputRegistersPDU, _hex("04 02 000A")),
    ("0x05 Write Single Coil", WriteSingleCoilPDU, _hex("05 00AC FF00")),
    ("0x06 Write Single Register", WriteSingleRegisterPDU, _hex("06 0001 0003")),
    ("0x0F Write Multiple Coils", WriteMultipleCoilsPDU, _hex("0F 0013 000A")),
    ("0x10 Write Multiple Registers", WriteMultipleRegistersPDU, _hex("10 0001 0002")),
    ("0x16 Mask Write Register", MaskWriteRegisterPDU, _hex("16 0004 00F2 0025")),
    ("0x17 Read/Write Multiple Registers", ReadWriteMultipleRegistersPDU, _hex("17 0C 00FE 0ACD 0001 0003 000D 00FF")),
    ("0x14 Read File Record", ReadFileRecordPDU, _hex("14 0C 05 06 0DFE 0020 05 06 33CD 0040")),
    ("0x18 Read FIFO Queue", ReadFifoQueuePDU, _hex("18 0006 0002 01B8 1234")),
    ("0x2B/0x0E Read Device Identification", ReadDeviceIdentificationPDU, _DEVICE_ID_RESPONSE),
]


@pytest.mark.parametrize(
    ("pdu_class", "response_pdu"),
    [(pdu_class, response_pdu) for _label, pdu_class, response_pdu in _FRAMING_VECTORS],
    ids=[vector[0] for vector in _FRAMING_VECTORS],
)
def test_rtu_response_framing_length(pdu_class: type[BaseClientPDU[Any]], response_pdu: bytes) -> None:
    """The framing length must equal the response data part (after the function code)."""
    data_after_function_code = response_pdu[1:]
    expected = len(data_after_function_code)
    assert pdu_class.get_expected_response_data_length(data_after_function_code) == expected


# --- Server-side symmetry ----------------------------------------------------
#
# A request must survive decode_request -> encode_request unchanged, and a
# response must survive encode_response -> decode_response unchanged.

_REQUEST_ROUND_TRIPS: list[tuple[str, BasePDU[Any]]] = [
    ("0x01 Read Coils", ReadCoilsPDU(0x0013, 0x0013)),
    ("0x02 Read Discrete Inputs", ReadDiscreteInputsPDU(0x00C4, 0x0016)),
    ("0x03 Read Holding Registers", ReadHoldingRegistersPDU(0x006B, 0x0003)),
    ("0x04 Read Input Registers", ReadInputRegistersPDU(0x0008, 0x0001)),
    ("0x05 Write Single Coil", WriteSingleCoilPDU(0x00AC, value=True)),
    ("0x06 Write Single Register", WriteSingleRegisterPDU(0x0001, 0x0003)),
    ("0x0F Write Multiple Coils", WriteMultipleCoilsPDU(0x0013, _bits(_hex("CD 01"), 10))),
    ("0x10 Write Multiple Registers", WriteMultipleRegistersPDU(0x0001, [0x000A, 0x0102])),
    ("0x16 Mask Write Register", MaskWriteRegisterPDU(0x0004, 0x00F2, 0x0025)),
    ("0x18 Read FIFO Queue", ReadFifoQueuePDU(0x04DE)),
    (
        "0x14 Read File Record",
        ReadFileRecordPDU([FileRecordRequest(0x0004, 0x0001, 0x0002), FileRecordRequest(0x0003, 0x0009, 0x0002)]),
    ),
    ("0x15 Write File Record", WriteFileRecordPDU([FileRecord(0x0004, 0x0007, _hex("06AF 04BE 100D"))])),
    ("0x07 Read Exception Status", ReadExceptionStatusPDU()),
]


@pytest.mark.parametrize(
    "pdu",
    [pdu for _label, pdu in _REQUEST_ROUND_TRIPS],
    ids=[label for label, _pdu in _REQUEST_ROUND_TRIPS],
)
def test_request_round_trip(pdu: BasePDU[Any]) -> None:
    """decode_request(encode_request()) must reproduce the same request bytes."""
    encoded = pdu.encode_request()
    assert type(pdu).decode_request(encoded).encode_request() == encoded


_RESPONSE_ROUND_TRIPS: list[tuple[str, BasePDU[Any], Any]] = [
    ("0x01 Read Coils", ReadCoilsPDU(0x0013, 0x0013), _bits(_hex("CD 6B 05"), 19)),
    ("0x03 Read Holding Registers", ReadHoldingRegistersPDU(0x006B, 0x0003), [0x022B, 0x0000, 0x0064]),
    ("0x04 Read Input Registers", ReadInputRegistersPDU(0x0008, 0x0001), [0x000A]),
    ("0x05 Write Single Coil", WriteSingleCoilPDU(0x00AC, value=True), True),
    ("0x06 Write Single Register", WriteSingleRegisterPDU(0x0001, 0x0003), 0x0003),
    ("0x0F Write Multiple Coils", WriteMultipleCoilsPDU(0x0013, _bits(_hex("CD 01"), 10)), 10),
    ("0x10 Write Multiple Registers", WriteMultipleRegistersPDU(0x0001, [0x000A, 0x0102]), 2),
    ("0x16 Mask Write Register", MaskWriteRegisterPDU(0x0004, 0x00F2, 0x0025), (0x00F2, 0x0025)),
    (
        "0x17 Read/Write Multiple Registers",
        ReadWriteMultipleRegistersPDU(
            read_start_address=0x0003, read_quantity=0x0006, write_start_address=0x000E, write_values=[0xFF, 0xFF, 0xFF]
        ),
        [0x00FE, 0x0ACD, 0x0001, 0x0003, 0x000D, 0x00FF],
    ),
    ("0x18 Read FIFO Queue", ReadFifoQueuePDU(0x04DE), [0x01B8, 0x1234]),
    ("0x07 Read Exception Status", ReadExceptionStatusPDU(), 0x6D),
]


@pytest.mark.parametrize(
    ("pdu", "value"),
    [(pdu, value) for _label, pdu, value in _RESPONSE_ROUND_TRIPS],
    ids=[label for label, _pdu, _value in _RESPONSE_ROUND_TRIPS],
)
def test_response_round_trip(pdu: BasePDU[Any], value: Any) -> None:
    """decode_response(encode_response(value)) must reproduce the same value."""
    assert pdu.decode_response(pdu.encode_response(value)) == value


# --- Exception responses (specification section 7) ---------------------------
#
# An exception response sets the high bit of the function code and carries a
# single exception code byte. The transport must raise the matching exception
# and recover the original function code.

_EXCEPTION_CODES: list[tuple[int, type[ModbusResponseError]]] = [
    (ExceptionCode.ILLEGAL_FUNCTION, IllegalFunctionError),
    (ExceptionCode.ILLEGAL_DATA_ADDRESS, IllegalDataAddressError),
    (ExceptionCode.ILLEGAL_DATA_VALUE, IllegalDataValueError),
    (ExceptionCode.SERVER_DEVICE_FAILURE, ServerDeviceFailureError),
    (ExceptionCode.ACKNOWLEDGE, AcknowledgeError),
    (ExceptionCode.SERVER_DEVICE_BUSY, ServerDeviceBusyError),
    (ExceptionCode.MEMORY_PARITY_ERROR, MemoryParityError),
    (ExceptionCode.GATEWAY_PATH_UNAVAILABLE, GatewayPathUnavailableError),
    (ExceptionCode.GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND, GatewayTargetDeviceFailedToRespondError),
]


def test_exception_code_mapping_matches_specification() -> None:
    """Every documented exception code maps to its exception class."""
    from tmodbus.exceptions import error_code_to_exception_map  # noqa: PLC0415

    for code, exc_class in _EXCEPTION_CODES:
        assert error_code_to_exception_map[code] is exc_class
        assert exc_class.error_code == code


def _mock_write_transport() -> MagicMock:
    """Create a mock asyncio write transport that reports an open connection."""
    transport = MagicMock(spec=asyncio.WriteTransport)
    transport.is_closing.return_value = False
    return transport


# A transport driver returns a connected protocol and a function that frames a
# response PDU (the bytes after the unit id) into a complete ADU for that
# transport. The exception detection logic is duplicated across the three
# transports, so these run the same vectors through each to keep them in step.

ProtocolFramer = tuple[Any, Callable[[int, bytes], bytes]]


def _rtu_driver() -> ProtocolFramer:
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(_mock_write_transport())
    protocol._last_frame_ended_at = time.monotonic() - 10

    def frame(unit_id: int, response_pdu: bytes) -> bytes:
        payload = bytes([unit_id]) + response_pdu
        return payload + calculate_crc16(payload)

    return protocol, frame


def _ascii_driver() -> ProtocolFramer:
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(_mock_write_transport())
    return protocol, build_ascii_frame


def _tcp_driver() -> ProtocolFramer:
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(_mock_write_transport())

    def frame(unit_id: int, response_pdu: bytes) -> bytes:
        # The first request on a fresh protocol uses transaction id 1.
        return struct.pack(">HHHB", 1, 0x0000, len(response_pdu) + 1, unit_id) + response_pdu

    return protocol, frame


_TRANSPORT_DRIVERS: dict[str, Callable[[], ProtocolFramer]] = {
    "rtu": _rtu_driver,
    "ascii": _ascii_driver,
    "tcp": _tcp_driver,
}


async def _send_and_capture_response_pdu(transport: str, response_pdu: bytes) -> Any:
    """Run one request through a transport and deliver the given response PDU.

    Returns the coroutine result, or raises whatever the transport raises.
    """
    protocol, frame = _TRANSPORT_DRIVERS[transport]()
    pdu = ReadHoldingRegistersPDU(0x0000, 0x0001)
    unit_id = 1
    response_adu = frame(unit_id, response_pdu)

    async def deliver() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(response_adu)

    deliver_task = asyncio.create_task(deliver())
    try:
        return await protocol.send_and_receive(unit_id, pdu)
    finally:
        await deliver_task


@pytest.mark.parametrize("transport", list(_TRANSPORT_DRIVERS))
@pytest.mark.parametrize(
    ("exception_code", "exception_class"),
    _EXCEPTION_CODES,
    ids=[exc_class.__name__ for _code, exc_class in _EXCEPTION_CODES],
)
async def test_exception_response(
    transport: str,
    exception_code: int,
    exception_class: type[ModbusResponseError],
) -> None:
    """Each transport raises the mapped exception and recovers the function code."""
    response_pdu = bytes([FunctionCode.READ_HOLDING_REGISTERS | 0x80, exception_code])
    with pytest.raises(exception_class) as exc_info:
        await _send_and_capture_response_pdu(transport, response_pdu)

    assert exc_info.value.function_code == FunctionCode.READ_HOLDING_REGISTERS
    assert exc_info.value.error_code == exception_code


@pytest.mark.parametrize("transport", list(_TRANSPORT_DRIVERS))
async def test_unknown_exception_code(transport: str) -> None:
    """An unmapped exception code raises UnknownModbusResponseError, keeping the code."""
    unknown_code = 0x7F
    response_pdu = bytes([FunctionCode.READ_HOLDING_REGISTERS | 0x80, unknown_code])
    with pytest.raises(UnknownModbusResponseError) as exc_info:
        await _send_and_capture_response_pdu(transport, response_pdu)

    assert exc_info.value.error_code == unknown_code
    assert exc_info.value.function_code == FunctionCode.READ_HOLDING_REGISTERS

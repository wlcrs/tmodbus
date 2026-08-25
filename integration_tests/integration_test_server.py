"""Shared server implementation and device simulation for integration tests."""

from typing import Any

from tmodbus.pdu import (
    BaseDiagnosticsSubFunctionPDU,
    CommEventCounterResponse,
    CommEventLogResponse,
    DiagnosticsBusCharacterOverrunCountPDU,
    DiagnosticsBusCommunicationErrorCountPDU,
    DiagnosticsBusExceptionErrorCountPDU,
    DiagnosticsBusMessageCountPDU,
    DiagnosticsChangeAsciiInputDelimiterPDU,
    DiagnosticsClearCountersAndRegisterPDU,
    DiagnosticsClearOverrunCounterAndFlagPDU,
    DiagnosticsDiagnosticRegisterPDU,
    DiagnosticsQueryDataPDU,
    DiagnosticsRestartCommunicationsOptionPDU,
    DiagnosticsServerBusyCountPDU,
    DiagnosticsServerMessageCountPDU,
    DiagnosticsServerNakCountPDU,
    DiagnosticsServerNoResponseCountPDU,
    FileRecord,
    GetCommEventCounterPDU,
    GetCommEventLogPDU,
    MaskWriteRegisterPDU,
    ReadCoilsPDU,
    ReadDeviceIdentificationPDU,
    ReadDeviceIdentificationResponse,
    ReadDiscreteInputsPDU,
    ReadExceptionStatusPDU,
    ReadFifoQueuePDU,
    ReadFileRecordPDU,
    ReadHoldingRegistersPDU,
    ReadInputRegistersPDU,
    ReadWriteMultipleRegistersPDU,
    ReportServerIdPDU,
    ServerIdResponse,
    WriteFileRecordPDU,
    WriteMultipleCoilsPDU,
    WriteMultipleRegistersPDU,
    WriteSingleCoilPDU,
    WriteSingleRegisterPDU,
)
from tmodbus.pdu.device import ConformityLevel, ObjectName
from tmodbus.server import ModbusRequestRouter


class ModbusDevice:
    """In-memory database simulation of a Modbus device.

    Contains 100 registers/coils of each type with the following defaults/expectations:
    - coils: initialized to False.
    - discrete_inputs: [0]=True, [1]=False, [2]=True, [3]=False.
    - holding_registers: initialized to 0.
    - input_registers: [0]=1234, [1]=5678.
    """

    def __init__(self) -> None:
        """Initialize ModbusDevice."""
        self.coils = [False] * 100

        self.discrete_inputs = [False] * 100
        self.discrete_inputs[0] = True
        self.discrete_inputs[1] = False
        self.discrete_inputs[2] = True
        self.discrete_inputs[3] = False

        self.holding_registers = [0] * 100

        self.input_registers = [0] * 100
        self.input_registers[0] = 1234
        self.input_registers[1] = 5678

        # Exception Status (FC 0x07)
        self.exception_status = 0x55

        # Comm Events (FC 0x0B, FC 0x0C)
        self.comm_status = 0x0000
        self.comm_event_count = 42
        self.comm_message_count = 100
        self.comm_events = b"\x01\x02\x03\x04"

        # Server ID (FC 0x11)
        self.server_id = b"TMB-DEV"
        self.run_indicator_status = True
        self.additional_data = b"V1.0"

        # File Records (FC 0x14, FC 0x15)
        # Map: file_number -> {record_number: bytes}
        self.files: dict[int, dict[int, bytes]] = {
            4: {
                0: b"\x12\x34\x56\x78",
                1: b"\xaa\xbb\xcc\xdd",
            }
        }

        # FIFO Queue (FC 0x18)
        self.fifo_queues: dict[int, list[int]] = {
            0: [100, 200, 300, 400],
        }

        # Diagnostics (FC 0x08)
        self.diagnostic_register = 0x1234
        self.ascii_input_delimiter = 0x0A
        self.bus_message_count = 10
        self.bus_comm_error_count = 0
        self.bus_exception_error_count = 0
        self.server_message_count = 10
        self.server_no_response_count = 0
        self.server_nak_count = 0
        self.server_busy_count = 0
        self.bus_character_overrun_count = 0


def setup_router(device: ModbusDevice) -> ModbusRequestRouter:  # noqa: C901, PLR0915
    """Register all PDU handlers on a ModbusRequestRouter.

    To verify integration compatibility, a client should perform the following:

    1. Coils (FC 0x01, 0x05, 0x0F)
       - Write single coil at address 0 to True, read it back (FC 0x01), and assert it is True.
       - Write multiple coils starting at address 5 with [True, False, True, True],
         read them back (FC 0x01, qty 4), and assert the values match.

    2. Discrete Inputs (FC 0x02)
       - Read 4 discrete inputs starting at address 0.
       - Assert that the returned array is [True, False, True, False].

    3. Holding Registers (FC 0x03, 0x06, 0x10, 0x16, 0x17)
       - Write single register at address 10 to 42, read it back (FC 0x03), and assert it is 42.
       - Write multiple registers starting at address 20 with [100, 200, 300],
         read them back (FC 0x03, qty 3), and assert the values match.
       - Mask Write Register (FC 0x16): (For clients supporting it)
         - Write 0x1234 to holding register 30.
         - Call Mask Write Register at address 30 with AND mask 0x00FF and OR mask 0x5600.
         - Read register 30 and assert the value is 0x5634.
       - Read/Write Multiple Registers (FC 0x17): (For clients supporting it)
         - Call Read/Write at read address 40 (qty 2) and write address 40 with [88, 99].
         - Assert returned values are [88, 99].

    4. Input Registers (FC 0x04)
       - Read 2 input registers starting at address 0.
       - Assert that the returned array is [1234, 5678].

    5. Exception Status (FC 0x07)
       - Read exception status byte.

    6. Comm Events (FC 0x0B, FC 0x0C)
       - Read comm event counter and comm event log.

    7. Server ID (FC 0x11)
       - Report Server ID response.

    8. File Records (FC 0x14, FC 0x15)
       - Read and write file records.

    9. FIFO Queue (FC 0x18)
       - Read FIFO queue registers.

    10. Diagnostics (FC 0x08)
        - Diagnostics loopback query data and counters.
    """
    router = ModbusRequestRouter()

    @router.register(ReadCoilsPDU)
    async def handle_read_coils(_unit_id: int, request: ReadCoilsPDU) -> list[bool]:
        return device.coils[request.start_address : request.start_address + request.quantity]

    @router.register(ReadDiscreteInputsPDU)
    async def handle_read_discrete_inputs(_unit_id: int, request: ReadDiscreteInputsPDU) -> list[bool]:
        return device.discrete_inputs[request.start_address : request.start_address + request.quantity]

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read_holding_registers(_unit_id: int, request: ReadHoldingRegistersPDU) -> list[int]:
        return device.holding_registers[request.start_address : request.start_address + request.quantity]

    @router.register(ReadInputRegistersPDU)
    async def handle_read_input_registers(_unit_id: int, request: ReadInputRegistersPDU) -> list[int]:
        return device.input_registers[request.start_address : request.start_address + request.quantity]

    @router.register(WriteSingleCoilPDU)
    async def handle_write_single_coil(_unit_id: int, request: WriteSingleCoilPDU) -> bool:
        device.coils[request.address] = request.value
        return request.value

    @router.register(WriteSingleRegisterPDU)
    async def handle_write_single_register(_unit_id: int, request: WriteSingleRegisterPDU) -> int:
        device.holding_registers[request.address] = request.value
        return request.value

    @router.register(WriteMultipleCoilsPDU)
    async def handle_write_multiple_coils(_unit_id: int, request: WriteMultipleCoilsPDU) -> int:
        start = request.start_address
        for i, val in enumerate(request.values):
            device.coils[start + i] = val
        return len(request.values)

    @router.register(WriteMultipleRegistersPDU)
    async def handle_write_multiple_registers(_unit_id: int, request: WriteMultipleRegistersPDU) -> int:
        start = request.start_address
        for i, val in enumerate(request.values):
            device.holding_registers[start + i] = val
        return len(request.values)

    @router.register(MaskWriteRegisterPDU)
    async def handle_mask_write_register(_unit_id: int, request: MaskWriteRegisterPDU) -> tuple[int, int]:
        addr = request.address
        curr = device.holding_registers[addr]
        new_val = (curr & request.and_mask) | (request.or_mask & ~request.and_mask)
        device.holding_registers[addr] = new_val & 0xFFFF
        return request.and_mask, request.or_mask

    @router.register(ReadWriteMultipleRegistersPDU)
    async def handle_read_write_multiple_registers(_unit_id: int, request: ReadWriteMultipleRegistersPDU) -> list[int]:
        # Write first
        write_start = request.write_start_address
        for i, val in enumerate(request.write_values):
            device.holding_registers[write_start + i] = val
        # Then read
        read_start = request.read_start_address
        return device.holding_registers[read_start : read_start + request.read_quantity]

    @router.register(ReadExceptionStatusPDU)
    async def handle_read_exception_status(_unit_id: int, _request: ReadExceptionStatusPDU) -> int:
        return device.exception_status

    @router.register(GetCommEventCounterPDU)
    async def handle_get_comm_event_counter(
        _unit_id: int, _request: GetCommEventCounterPDU
    ) -> CommEventCounterResponse:
        return CommEventCounterResponse(status=device.comm_status, event_count=device.comm_event_count)

    @router.register(GetCommEventLogPDU)
    async def handle_get_comm_event_log(_unit_id: int, _request: GetCommEventLogPDU) -> CommEventLogResponse:
        return CommEventLogResponse(
            status=device.comm_status,
            event_count=device.comm_event_count,
            message_count=device.comm_message_count,
            events=device.comm_events,
        )

    @router.register(ReportServerIdPDU)
    async def handle_report_server_id(_unit_id: int, _request: ReportServerIdPDU) -> ServerIdResponse:
        return ServerIdResponse(
            server_id=device.server_id,
            run_indicator_status=device.run_indicator_status,
            additional_data=device.additional_data,
        )

    @router.register(ReadFileRecordPDU)
    async def handle_read_file_record(_unit_id: int, request: ReadFileRecordPDU) -> list[bytes]:
        results: list[bytes] = []
        for req in request.requests:
            file_data = device.files.get(req.file_number, {})
            record_data = file_data.get(req.record_number, b"\x00" * (req.record_length * 2))
            results.append(record_data[: req.record_length * 2])
        return results

    @router.register(WriteFileRecordPDU)
    async def handle_write_file_record(_unit_id: int, request: WriteFileRecordPDU) -> list[FileRecord]:
        echo_records: list[FileRecord] = []
        for rec in request.file_records:
            if rec.file_number not in device.files:
                device.files[rec.file_number] = {}
            device.files[rec.file_number][rec.record_number] = rec.data
            echo_records.append(rec)
        return echo_records

    @router.register(ReadFifoQueuePDU)
    async def handle_read_fifo_queue(_unit_id: int, request: ReadFifoQueuePDU) -> list[int]:
        return device.fifo_queues.get(request.address, [])

    @router.register(DiagnosticsQueryDataPDU)
    async def handle_diagnostics(  # noqa: C901, PLR0911, PLR0912
        _unit_id: int, request: BaseDiagnosticsSubFunctionPDU[Any]
    ) -> Any:
        if isinstance(request, DiagnosticsQueryDataPDU):
            return request.data
        if isinstance(request, DiagnosticsRestartCommunicationsOptionPDU):
            if request.clear_event_log:
                device.comm_events = b""
                device.comm_event_count = 0
            return request.clear_event_log
        if isinstance(request, DiagnosticsDiagnosticRegisterPDU):
            return device.diagnostic_register
        if isinstance(request, DiagnosticsChangeAsciiInputDelimiterPDU):
            device.ascii_input_delimiter = request.delimiter
            return request.delimiter
        if isinstance(request, DiagnosticsClearCountersAndRegisterPDU):
            device.diagnostic_register = 0
            device.bus_message_count = 0
            device.bus_comm_error_count = 0
            device.bus_exception_error_count = 0
            device.server_message_count = 0
            device.server_no_response_count = 0
            device.server_nak_count = 0
            device.server_busy_count = 0
            device.bus_character_overrun_count = 0
            return None
        if isinstance(request, DiagnosticsBusMessageCountPDU):
            return device.bus_message_count
        if isinstance(request, DiagnosticsBusCommunicationErrorCountPDU):
            return device.bus_comm_error_count
        if isinstance(request, DiagnosticsBusExceptionErrorCountPDU):
            return device.bus_exception_error_count
        if isinstance(request, DiagnosticsServerMessageCountPDU):
            return device.server_message_count
        if isinstance(request, DiagnosticsServerNoResponseCountPDU):
            return device.server_no_response_count
        if isinstance(request, DiagnosticsServerNakCountPDU):
            return device.server_nak_count
        if isinstance(request, DiagnosticsServerBusyCountPDU):
            return device.server_busy_count
        if isinstance(request, DiagnosticsBusCharacterOverrunCountPDU):
            return device.bus_character_overrun_count
        if isinstance(request, DiagnosticsClearOverrunCounterAndFlagPDU):
            device.bus_character_overrun_count = 0
            return None
        return None

    @router.register(ReadDeviceIdentificationPDU)
    async def handle_read_device_identification(
        _unit_id: int, request: ReadDeviceIdentificationPDU
    ) -> ReadDeviceIdentificationResponse:
        all_objects = {
            ObjectName.VENDOR_NAME: b"wlcrs",
            ObjectName.PRODUCT_CODE: b"TMB",
            ObjectName.MAJOR_MINOR_REVISION: b"1.0",
        }
        filtered = {k: v for k, v in all_objects.items() if k >= request.object_id}
        return ReadDeviceIdentificationResponse(
            device_id_code=request.read_device_id_code,
            conformity_level=ConformityLevel.BASIC,
            more=False,
            next_object_id=0,
            number_of_objects=len(filtered),
            objects=filtered,
        )

    return router

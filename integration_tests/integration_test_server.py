"""Shared server implementation and device simulation for integration tests."""

from tmodbus.pdu import (
    MaskWriteRegisterPDU,
    ReadCoilsPDU,
    ReadDeviceIdentificationPDU,
    ReadDeviceIdentificationResponse,
    ReadDiscreteInputsPDU,
    ReadHoldingRegistersPDU,
    ReadInputRegistersPDU,
    ReadWriteMultipleRegistersPDU,
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


def setup_router(device: ModbusDevice) -> ModbusRequestRouter:  # noqa: C901
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
        start = request.address
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

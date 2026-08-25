"""End-to-end integration tests covering all PDUs, transports, and features in tmodbus."""

from __future__ import annotations

import datetime
import ipaddress
import ssl
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from tmodbus.client import AsyncModbusClient
from tmodbus.pdu import FileRecord, FileRecordRequest
from tmodbus.server import (
    AsyncAsciiServer,
    AsyncRtuOverTcpServer,
    AsyncRtuServer,
    AsyncTcpServer,
    AsyncUdpServer,
)
from tmodbus.server.security import MODBUS_ROLE_OID
from tmodbus.transport import (
    AsyncAsciiTransport,
    AsyncRtuOverTcpTransport,
    AsyncRtuTransport,
    AsyncSmartTransport,
    AsyncTcpTransport,
    AsyncUdpTransport,
)

from helpers import get_server_port, make_virtual_serial_ports
from integration_test_server import ModbusDevice, setup_router

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture
def virtual_serial_ports() -> Generator[tuple[Path, Path], None, None]:
    """Create a pair of virtual serial ports for RTU/ASCII integration testing."""
    server_socket_path = Path(__file__).parent / "e2e-server-socket"
    client_socket_path = Path(__file__).parent / "e2e-client-socket"
    with make_virtual_serial_ports(server_socket_path, client_socket_path) as ports:
        yield ports


async def run_full_pdu_test_suite(client: AsyncModbusClient) -> None:  # noqa: PLR0915
    """Execute assertions for every PDU and feature supported by tmodbus."""
    # 1. Coils (FC 0x01, FC 0x05, FC 0x0F)
    await client.write_single_coil(0, value=True)
    assert await client.read_coils(0, 1) == [True]
    await client.write_single_coil(0, value=False)
    assert await client.read_coils(0, 1) == [False]

    await client.write_multiple_coils(5, [True, False, True, True, False])
    assert await client.read_coils(5, 5) == [True, False, True, True, False]

    # 2. Discrete Inputs (FC 0x02)
    assert await client.read_discrete_inputs(0, 4) == [True, False, True, False]

    # 3. Holding Registers (FC 0x03, FC 0x06, FC 0x10)
    await client.write_single_register(10, 42)
    assert await client.read_holding_registers(10, 1) == [42]

    await client.write_multiple_registers(20, [100, 200, 300, 400])
    assert await client.read_holding_registers(20, 4) == [100, 200, 300, 400]

    # 4. Mask Write Register (FC 0x16)
    await client.write_single_register(30, 0x1234)
    and_mask, or_mask = await client.mask_write_register(30, and_mask=0x00FF, or_mask=0x5600)
    assert (and_mask, or_mask) == (0x00FF, 0x5600)
    assert await client.read_holding_registers(30, 1) == [0x5634]

    # 5. Read/Write Multiple Registers (FC 0x17)
    res = await client.read_write_multiple_registers(
        read_start_address=40,
        read_quantity=2,
        write_start_address=40,
        write_values=[888, 999],
    )
    assert res == [888, 999]
    assert await client.read_holding_registers(40, 2) == [888, 999]

    # 6. Input Registers (FC 0x04)
    assert await client.read_input_registers(0, 2) == [1234, 5678]

    # 7. Read Exception Status (FC 0x07)
    assert await client.read_exception_status() == 0x55

    # 8. Comm Events (FC 0x0B, FC 0x0C)
    counter_resp = await client.get_comm_event_counter()
    assert counter_resp.event_count == 42
    assert counter_resp.status == 0x0000

    log_resp = await client.get_comm_event_log()
    assert log_resp.event_count == 42
    assert log_resp.message_count == 100
    assert log_resp.events == b"\x01\x02\x03\x04"

    # 9. Server ID (FC 0x11)
    srv_id = await client.read_server_id()
    assert srv_id.server_id == b"TMB-DEV"
    assert srv_id.run_indicator_status is True
    assert srv_id.additional_data == b"V1.0"

    # 10. File Records (FC 0x14, FC 0x15)
    # Read file records
    read_recs = await client.read_file_records(
        [
            FileRecordRequest(file_number=4, record_number=0, record_length=2),
            FileRecordRequest(file_number=4, record_number=1, record_length=2),
        ]
    )
    assert read_recs == [b"\x12\x34\x56\x78", b"\xaa\xbb\xcc\xdd"]

    read_single = await client.read_file_record(file_number=4, record_number=0, record_length=2)
    assert read_single == b"\x12\x34\x56\x78"

    # Write file records
    written = await client.write_file_records(
        [
            FileRecord(file_number=4, record_number=2, data=b"\x11\x22\x33\x44"),
        ]
    )
    assert written == [FileRecord(file_number=4, record_number=2, data=b"\x11\x22\x33\x44")]
    assert await client.read_file_record(file_number=4, record_number=2, record_length=2) == b"\x11\x22\x33\x44"

    written_single = await client.write_file_record(file_number=4, record_number=3, data=b"\x55\x66\x77\x88")
    assert written_single == FileRecord(file_number=4, record_number=3, data=b"\x55\x66\x77\x88")
    assert await client.read_file_record(file_number=4, record_number=3, record_length=2) == b"\x55\x66\x77\x88"

    # 11. Read FIFO Queue (FC 0x18)
    fifo = await client.read_fifo_queue(0)
    assert fifo == [100, 200, 300, 400]

    # 12. Read Device Identification (FC 0x2B/0x0E)
    dev_id = await client.read_device_identification(1, 0)
    assert dev_id[0] == b"wlcrs"
    assert dev_id[1] == b"TMB"
    assert dev_id[2] == b"1.0"

    # 13. Diagnostics Subfunctions (FC 0x08)
    assert await client.diag_read_query_data(b"\xaa\x55") == b"\xaa\x55"
    assert await client.diag_read_diagnostic_register() == 0x1234
    assert await client.diag_read_bus_message_count() == 10
    assert await client.diag_read_bus_communication_error_count() == 0
    assert await client.diag_read_bus_exception_error_count() == 0
    assert await client.diag_read_server_message_count() == 10
    assert await client.diag_read_server_no_response_count() == 0
    assert await client.diag_read_server_nak_count() == 0
    assert await client.diag_read_server_busy_count() == 0
    assert await client.diag_read_bus_character_overrun_count() == 0

    assert await client.diag_restart_communications_option(clear_event_log=True) is True
    assert (await client.get_comm_event_counter()).event_count == 0

    assert await client.diag_change_ascii_input_delimiter(0x0D) == 0x0D

    await client.diag_clear_counters_and_register()
    assert await client.diag_read_diagnostic_register() == 0
    assert await client.diag_read_bus_message_count() == 0

    await client.diag_clear_overrun_counter_and_flag()
    assert await client.diag_read_bus_character_overrun_count() == 0

    # 14. Struct / Typed Register Helpers
    await client.write_int16(50, -32000)
    assert await client.read_int16(50) == -32000

    await client.write_uint16(51, 65500)
    assert await client.read_uint16(51) == 65500

    await client.write_int32(52, -2000000000)
    assert await client.read_int32(52) == -2000000000

    await client.write_uint32(54, 4000000000)
    assert await client.read_uint32(54) == 4000000000

    await client.write_int64(56, -9000000000000000000)
    assert await client.read_int64(56) == -9000000000000000000

    await client.write_uint64(60, 18000000000000000000)
    assert await client.read_uint64(60) == 18000000000000000000

    await client.write_float(64, -123.456)
    assert pytest.approx(await client.read_float(64), rel=1e-5) == -123.456

    await client.write_double(66, 123456789.987654321)
    assert pytest.approx(await client.read_double(66), rel=1e-9) == 123456789.987654321

    await client.write_string(70, "TMODBUS-TEST", number_of_registers=6)
    assert (await client.read_string(70, number_of_registers=6)).rstrip("\x00") == "TMODBUS-TEST"

    # 15. Endianness Variants
    client_be_le = AsyncModbusClient(
        client.transport,
        unit_id=client.unit_id,
        word_order="big",
        byte_order="little",
    )
    await client_be_le.write_uint32(80, 0x12345678)
    assert await client_be_le.read_uint32(80) == 0x12345678
    raw_regs = await client.read_holding_registers(80, 2)
    assert raw_regs == [0x3412, 0x7856]

    client_le_be = AsyncModbusClient(
        client.transport,
        unit_id=client.unit_id,
        word_order="little",
        byte_order="big",
    )
    await client_le_be.write_uint32(82, 0x12345678)
    assert await client_le_be.read_uint32(82) == 0x12345678
    raw_regs = await client.read_holding_registers(82, 2)
    assert raw_regs == [0x5678, 0x1234]

    client_le_le = AsyncModbusClient(
        client.transport,
        unit_id=client.unit_id,
        word_order="little",
        byte_order="little",
    )
    await client_le_le.write_uint32(84, 0x12345678)
    assert await client_le_le.read_uint32(84) == 0x12345678
    raw_regs = await client.read_holding_registers(84, 2)
    assert raw_regs == [0x7856, 0x3412]

    # 16. Unit ID switching via for_unit_id
    client_u2 = client.for_unit_id(2)
    assert client_u2.unit_id == 2
    assert await client_u2.read_holding_registers(10, 1) == [42]


@pytest.mark.asyncio
async def test_tcp_server_and_client_e2e() -> None:
    """Test AsyncTcpServer with AsyncTcpTransport."""
    device = ModbusDevice()
    router = setup_router(device)
    server = AsyncTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    port = get_server_port(server)

    transport = AsyncTcpTransport("127.0.0.1", port)
    client = AsyncModbusClient(transport=transport, unit_id=1)

    async with client:
        await run_full_pdu_test_suite(client)

    await server.stop()


@pytest.mark.asyncio
async def test_udp_server_and_client_e2e() -> None:
    """Test AsyncUdpServer with AsyncUdpTransport."""
    device = ModbusDevice()
    router = setup_router(device)
    server = AsyncUdpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    port = get_server_port(server)

    transport = AsyncUdpTransport("127.0.0.1", port)
    client = AsyncModbusClient(transport=transport, unit_id=1)

    async with client:
        await run_full_pdu_test_suite(client)

    await server.stop()


@pytest.mark.asyncio
async def test_rtu_over_tcp_server_and_client_e2e() -> None:
    """Test AsyncRtuOverTcpServer with AsyncRtuOverTcpTransport."""
    device = ModbusDevice()
    router = setup_router(device)
    server = AsyncRtuOverTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    port = get_server_port(server)

    transport = AsyncRtuOverTcpTransport("127.0.0.1", port)
    client = AsyncModbusClient(transport=transport, unit_id=1)

    async with client:
        await run_full_pdu_test_suite(client)

    await server.stop()


@pytest.mark.asyncio
async def test_rtu_serial_server_and_client_e2e(virtual_serial_ports: tuple[Path, Path]) -> None:
    """Test AsyncRtuServer with AsyncRtuTransport over virtual serial link."""
    server_port, client_port = virtual_serial_ports
    device = ModbusDevice()
    router = setup_router(device)

    server = AsyncRtuServer(port=str(server_port), handler=router, baudrate=19200)
    await server.start()

    transport = AsyncRtuTransport(str(client_port), baudrate=19200, timeout=3.0)
    client = AsyncModbusClient(transport=transport, unit_id=1)

    async with client:
        await run_full_pdu_test_suite(client)

    await server.stop()


@pytest.mark.asyncio
async def test_ascii_serial_server_and_client_e2e(virtual_serial_ports: tuple[Path, Path]) -> None:
    """Test AsyncAsciiServer with AsyncAsciiTransport over virtual serial link."""
    server_port, client_port = virtual_serial_ports
    device = ModbusDevice()
    router = setup_router(device)

    server = AsyncAsciiServer(port=str(server_port), handler=router, baudrate=19200)
    await server.start()

    transport = AsyncAsciiTransport(str(client_port), baudrate=19200, timeout=3.0)
    client = AsyncModbusClient(transport=transport, unit_id=1)

    async with client:
        await run_full_pdu_test_suite(client)

    await server.stop()


@pytest.mark.asyncio
async def test_smart_transport_e2e() -> None:
    """Test AsyncSmartTransport wrapping AsyncTcpTransport."""
    device = ModbusDevice()
    router = setup_router(device)
    server = AsyncTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    port = get_server_port(server)

    base_transport = AsyncTcpTransport("127.0.0.1", port)
    smart_transport = AsyncSmartTransport(
        base_transport,
        wait_between_requests=0.001,
        auto_reconnect=True,
    )
    client = AsyncModbusClient(transport=smart_transport, unit_id=1)

    async with client:
        await run_full_pdu_test_suite(client)

    await server.stop()


@pytest.mark.asyncio
async def test_tls_server_and_client_with_role_auth_e2e(tmp_path: Path) -> None:
    """Test AsyncTcpServer with TLS, mutual authentication, and RequestContext client_role."""
    now = datetime.datetime.now(datetime.UTC)
    validity = datetime.timedelta(days=365)
    modbus_oid = x509.ObjectIdentifier(MODBUS_ROLE_OID)

    # Generate CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + validity)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # Generate Server Cert
    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_cert.subject)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + validity)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Generate Client Cert with "operator" Role
    cli_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    role_bytes = b"operator"
    asn1_role = bytes([0x0C, len(role_bytes)]) + role_bytes
    cli_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Client")]))
        .issuer_name(ca_cert.subject)
        .public_key(cli_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + validity)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(cli_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.UnrecognizedExtension(modbus_oid, asn1_role), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # Write PEM files
    ca_pem = tmp_path / "ca.crt"
    ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    srv_pem = tmp_path / "srv.crt"
    srv_pem.write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))
    srv_key_pem = tmp_path / "srv.key"
    srv_key_pem.write_bytes(
        srv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    cli_pem = tmp_path / "cli.crt"
    cli_pem.write_bytes(cli_cert.public_bytes(serialization.Encoding.PEM))
    cli_key_pem = tmp_path / "cli.key"
    cli_key_pem.write_bytes(
        cli_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    # Setup SSL Contexts
    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl.load_cert_chain(srv_pem, srv_key_pem)
    server_ssl.load_verify_locations(cafile=ca_pem)
    server_ssl.verify_mode = ssl.CERT_REQUIRED

    client_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ssl.check_hostname = False
    client_ssl.verify_mode = ssl.CERT_REQUIRED
    client_ssl.load_cert_chain(cli_pem, cli_key_pem)
    client_ssl.load_verify_locations(cafile=ca_pem)

    device = ModbusDevice()
    router = setup_router(device)
    server = AsyncTcpServer(host="127.0.0.1", port=0, handler=router, ssl_context=server_ssl)
    await server.start()
    port = get_server_port(server)

    transport = AsyncTcpTransport("127.0.0.1", port, ssl=client_ssl, server_hostname="localhost")
    client = AsyncModbusClient(transport=transport, unit_id=1)

    async with client:
        await run_full_pdu_test_suite(client)

    await server.stop()

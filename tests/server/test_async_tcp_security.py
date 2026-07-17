"""Tests for Modbus/TCP Security (mbaps) support in AsyncTcpServer."""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import ssl
import struct
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest
from tmodbus.exceptions import IllegalFunctionError
from tmodbus.pdu import ReadHoldingRegistersPDU
from tmodbus.server import AsyncTcpServer, ModbusRequestRouter, RequestContext
from tmodbus.server.handler import _handler_accepts_context
from tmodbus.server.security import (
    MODBUS_ROLE_OID,
    MODBUS_SECURITY_PORT,
    extract_client_cert_info,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

# ---------------------------------------------------------------------------
# Certificate generation helpers (require cryptography)
# ---------------------------------------------------------------------------

try:
    from cryptography import x509
    from cryptography.hazmat import asn1
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not CRYPTOGRAPHY_AVAILABLE,
    reason="cryptography package is required for TLS tests",
)

_MODBUS_OID = x509.ObjectIdentifier(MODBUS_ROLE_OID)

_NOW = datetime.datetime.now(datetime.UTC)
_VALIDITY = datetime.timedelta(days=365)


def _make_key() -> rsa.RSAPrivateKey:
    """Generate a 2048-bit RSA key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_ca_cert(key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Create a self-signed CA certificate."""
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestCA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW)
        .not_valid_after(_NOW + _VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def _make_end_cert(  # noqa: PLR0913
    key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    cn: str,
    role: str | None = None,
    ips: list[str] | None = None,
) -> x509.Certificate:
    """Create a CA-signed end-entity certificate, optionally with a Modbus role extension."""
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    san_list: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    san_list.extend(x509.IPAddress(ipaddress.IPv4Address(ip)) for ip in (ips or []))

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW)
        .not_valid_after(_NOW + _VALIDITY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
    )

    if role is not None:
        # Encode role as DER UTF8String (tag 0x0C + length + UTF-8 bytes). (R-22)
        role_bytes = role.encode("utf-8")
        asn1_value = bytes([0x0C, len(role_bytes)]) + role_bytes
        builder = builder.add_extension(
            x509.UnrecognizedExtension(_MODBUS_OID, asn1_value),
            critical=False,
        )

    return builder.sign(ca_key, hashes.SHA256())


def _cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_to_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Generate a CA + server cert + two client certs (with/without role) as PEM files."""
    tmp = tmp_path_factory.mktemp("pki")

    ca_key = _make_key()
    ca_cert = _make_ca_cert(ca_key)

    server_key = _make_key()
    server_cert = _make_end_cert(server_key, ca_cert, ca_key, "TestServer")

    client_key = _make_key()
    client_cert_with_role = _make_end_cert(client_key, ca_cert, ca_key, "TestClient", role="Operator")
    client_cert_no_role = _make_end_cert(client_key, ca_cert, ca_key, "TestClientNoRole")

    files: dict[str, Path] = {
        "ca_cert": tmp / "ca.crt",
        "server_cert": tmp / "server.crt",
        "server_key": tmp / "server.key",
        "client_cert_with_role": tmp / "client_role.crt",
        "client_cert_no_role": tmp / "client_norole.crt",
        "client_key": tmp / "client.key",
    }
    files["ca_cert"].write_bytes(_cert_to_pem(ca_cert))
    files["server_cert"].write_bytes(_cert_to_pem(server_cert))
    files["server_key"].write_bytes(_key_to_pem(server_key))
    files["client_cert_with_role"].write_bytes(_cert_to_pem(client_cert_with_role))
    files["client_cert_no_role"].write_bytes(_cert_to_pem(client_cert_no_role))
    files["client_key"].write_bytes(_key_to_pem(client_key))

    return files


def _make_server_ssl_ctx(pki: dict[str, Path]) -> ssl.SSLContext:
    """Build a server SSLContext requiring mutual auth (mbaps compliant)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki["server_cert"], pki["server_key"])
    ctx.load_verify_locations(cafile=pki["ca_cert"])
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _make_client_ssl_ctx(
    pki: dict[str, Path],
    cert_key: str = "client_cert_with_role",
) -> ssl.SSLContext:
    """Build a client SSLContext presenting a client certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(pki[cert_key], pki["client_key"])
    ctx.load_verify_locations(cafile=pki["ca_cert"])
    return ctx


@pytest.fixture
async def tls_server(pki: dict[str, Path]) -> AsyncIterator[AsyncTcpServer]:
    """Start a TLS-enabled AsyncTcpServer with a ReadHoldingRegisters handler."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0xABCD]

    server = AsyncTcpServer(
        host="127.0.0.1",
        port=0,
        handler=router,
        ssl_context=_make_server_ssl_ctx(pki),
    )
    await server.start()
    yield server
    await server.stop()


@pytest.fixture
async def tls_server_with_rbac(
    pki: dict[str, Path],
) -> AsyncIterator[tuple[AsyncTcpServer, list[RequestContext | None]]]:
    """Start a TLS server whose handler declares context and captures it for assertions."""
    captured: list[RequestContext | None] = []
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(
        _unit_id: int,
        _request: ReadHoldingRegistersPDU,
        context: RequestContext,
    ) -> list[int]:
        captured.append(context)
        return [0x1234]

    server = AsyncTcpServer(
        host="127.0.0.1",
        port=0,
        handler=router,
        ssl_context=_make_server_ssl_ctx(pki),
    )
    await server.start()
    yield server, captured
    await server.stop()


def _port(server: AsyncTcpServer) -> int:
    assert server._server is not None
    sockets = server._server.sockets
    assert sockets
    return int(sockets[0].getsockname()[1])


async def _send_read_holding_registers(
    port: int,
    ssl_ctx: ssl.SSLContext,
    unit_id: int = 1,
) -> bytes:
    """Open a TLS connection and send a single ReadHoldingRegisters request."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=ssl_ctx)
    try:
        mbap = struct.pack(">HHHB", 1, 0, 6, unit_id)
        pdu = b"\x03\x00\x00\x00\x01"
        writer.write(mbap + pdu)
        await writer.drain()

        resp_mbap = await reader.readexactly(7)
        _tx, _proto, length, _unit = struct.unpack(">HHHB", resp_mbap)
        return await reader.readexactly(length - 1)
    finally:
        writer.close()
        await writer.wait_closed()


# ---------------------------------------------------------------------------
# Tests: constants and module attributes
# ---------------------------------------------------------------------------


def test_modbus_role_oid_value() -> None:
    """Verify the Modbus role OID matches the specification (R-21)."""
    assert MODBUS_ROLE_OID == "1.3.6.1.4.1.50316.802.1"


def test_modbus_security_port() -> None:
    """Verify the standard mbaps port is 802 (IANA registration)."""
    assert MODBUS_SECURITY_PORT == 802


# ---------------------------------------------------------------------------
# Tests: asn1 decoding
# ---------------------------------------------------------------------------


def test_asn1_decode_operator() -> None:
    """Parse 'Operator' encoded as ASN.1 UTF8String."""
    role_bytes = b"Operator"
    data = bytes([0x0C, len(role_bytes)]) + role_bytes
    assert asn1.decode_der(str, data).strip() == "Operator"


# ---------------------------------------------------------------------------
# Tests: _handler_accepts_context (inspection helper)
# ---------------------------------------------------------------------------


def test_handler_inspection_without_context() -> None:
    """Handler without context parameter is detected correctly."""

    async def plain_handler(_unit_id: int, _request: Any) -> list[int]:
        return []

    assert _handler_accepts_context(plain_handler) is False


def test_handler_inspection_with_context() -> None:
    """Handler with context parameter is detected correctly."""

    async def secure_handler(
        _unit_id: int,
        _request: Any,
        context: RequestContext,
    ) -> list[int]:
        _ = context
        return []

    assert _handler_accepts_context(secure_handler) is True


def test_handler_inspection_router_detects_context() -> None:
    """ModbusRequestRouter.__call__ declares context and is detected."""
    router = ModbusRequestRouter()
    assert _handler_accepts_context(router) is True


def test_handler_inspection_invalid_callable() -> None:
    """Returns False gracefully for objects that raise on signature inspection."""
    assert _handler_accepts_context(42) is False


# ---------------------------------------------------------------------------
# Tests: ModbusRequestRouter registers wants_context flag
# ---------------------------------------------------------------------------


def test_router_stores_wants_context_true() -> None:
    """Handler with context is stored with wants_context=True."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handler(
        _unit_id: int,
        _request: ReadHoldingRegistersPDU,
        context: RequestContext,
    ) -> list[int]:
        _ = context
        return []

    # Access internal structure to verify
    entry = router._handlers[None][ReadHoldingRegistersPDU.function_code]
    assert _handler_accepts_context(entry) is True


def test_router_stores_wants_context_false() -> None:
    """Handler without context is stored with wants_context=False."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handler(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return []

    entry = router._handlers[None][ReadHoldingRegistersPDU.function_code]
    assert _handler_accepts_context(entry) is False


# ---------------------------------------------------------------------------
# Tests: AsyncTcpServer with TLS (integration)
# ---------------------------------------------------------------------------


async def test_tls_server_happy_path(tls_server: AsyncTcpServer, pki: dict[str, Path]) -> None:
    """TLS connection succeeds and server returns a response."""
    resp = await _send_read_holding_registers(
        _port(tls_server),
        _make_client_ssl_ctx(pki),
    )
    # Response: FC=3, byte_count=2, data=[0xABCD]
    assert resp == b"\x03\x02\xab\xcd"


async def test_tls_server_cert_info_injected(
    tls_server_with_rbac: tuple[AsyncTcpServer, list[RequestContext | None]],
    pki: dict[str, Path],
) -> None:
    """RequestContext is populated and injected into handlers that declare it."""
    server, captured = tls_server_with_rbac

    resp = await _send_read_holding_registers(
        _port(server),
        _make_client_ssl_ctx(pki, cert_key="client_cert_with_role"),
    )
    assert resp == b"\x03\x02\x12\x34"

    assert len(captured) == 1
    context = captured[0]
    assert context is not None
    assert context.peer_addr is not None
    cert_info = context.cert_info
    assert cert_info is not None
    assert "TestClient" in cert_info.subject
    assert cert_info.role == "Operator"
    assert "127.0.0.1" in cert_info.san_ips


async def test_tls_server_cert_no_role(
    tls_server_with_rbac: tuple[AsyncTcpServer, list[RequestContext | None]],
    pki: dict[str, Path],
) -> None:
    """Client cert without Modbus role OID results in cert_info.role == None (R-23)."""
    server, captured = tls_server_with_rbac

    await _send_read_holding_registers(
        _port(server),
        _make_client_ssl_ctx(pki, cert_key="client_cert_no_role"),
    )

    assert len(captured) == 1
    context = captured[0]
    assert context is not None
    cert_info = context.cert_info
    assert cert_info is not None
    assert cert_info.role is None


async def test_tls_server_rbac_reject(pki: dict[str, Path]) -> None:
    """Handler raises IllegalFunctionError when role is unauthorized (R-31)."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(
        _unit_id: int,
        request: ReadHoldingRegistersPDU,
        context: RequestContext,
    ) -> list[int]:
        cert_info = context.cert_info
        if cert_info is None or cert_info.role != "Operator":
            raise IllegalFunctionError(request.function_code)
        return [0x0001]

    server = AsyncTcpServer(
        host="127.0.0.1",
        port=0,
        handler=router,
        ssl_context=_make_server_ssl_ctx(pki),
    )
    await server.start()
    try:
        # Client cert WITHOUT role → role=None → rejected with IllegalFunction (0x01)
        resp = await _send_read_holding_registers(
            _port(server),
            _make_client_ssl_ctx(pki, cert_key="client_cert_no_role"),
        )
        # Exception response: FC | 0x80 = 0x83, exception code = 0x01 (R-31)
        assert resp == b"\x83\x01"
    finally:
        await server.stop()


async def test_plain_tcp_context_is_populated() -> None:
    """Plain TCP server passes context with peer_addr but cert_info=None."""
    captured: list[RequestContext | None] = []
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(
        _unit_id: int,
        _request: ReadHoldingRegistersPDU,
        context: RequestContext,
    ) -> list[int]:
        captured.append(context)
        return [0x0000]

    server = AsyncTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    try:
        port = _port(server)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            mbap = struct.pack(">HHHB", 1, 0, 6, 1)
            pdu = b"\x03\x00\x00\x00\x01"
            writer.write(mbap + pdu)
            await writer.drain()
            await reader.readexactly(7)
            await reader.readexactly(4)  # FC + byte_count + 2 bytes data
        finally:
            writer.close()
            await writer.wait_closed()

        assert len(captured) == 1
        context = captured[0]
        assert context is not None
        assert context.peer_addr is not None
        assert context.cert_info is None
    finally:
        await server.stop()


async def test_plain_handler_not_passed_context(pki: dict[str, Path]) -> None:
    """Handler without context param continues to work on TLS connections."""
    received: list[tuple[int, Any]] = []
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(unit_id: int, request: ReadHoldingRegistersPDU) -> list[int]:
        # This handler does NOT declare context — must not receive it
        received.append((unit_id, request))
        return [0xFFFF]

    server = AsyncTcpServer(
        host="127.0.0.1",
        port=0,
        handler=router,
        ssl_context=_make_server_ssl_ctx(pki),
    )
    await server.start()
    try:
        resp = await _send_read_holding_registers(
            _port(server),
            _make_client_ssl_ctx(pki),
        )
        assert resp == b"\x03\x02\xff\xff"
        assert len(received) == 1
    finally:
        await server.stop()


async def test_tls_server_ssl_context_stored() -> None:
    """ssl_context is stored on the server and passed to asyncio.start_server."""
    router = ModbusRequestRouter()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server = AsyncTcpServer(host="127.0.0.1", port=0, handler=router, ssl_context=ctx)
    assert server.ssl_context is ctx


async def test_server_no_ssl_context_is_none() -> None:
    """Default server (no ssl_context) has ssl_context=None."""
    router = ModbusRequestRouter()
    server = AsyncTcpServer(host="127.0.0.1", port=0, handler=router)
    assert server.ssl_context is None


# ---------------------------------------------------------------------------
# Tests: extract_client_cert_info on non-TLS writer
# ---------------------------------------------------------------------------


async def test_extract_cert_info_plain_connection() -> None:
    """extract_client_cert_info returns None for a plain (non-TLS) writer.

    Verified by passing a mock writer whose get_extra_info("ssl_object") returns
    None — the code path taken for all plain TCP connections.
    """
    mock_writer = MagicMock(spec=asyncio.StreamWriter)
    mock_writer.get_extra_info.return_value = None  # no ssl_object

    result = extract_client_cert_info(mock_writer)
    assert result is None
    mock_writer.get_extra_info.assert_called_once_with("ssl_object")


async def test_extract_cert_info_cryptography_missing() -> None:
    """extract_client_cert_info propagates ImportError when cryptography is not available."""
    mock_writer = MagicMock(spec=asyncio.StreamWriter)
    mock_ssl = MagicMock()
    mock_writer.get_extra_info.return_value = mock_ssl
    mock_ssl.getpeercert.return_value = {"subject": (), "issuer": ()}

    with (
        patch.dict("sys.modules", {"cryptography": None, "cryptography.x509": None, "cryptography.hazmat": None}),
        pytest.raises(ImportError, match="The 'cryptography' package is required"),
    ):
        extract_client_cert_info(mock_writer)


async def test_extract_cert_info_malformed_asn1() -> None:
    """extract_client_cert_info propagates ValueError when the OID extension is malformed."""
    mock_writer = MagicMock(spec=asyncio.StreamWriter)
    mock_ssl = MagicMock()
    mock_writer.get_extra_info.return_value = mock_ssl
    mock_ssl.getpeercert.side_effect = lambda binary_form=False: (
        b"some_fake_der_cert" if binary_form else {"subject": (), "issuer": ()}
    )

    mock_cert = MagicMock(spec=x509.Certificate)
    mock_ext = MagicMock()
    mock_ext.value.value = b"\x02\x01\x01"  # non-string tag to trigger ValueError in decode_der

    mock_cert.extensions.get_extension_for_oid.return_value = mock_ext

    with (
        patch("cryptography.x509.load_der_x509_certificate", return_value=mock_cert),
        pytest.raises(ValueError, match="error parsing asn1 value"),
    ):
        extract_client_cert_info(mock_writer)


async def test_extract_cert_info_no_peercert() -> None:
    """extract_client_cert_info returns None if peercert is None."""
    mock_writer = MagicMock(spec=asyncio.StreamWriter)
    mock_ssl = MagicMock()
    mock_writer.get_extra_info.return_value = mock_ssl
    mock_ssl.getpeercert.return_value = None

    result = extract_client_cert_info(mock_writer)
    assert result is None


async def test_extract_cert_info_no_binary_der_cert() -> None:
    """extract_client_cert_info returns None if binary der_cert is empty/None."""
    mock_writer = MagicMock(spec=asyncio.StreamWriter)
    mock_ssl = MagicMock()
    mock_writer.get_extra_info.return_value = mock_ssl
    mock_ssl.getpeercert.side_effect = lambda binary_form=False: None if binary_form else {"subject": (), "issuer": ()}

    result = extract_client_cert_info(mock_writer)
    assert result is None


async def test_extract_cert_info_non_ip_or_dns_san() -> None:
    """extract_client_cert_info parses SANs correctly and ignores non-IP/DNS types."""
    mock_writer = MagicMock(spec=asyncio.StreamWriter)
    mock_ssl = MagicMock()
    mock_writer.get_extra_info.return_value = mock_ssl
    mock_ssl.getpeercert.return_value = b"some_fake_der_cert"

    mock_cert = MagicMock(spec=x509.Certificate)
    mock_cert.subject.rfc4514_string.return_value = "CN=TestClient"
    mock_cert.issuer.rfc4514_string.return_value = "CN=TestCA"

    # Mock the SAN extension
    mock_san_ext = MagicMock()
    mock_san_ext.value = [
        x509.RFC822Name("test@example.com"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.DNSName("localhost"),
    ]
    mock_cert.extensions.get_extension_for_class.return_value = mock_san_ext

    mock_cert.extensions.get_extension_for_oid.side_effect = x509.ExtensionNotFound(
        "Modbus role OID extension not found", x509.ObjectIdentifier(MODBUS_ROLE_OID)
    )

    with patch("cryptography.x509.load_der_x509_certificate", return_value=mock_cert):
        result = extract_client_cert_info(mock_writer)

    assert result is not None
    assert result.role is None
    assert result.san_ips == ["127.0.0.1"]
    assert result.san_dns == ["localhost"]


async def test_extract_cert_info_no_san_extension() -> None:
    """extract_client_cert_info returns empty SAN lists when the extension is missing."""
    mock_writer = MagicMock(spec=asyncio.StreamWriter)
    mock_ssl = MagicMock()
    mock_writer.get_extra_info.return_value = mock_ssl
    mock_ssl.getpeercert.return_value = b"some_fake_der_cert"

    mock_cert = MagicMock(spec=x509.Certificate)
    mock_cert.subject.rfc4514_string.return_value = "CN=TestClient"
    mock_cert.issuer.rfc4514_string.return_value = "CN=TestCA"

    mock_cert.extensions.get_extension_for_class.side_effect = x509.ExtensionNotFound(
        "SubjectAlternativeName not found", x509.ObjectIdentifier("2.5.29.17")
    )
    mock_cert.extensions.get_extension_for_oid.side_effect = x509.ExtensionNotFound(
        "Modbus role OID extension not found", x509.ObjectIdentifier(MODBUS_ROLE_OID)
    )

    with patch("cryptography.x509.load_der_x509_certificate", return_value=mock_cert):
        result = extract_client_cert_info(mock_writer)

    assert result is not None
    assert result.san_ips == []
    assert result.san_dns == []

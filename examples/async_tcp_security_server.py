"""Example of an Async TCP Modbus Security (mbaps) Server.

This example runs a Modbus/TCP Security server on localhost port 8020
using mutual TLS (mTLS). It dynamically generates self-signed certificates in the
'examples/certs' folder if they do not exist, and demonstrates Role-Based Access
Control (RBAC) using the Modbus OID extension.
"""

import asyncio
import logging
import ssl
import sys
from pathlib import Path

from tmodbus.exceptions import IllegalFunctionError
from tmodbus.pdu import ReadHoldingRegistersPDU
from tmodbus.server import AsyncTcpServer, ModbusRequestRouter, RequestContext
from tmodbus.server.security import extract_modbus_role

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
PORT = 8020
CERT_DIR = Path(__file__).parent / "certs"

router = ModbusRequestRouter()


@router.register(ReadHoldingRegistersPDU)
async def handle_read_holding_registers(
    _unit_id: int,
    request: ReadHoldingRegistersPDU,
    context: RequestContext,
) -> list[int]:
    """Context-aware handler with Role-Based Access Control (RBAC).

    This handler extracts the client certificate from RequestContext,
    inspects the Modbus role, and permits the read only if the role is 'Operator' or 'Admin'.
    """
    cert = context.client_cert
    if not cert:
        logger.warning("Rejecting connection: No TLS client certificate presented.")
        raise IllegalFunctionError(request.function_code)

    # Extract role from the custom Modbus OID extension
    role = extract_modbus_role(cert)
    logger.info("Handling request: client_subject='%s', role='%s'", cert.subject.rfc4514_string(), role)

    if role not in {"Operator", "Admin"}:
        logger.warning("Rejecting connection: Role '%s' is unauthorized to read registers.", role)
        # R-31: Illegal function code returned if unauthorized
        raise IllegalFunctionError(request.function_code)

    return [42] * request.quantity


async def main() -> None:
    """Run the Async TCP Modbus Security server."""
    # Check if PKI files exist
    if not (CERT_DIR / "server.crt").exists():
        print("Generate PKI files by running: python generate_modbus_security_certs.py")
        sys.exit(99)

    # Build SSLContext configured for mutual TLS (compliant with mbaps spec)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_DIR / "server.crt", CERT_DIR / "server.key")
    ctx.load_verify_locations(cafile=CERT_DIR / "ca.crt")

    # Mandate client certificate validation
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Instantiate the secure AsyncTcpServer on the mbaps security port (configured to localhost here)
    server = AsyncTcpServer(host="127.0.0.1", port=PORT, handler=router, ssl_context=ctx)

    print(f"\nStarting Modbus TCP Security Server on 127.0.0.1:{PORT}")
    print("Press Ctrl+C to stop.")
    print("\nTo test mTLS authentication manually, you can use openssl:")
    print("  1. As an authorized Operator:")
    print(
        f"     openssl s_client -connect 127.0.0.1:{PORT} "
        f"-CAfile {CERT_DIR}/ca.crt -cert {CERT_DIR}/client_operator.crt -key {CERT_DIR}/client_operator.key"
    )
    print("  2. As an authorized Admin:")
    print(
        f"     openssl s_client -connect 127.0.0.1:{PORT} "
        f"-CAfile {CERT_DIR}/ca.crt -cert {CERT_DIR}/client_admin.crt -key {CERT_DIR}/client_admin.key"
    )
    print("  3. As an unauthorized User:")
    print(
        f"     openssl s_client -connect 127.0.0.1:{PORT} "
        f"-CAfile {CERT_DIR}/ca.crt -cert {CERT_DIR}/client_user.crt -key {CERT_DIR}/client_user.key"
    )
    print("\nWait for client connections...")
    await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped.")

r"""Modbus TCP+TLS (MBAPS or Modbus Security) server example.

This file is intended to be a demo of the modbus server in a tcp+tls
configuration.
It shows how to configure and start a server, as well as how to use
client roles to perform authorization in the handler.
Feel free to use it as boilerplate for simple servers.

This server exposes a demo holding registers handler that permits reading
only for clients with the "Operator" or "Admin" role specified in their
certificate.

Access control is done by way of Modbus Roles, which are encoded in the
client certificate as an X509 extension.
Certificates with no Modbus Role extension will have their role set to
None (role is None).

Requests from clients with certificates not passing TLS verification are
rejected at the TLS layer (i.e. before reaching the Modbus layer).


The following commands can be used to create self-signed CA, server, and client
certificates:
$ mkdir -p examples/certs

create a CA key pair:
$ openssl req -x509 -newkey rsa:4096 -sha256 -days 360 -nodes \
  -keyout examples/certs/ca.key.pem -out examples/certs/ca.cert.pem \
  -subj "/CN=TEST CA DO NOT USE/"

create the server key pair and sign it with the CA:
$ echo "subjectAltName=DNS:localhost" > examples/certs/server.ext
$ echo "keyUsage=digitalSignature,keyEncipherment" >> examples/certs/server.ext
$ echo "extendedKeyUsage=critical,serverAuth" >> examples/certs/server.ext
$ openssl req -newkey rsa:4096 -nodes -keyout examples/certs/server.key.pem \
  -out examples/certs/server.csr -subj "/CN=localhost/"
$ openssl x509 -req -in examples/certs/server.csr \
  -CA examples/certs/ca.cert.pem -CAkey examples/certs/ca.key.pem \
  -CAcreateserial -out examples/certs/server.cert.pem -days 360 -sha256 \
  -extfile examples/certs/server.ext

create a client certificate with the "User" role, signed by the CA:
$ echo "keyUsage=digitalSignature,keyEncipherment" > examples/certs/user-client.ext
$ echo "extendedKeyUsage=critical,clientAuth" >> examples/certs/user-client.ext
$ echo "1.3.6.1.4.1.50316.802.1=ASN1:UTF8String:User" >> examples/certs/user-client.ext
$ openssl req -newkey rsa:4096 -nodes -keyout examples/certs/user-client.key.pem \
  -out examples/certs/user-client.csr -subj "/CN=TEST CLIENT USER/"
$ openssl x509 -req -in examples/certs/user-client.csr \
  -CA examples/certs/ca.cert.pem -CAkey examples/certs/ca.key.pem \
  -CAcreateserial -out examples/certs/user-client.cert.pem -days 360 -sha256 \
  -extfile examples/certs/user-client.ext

create another client certificate with the "Operator" role, signed by the CA:
$ echo "keyUsage=digitalSignature,keyEncipherment" > examples/certs/operator-client.ext
$ echo "extendedKeyUsage=critical,clientAuth" >> examples/certs/operator-client.ext
$ echo "1.3.6.1.4.1.50316.802.1=ASN1:UTF8String:Operator" >> examples/certs/operator-client.ext
$ openssl req -newkey rsa:4096 -nodes -keyout examples/certs/operator-client.key.pem \
  -out examples/certs/operator-client.csr -subj "/CN=TEST CLIENT OPERATOR/"
$ openssl x509 -req -in examples/certs/operator-client.csr \
  -CA examples/certs/ca.cert.pem -CAkey examples/certs/ca.key.pem \
  -CAcreateserial -out examples/certs/operator-client.cert.pem -days 360 -sha256 \
  -extfile examples/certs/operator-client.ext

(OPTIONAL) create a file containing both client certificates if you want to test client
certificate pinning instead of validating via a shared CA:
$ cat examples/certs/user-client.cert.pem examples/certs/operator-client.cert.pem > examples/certs/clients.cert.pem

start the server:
$ python examples/async_tcp_tls_server.py

in another shell, read the registers as the 'Operator' role (should succeed):
$ python -c "
import asyncio, ssl
from tmodbus import create_async_tcp_client

async def run():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations('examples/certs/ca.cert.pem')
    ctx.load_cert_chain('examples/certs/operator-client.cert.pem', 'examples/certs/operator-client.key.pem')
    async with create_async_tcp_client('127.0.0.1', 8020, ssl=ctx) as client:
        print('Registers:', await client.read_holding_registers(0, 2))

asyncio.run(run())
"

attempting to read the registers as the 'User' role (should fail with ModbusResponseError):
$ python -c "
import asyncio, ssl
from tmodbus import create_async_tcp_client
from tmodbus.exceptions import ModbusResponseError

async def run():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations('examples/certs/ca.cert.pem')
    ctx.load_cert_chain('examples/certs/user-client.cert.pem', 'examples/certs/user-client.key.pem')
    async with create_async_tcp_client('127.0.0.1', 8020, ssl=ctx) as client:
        try:
            await client.read_holding_registers(0, 2)
        except ModbusResponseError as e:
            print('Failed as expected:', e)

asyncio.run(run())
"
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
    if not (CERT_DIR / "server.cert.pem").exists() or not (CERT_DIR / "ca.cert.pem").exists():
        print("Generate PKI files using the openssl commands in the module docstring.")
        sys.exit(99)

    # Build SSLContext configured for mutual TLS (compliant with mbaps spec)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_DIR / "server.cert.pem", CERT_DIR / "server.key.pem")

    # Load TLS client verification material, which could either be:
    # - the CA (Certificate Authority) certificate used to sign/verify client certs (default),
    # - the list of allowed client certs, if client certificates are self-signed or
    #   if client certificate pinning is required.
    ctx.load_verify_locations(cafile=CERT_DIR / "ca.cert.pem")
    # Alternatively, specify the 'clients.cert.pem' path here to trust only specific client certs.

    # Mandate client certificate validation
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Instantiate the secure AsyncTcpServer on the mbaps security port (configured to localhost here)
    server = AsyncTcpServer(host="127.0.0.1", port=PORT, handler=router, ssl_context=ctx)

    print(f"\nStarting Modbus TCP Security Server on 127.0.0.1:{PORT}")
    print("Press Ctrl+C to stop.")
    print("\nTo test, use the python snippets in the module docstring.")
    print("Wait for client connections...")
    await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped.")

"""Modbus/TCP Security (mbaps) utilities.

This module provides support for the Modbus/TCP Security protocol (mbaps),
as defined in the *MB-TCP-Security-v36_2021-07-30* specification.

The mbaps protocol is standard Modbus/TCP framing (the mbap ADU, unchanged)
transported over **TLS** (RFC 5246).  Key security properties added by TLS:

- Confidential transport and data integrity.
- Mutual client/server authentication via x.509v3 certificates (R-02, R-03).
- Role-based client authorization (RBAC) using a custom OID extension in the
  client certificate (R-16 - R-31).

The standard IANA port for mbaps is **802** (plain Modbus/TCP uses port 502).

Role Extraction
---------------
The client's role is encoded in the x.509v3 certificate under the Modbus.org
Private Enterprise OID ``1.3.6.1.4.1.50316.802.1`` as an ASN.1 UTF8String
(R-21, R-22).  This role value is parsed and extracted using the
``cryptography`` package.

TLS Compliance Notes
--------------------
The mbaps specification mandates mutual TLS (R-06, R-41, R-44).  When building
an :class:`ssl.SSLContext` for use with :class:`~tmodbus.server.AsyncTcpServer`,
the following settings are **required** for spec compliance:

.. code-block:: python

    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("server.crt", "server.key")   # R-03: server certificate
    ctx.load_verify_locations(cafile="ca.crt")         # Trust anchor
    ctx.verify_mode = ssl.CERT_REQUIRED                # R-06, R-44: mutual auth
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2       # R-32, R-34: TLS >= 1.2

    server = AsyncTcpServer(host="0.0.0.0", port=802, handler=router, ssl_context=ctx)

References:
    - MB-TCP-Security-v36_2021-07-30
    - :rfc:`5246` — TLS 1.2
    - :rfc:`5280` — Internet x.509 Public Key Infrastructure

"""

from __future__ import annotations

import dataclasses
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import asyncio
    import ssl as _ssl

__all__ = [
    "MODBUS_ROLE_OID",
    "MODBUS_SECURITY_PORT",
    "ClientCertInfo",
    "extract_client_cert_info",
]

logger = logging.getLogger(__name__)

#: OID registered with Modbus.org (Private Enterprise Number 50316) for the
#: client role extension in x.509v3 certificates. (R-21)
MODBUS_ROLE_OID: str = "1.3.6.1.4.1.50316.802.1"

#: Standard IANA port number for Modbus/TCP Security (mbaps).
MODBUS_SECURITY_PORT: int = 802


@dataclasses.dataclass(frozen=True)
class ClientCertInfo:
    """Identity and role information extracted from a client x.509v3 certificate.

    Populated once per TLS connection during mutual authentication (R-02, R-03)
    and made available to Modbus request handlers for role-based client
    authorization (R-16 - R-31).

    Handlers that wish to receive this information should declare a ``context``
    parameter — the dispatcher detects and injects it automatically:

    .. code-block:: python

        from tmodbus.server import ModbusRequestRouter, RequestContext
        from tmodbus.pdu import ReadHoldingRegistersPDU
        from tmodbus.exceptions import IllegalFunctionError

        router = ModbusRequestRouter()

        @router.register(ReadHoldingRegistersPDU)
        async def handle_read(
            unit_id: int,
            request: ReadHoldingRegistersPDU,
            context: RequestContext,
        ) -> list[int]:
            cert_info = context.cert_info
            if cert_info is None or cert_info.role not in {"Operator", "Admin"}:
                raise IllegalFunctionError(request.function_code)  # R-31
            return [42] * request.quantity

    Handlers that do **not** declare ``context`` continue to work unchanged.

    Note:
        Per R-23, if the certificate does not contain the Modbus role OID
        extension, :attr:`role` will be ``None``.

        Per R-65, there MUST be only one role per certificate; only the first
        occurrence of the OID extension is used.

    """

    subject: str
    """Certificate subject Distinguished Name (e.g. ``"CN=ModbusSecurityClient, O=Org"``)."""

    issuer: str
    """Certificate issuer Distinguished Name."""

    role: str | None
    """Value of the Modbus role extension (OID ``1.3.6.1.4.1.50316.802.1``).

    ``None`` when the extension is absent (R-23).
    """

    san_ips: list[str]
    """IP addresses from the x.509v3 SubjectAltName extension."""

    san_dns: list[str]
    """DNS names from the x.509v3 SubjectAltName extension."""


# ---------------------------------------------------------------------------
# Internal helpers and extraction
# ---------------------------------------------------------------------------


def extract_client_cert_info(writer: asyncio.StreamWriter) -> ClientCertInfo | None:
    """Extract certificate identity and role from an accepted TLS connection.

    Reads the peer certificate from the TLS transport of *writer* and returns
    a :class:`ClientCertInfo` containing the subject DN, issuer DN, Modbus
    role (OID ``1.3.6.1.4.1.50316.802.1``), and Subject Alternative Names.

    Called **once per connection** by :class:`~tmodbus.server.AsyncTcpServer`
    immediately after the TLS handshake, mirroring R-30 (role is extracted and
    cached per TLS session).

    Args:
        writer: The :class:`asyncio.StreamWriter` for an accepted connection.

    Returns:
        A :class:`ClientCertInfo` instance, or ``None`` if the connection is
        not TLS or the client did not present a certificate.

    """
    try:
        from cryptography import x509  # noqa: PLC0415
        from cryptography.hazmat import asn1  # noqa: PLC0415
    except ImportError as e:
        msg = (
            "The 'cryptography' package is required to extract Modbus roles "
            "from TLS client certificates. Install with 'pip install tmodbus[security]'."
        )
        raise ImportError(msg) from e

    ssl_object: _ssl.SSLObject | None = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return None

    der_cert: bytes | None = ssl_object.getpeercert(binary_form=True)
    if not der_cert:
        return None

    cert = x509.load_der_x509_certificate(der_cert)

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()

    san_ips: list[str] = []
    san_dns: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value:
            if isinstance(name, x509.IPAddress):
                san_ips.append(str(name.value))
            elif isinstance(name, x509.DNSName):
                san_dns.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    # Extract role from MODBUS_ROLE_OID
    modbus_oid = x509.ObjectIdentifier(MODBUS_ROLE_OID)
    role: str | None = None
    try:
        role_ext = cert.extensions.get_extension_for_oid(modbus_oid)
        if isinstance(role_ext.value, x509.UnrecognizedExtension):
            raw_value: bytes = role_ext.value.value
        else:
            raw_value = getattr(role_ext.value, "value", b"")
        role = asn1.decode_der(str, raw_value).strip()
    except x509.ExtensionNotFound:
        pass

    return ClientCertInfo(
        subject=subject,
        issuer=issuer,
        role=role,
        san_ips=san_ips,
        san_dns=san_dns,
    )

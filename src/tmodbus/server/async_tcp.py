"""Async Modbus TCP Server."""

import asyncio
import contextlib
import logging
import ssl as _ssl
import struct
from functools import partial
from typing import Any

from tmodbus.const import ExceptionCode
from tmodbus.exceptions import InvalidRequestError
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .base import AsyncBaseServer, get_server_pdu_class
from .handler import AnyModbusHandler, RequestContext, handle_modbus_request, handler_supports_unit_id
from .security import extract_client_cert, extract_modbus_role

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "TCP-Server")


class AsyncTcpServer(AsyncBaseServer):
    """Async Modbus TCP Server.

    This server implements Modbus/TCP framing and dispatching. It supports both
    unencrypted TCP connections and encrypted Modbus/TCP Security (mbaps) over TLS.

    When ``ssl_context`` is set:

    - Connections are accepted over TLS; a full TLS handshake is performed
      before any data is read.
    - The client's x.509v3 certificate is parsed after the handshake as a
      :class:`cryptography.x509.Certificate` when the ``cryptography``
      package is installed.
    - The parsed certificate is supplied to any request handler that accepts
      at least three positional parameters (via the connection's RequestContext).

    TLS compliance (mbaps) requires **mutual authentication** (R-06, R-41, R-44).
    Configure the :class:`ssl.SSLContext` as follows::

        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain("server.crt", "server.key")
        ctx.load_verify_locations(cafile="ca.crt")
        ctx.verify_mode = ssl.CERT_REQUIRED          # mandatory mutual auth
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2 # TLS >= 1.2 (R-32, R-34)

        server = AsyncTcpServer(
            host="0.0.0.0",
            port=802,  # IANA port for mbaps
            handler=router,
            ssl_context=ctx,
        )

    Incoming Data Flow & Error Branches::

        [ TCP Socket / Client Connection ]
                      │
                      ▼
             handle_client()
                      │ (extracts client certificate from TLS peer cert, once per conn)
                      │ (reads 7-byte MBAP header)
                      ├───[ IncompleteReadError ]─────────────► [ Terminate Connection ]
                      ▼
           _handle_single_request()
                      │
                      ├───[ Protocol ID != 0 ]────────────────► [ Terminate Connection ] (returns False)
                      ├───[ PDU Length invalid ]──────────────► [ Terminate Connection ] (returns False)
                      │ (reads PDU bytes)
                      ├───[ IncompleteReadError ]─────────────► [ Terminate Connection ]
                      ▼
             _get_pdu_class()
                      │
                      ├───[ Unsupported Code / Not Server PDU ]
                      │   (ValueError) ──► Responds with IllegalFunction PDU ──► [ Continue Loop ] (returns True)
                      ▼
             PDU.decode_request()
                      │
                      ├───[ Malformed Request ]
                      │   (InvalidRequestError) ──► Responds with IllegalFunction ──► [ Continue Loop ] (returns True)
                      ▼
            handle_modbus_request()  ────► routes to ModbusHandler/router
                      │                   (injects cert_info if handler declares it)
                      │ (normal case: executes handler, encodes response)
                      ▼
                 [ TCP Write ]       ────► prepends response MBAP and sends (returns True)

    """

    def __init__(
        self,
        host: str,
        handler: AnyModbusHandler,
        port: int = 502,
        *,
        ssl_context: _ssl.SSLContext | None = None,
        unregistered_unit_id_exception_code: int = ExceptionCode.GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND,
        **server_kwargs: Any,
    ) -> None:
        """Initialize Async Modbus TCP Server.

        Args:
            host: Interface to bind to.
            port: Port to listen on (default: 502 for plain TCP; use 802 for mbaps/TLS).
            handler: User-defined async handler for processing requests.
            ssl_context: Optional :class:`ssl.SSLContext` to enable TLS (mbaps).
                When provided, all connections are wrapped in TLS.  For full mbaps
                compliance (mutual authentication, TLS >= 1.2) configure the context
                with ``verify_mode=ssl.CERT_REQUIRED`` and
                ``minimum_version=ssl.TLSVersion.TLSv1_2``.
                See :mod:`tmodbus.server.security` for details.
            unregistered_unit_id_exception_code: Exception code returned when a request is received
                for a Unit ID that is not registered in the handler (default: 0x0B).
                Note that `ExceptionCode.GATEWAY_PATH_UNAVAILABLE` (0x0A) is preferred if the server
                is acting as a gateway.
            server_kwargs: Additional arguments for `asyncio.start_server`.

        """
        self.host = host
        self.handler = handler
        self.port = port
        self.ssl_context = ssl_context
        self.unregistered_unit_id_exception_code = unregistered_unit_id_exception_code
        self.server_kwargs = server_kwargs
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        """Start the server."""
        self._server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port,
            ssl=self.ssl_context,
            **self.server_kwargs,
        )
        if self.ssl_context is not None:
            logger.info("Modbus TCP Security (mbaps) Server listening on %s:%d (TLS)", self.host, self.port)
        else:
            logger.info("Modbus TCP Server listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Stop the server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info("Modbus TCP Server stopped")

    async def serve_forever(self) -> None:
        """Start the server and block until cancelled."""
        await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def _handle_single_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        addr: Any,
        context: RequestContext,
    ) -> bool:
        """Handle a single Modbus TCP request from the reader and write to writer.

        Args:
            reader: Stream reader for the client connection.
            writer: Stream writer for the client connection.
            addr: Peer address (for logging).
            context: RequestContext containing connection and client cert info.

        Returns:
            ``True`` if handling should continue, ``False`` if connection should close.

        """
        mbap_header = b""
        pdu_bytes = b""
        try:
            # Read MBAP header (7 bytes)
            mbap_header = await reader.readexactly(7)
            transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", mbap_header)

            if protocol_id != 0:
                logger.warning("Invalid protocol ID from %s: %d", addr, protocol_id)
                log_raw_traffic("recv", mbap_header, is_error=True)
                return False

            # Read PDU
            pdu_length = length - 1  # Length includes unit_id
            if pdu_length <= 0 or pdu_length > 253:
                logger.warning("Invalid PDU length from %s: %d", addr, pdu_length)
                log_raw_traffic("recv", mbap_header, is_error=True)
                return False

            pdu_bytes = await reader.readexactly(pdu_length)
        except asyncio.IncompleteReadError as e:
            received_bytes = mbap_header + e.partial
            if received_bytes:
                log_raw_traffic("recv", received_bytes, is_error=True)
            raise
        except Exception:
            received_bytes = mbap_header + pdu_bytes
            if received_bytes:
                log_raw_traffic("recv", received_bytes, is_error=True)
            raise

        function_code = pdu_bytes[0]
        is_error = False

        if not handler_supports_unit_id(self.handler, unit_id):
            logger.warning("Request for unregistered unit ID %d from %s", unit_id, addr)
            response_pdu_bytes = bytes([function_code | 0x80, self.unregistered_unit_id_exception_code])
            is_error = True
        else:
            try:
                raw_pdu_class = get_server_pdu_class(pdu_bytes)
                request_pdu = raw_pdu_class.decode_request(pdu_bytes)
            except (ValueError, InvalidRequestError) as e:
                logger.warning("Invalid request from %s: %s", addr, e)
                # Cannot respond if we don't even know the function code properly, or if unsupported
                # We might reply with IllegalFunction if we at least have function_code
                response_pdu_bytes = bytes([function_code | 0x80, 0x01])  # ILLEGAL_FUNCTION
                is_error = True
            else:
                response_pdu_bytes = await handle_modbus_request(unit_id, request_pdu, self.handler, context=context)

        log_raw_traffic("recv", mbap_header + pdu_bytes, is_error=is_error)

        # Build MBAP header for response
        resp_length = len(response_pdu_bytes) + 1
        resp_mbap = struct.pack(">HHHB", transaction_id, protocol_id, resp_length, unit_id)

        out_bytes = resp_mbap + response_pdu_bytes
        writer.write(out_bytes)
        log_raw_traffic("sent", out_bytes)
        await writer.drain()
        return True

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle a single client connection."""
        addr = writer.get_extra_info("peername")
        logger.info("Client connected: %s", addr)

        # Extract TLS client certificate once per connection (R-30).
        # Returns None for plain TCP connections or if the client sent no cert.
        client_cert = extract_client_cert(writer)
        if client_cert is not None:
            role = extract_modbus_role(client_cert)
            logger.debug(
                "TLS client cert: subject=%s role=%s",
                client_cert.subject.rfc4514_string(),
                role,
            )

        context = RequestContext(peer_addr=addr, client_cert=client_cert)

        try:
            while await self._handle_single_request(reader, writer, addr, context):
                pass
        except asyncio.IncompleteReadError:
            logger.info("Client disconnected: %s", addr)
        except Exception:
            logger.exception("Error handling client %s", addr)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

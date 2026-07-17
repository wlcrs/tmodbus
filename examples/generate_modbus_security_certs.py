"""Generate temporary mTLS certificates for Modbus/TCP Security (mbaps)."""

import datetime
import ipaddress
import sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    print(
        "The 'cryptography' library is required to run the security server example.\n"
        "Please install it using: pip install tmodbus[security]\n",
        file=sys.stderr,
    )
    sys.exit(1)

CERT_DIR = Path(__file__).parent / "certs"


def generate_temp_pki(cert_dir: Path) -> None:
    """Generate temporary CA, server, and client certificates for mTLS demonstration."""
    cert_dir.mkdir(parents=True, exist_ok=True)

    ca_key_path = cert_dir / "ca.key"
    ca_cert_path = cert_dir / "ca.crt"
    server_key_path = cert_dir / "server.key"
    server_cert_path = cert_dir / "server.crt"
    operator_key_path = cert_dir / "client_operator.key"
    operator_cert_path = cert_dir / "client_operator.crt"
    admin_key_path = cert_dir / "client_admin.key"
    admin_cert_path = cert_dir / "client_admin.crt"
    user_key_path = cert_dir / "client_user.key"
    user_cert_path = cert_dir / "client_user.crt"

    # Check if they already exist
    required_files = (
        ca_cert_path,
        server_cert_path,
        server_key_path,
        operator_cert_path,
        operator_key_path,
        admin_cert_path,
        admin_key_path,
        user_cert_path,
        user_key_path,
    )
    if all(p.exists() for p in required_files):
        return

    print("Generating temporary mTLS certificates in", cert_dir)

    now = datetime.datetime.now(datetime.UTC)
    expiry = datetime.timedelta(days=365)

    # 1. CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + expiry)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # 2. Server Cert
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + expiry)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
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

    def _create_client_cert(cn: str, role: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

        role_bytes = role.encode("utf-8")
        asn1_value = bytes([0x0C, len(role_bytes)]) + role_bytes
        modbus_role_oid = x509.ObjectIdentifier("1.3.6.1.4.1.50316.802.1")

        client_cert = (
            x509.CertificateBuilder()
            .subject_name(client_name)
            .issuer_name(ca_name)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + expiry)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.UnrecognizedExtension(modbus_role_oid, asn1_value), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return client_key, client_cert

    # 3. Generate Clients with roles: Operator, Admin, User
    operator_key, operator_cert = _create_client_cert("DemoOperator", "Operator")
    admin_key, admin_cert = _create_client_cert("DemoAdmin", "Admin")
    user_key, user_cert = _create_client_cert("DemoUser", "User")

    # Helper to save key/cert PEM bytes
    def _save(key_path: Path, cert_path: Path, key: rsa.RSAPrivateKey, cert: x509.Certificate) -> None:
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    # Save to files
    _save(ca_key_path, ca_cert_path, ca_key, ca_cert)
    _save(server_key_path, server_cert_path, server_key, server_cert)
    _save(operator_key_path, operator_cert_path, operator_key, operator_cert)
    _save(admin_key_path, admin_cert_path, admin_key, admin_cert)
    _save(user_key_path, user_cert_path, user_key, user_cert)


if __name__ == "__main__":
    generate_temp_pki(CERT_DIR)

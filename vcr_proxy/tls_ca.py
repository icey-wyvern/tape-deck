import ipaddress
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass
class CaBundle:
    key: rsa.RSAPrivateKey
    cert: x509.Certificate


def init_ca(ca_key_path: Path, ca_cert_path: Path, password: Optional[str]) -> None:
    if ca_key_path.exists() or ca_cert_path.exists():
        raise FileExistsError("CA key or certificate already exists")
    ca_key_path.parent.mkdir(parents=True, exist_ok=True)
    ca_cert_path.parent.mkdir(parents=True, exist_ok=True)
    key = _generate_key()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "vcr-proxy local CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "vcr-proxy"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    _write_key(ca_key_path, key, password)
    _write_cert(ca_cert_path, cert)


def load_ca(ca_key_path: Path, ca_cert_path: Path, password: Optional[str]) -> CaBundle:
    key_bytes = ca_key_path.read_bytes()
    cert_bytes = ca_cert_path.read_bytes()
    key = serialization.load_pem_private_key(
        key_bytes, password=password.encode("utf-8") if password else None
    )
    cert = x509.load_pem_x509_certificate(cert_bytes)
    return CaBundle(key=key, cert=cert)


def ensure_leaf(
    host: str, ca: CaBundle, leaf_dir: Path, password: Optional[str]
) -> Tuple[Path, Path]:
    leaf_dir.mkdir(parents=True, exist_ok=True)
    safe = host.replace(":", "_")
    cert_path = leaf_dir / f"{safe}.crt"
    key_path = leaf_dir / f"{safe}.key"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path
    key = _generate_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()), critical=False)
    )
    cert_builder = cert_builder.add_extension(_host_san(host), critical=False)
    cert = cert_builder.sign(private_key=ca.key, algorithm=hashes.SHA256())
    _write_key(key_path, key, password)
    _write_cert(cert_path, cert)
    return cert_path, key_path


def _host_san(host: str) -> x509.SubjectAlternativeName:
    try:
        ip = ipaddress.ip_address(host)
        return x509.SubjectAlternativeName([x509.IPAddress(ip)])
    except ValueError:
        return x509.SubjectAlternativeName([x509.DNSName(host)])


def _generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_key(path: Path, key: rsa.RSAPrivateKey, password: Optional[str]) -> None:
    if password:
        enc = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        enc = serialization.NoEncryption()
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=enc,
        )
    )
    _try_chmod(path, 0o600)


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _try_chmod(path, 0o644)


def _try_chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass

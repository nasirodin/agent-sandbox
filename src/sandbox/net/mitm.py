"""Ephemeral per-session certificate authority for request-rule enforcement.

`inspect` hosts (see `NetworkPolicy.hosts`) are TLS-intercepted by the proxy: it
terminates the sandbox side of a CONNECT tunnel with a leaf certificate minted here, vets
the request inside, and re-encrypts upstream with normal verification. Fresh keys are
generated per `Sandbox.start()` and the CA key never touches disk; the sandbox only ever
sees `ca_pem` (through SSL_CERT_FILE and friends), which is worthless beyond this session.
Leaf key PEMs exist on disk only for the instant `ssl` needs a file to load them from.
"""

import datetime
import ipaddress
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_BACKDATE = datetime.timedelta(hours=1)  # tolerate modest clock skew
_LIFETIME = datetime.timedelta(days=7)


def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


class CertificateAuthority:
    """Mints one CA and per-host server certificates; contexts are cached per host."""

    def __init__(self, directory: Path) -> None:
        self._dir = directory
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._key = _new_key()
        self._leaf_key = _new_key()
        now = datetime.datetime.now(datetime.UTC)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sandbox request-filter CA")])
        self._cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _BACKDATE)
            .not_valid_after(now + _LIFETIME)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()), critical=False
            )
            .sign(self._key, hashes.SHA256())
        )
        self.ca_pem: bytes = self._cert.public_bytes(serialization.Encoding.PEM)
        self._contexts: dict[str, ssl.SSLContext] = {}

    def server_context(self, host: str) -> ssl.SSLContext:
        """A server-side TLS context presenting a certificate for `host` (name or IP)."""
        ctx = self._contexts.get(host)
        if ctx is None:
            ctx = self._contexts[host] = self._mint(host)
        return ctx

    def _mint(self, host: str) -> ssl.SSLContext:
        try:
            san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        now = datetime.datetime.now(datetime.UTC)
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(self._cert.subject)
            .public_key(self._leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _BACKDATE)
            .not_valid_after(now + _LIFETIME)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            # VERIFY_X509_STRICT (the default since Python 3.13) wants SKI/AKI everywhere
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._leaf_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )
        pem = (
            leaf.public_bytes(serialization.Encoding.PEM)
            + self._leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            + self.ca_pem
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(["http/1.1"])  # the proxy only parses HTTP/1.1
        # ssl only loads certificates from files: written 0600 and removed immediately
        path = self._dir / f"leaf-{len(self._contexts)}.pem"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
            ctx.load_cert_chain(path)
        finally:
            path.unlink(missing_ok=True)
        return ctx


def trust_bundle(ca_pem: bytes) -> bytes:
    """The system CA bundle plus `ca_pem`, so pointing SSL_CERT_FILE at it makes minted
    certificates verify without untrusting the rest of the web."""
    paths = ssl.get_default_verify_paths()
    for p in (paths.cafile, paths.openssl_cafile):
        if p and os.path.exists(p):
            return Path(p).read_bytes().rstrip(b"\n") + b"\n" + ca_pem
    return ca_pem


__all__ = ["CertificateAuthority", "trust_bundle"]

import ssl
from pathlib import Path

from cryptography import x509

from sandbox.net.mitm import CertificateAuthority, trust_bundle


def test_certificates(tmp_path: Path) -> None:
    ca = CertificateAuthority(tmp_path / "ca")
    root = x509.load_pem_x509_certificate(ca.ca_pem)
    constraints = root.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert constraints.ca and constraints.path_length == 0
    ctx = ca.server_context("api.github.com")
    assert isinstance(ctx, ssl.SSLContext) and ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ca.server_context("api.github.com") is ctx  # cached
    assert ca.server_context("127.0.0.1") is not ctx  # IP hosts get an IP SAN
    # leaf key PEMs never linger on disk
    assert [p.name for p in (tmp_path / "ca").iterdir()] == []


def test_fresh_keys_per_session(tmp_path: Path) -> None:
    assert (
        CertificateAuthority(tmp_path / "a").ca_pem != CertificateAuthority(tmp_path / "b").ca_pem
    )


def test_trust_bundle(tmp_path: Path) -> None:
    ca = CertificateAuthority(tmp_path / "ca")
    bundle = trust_bundle(ca.ca_pem)
    assert bundle.endswith(ca.ca_pem)  # the system store, if any, comes first
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cadata=bundle.decode())  # well-formed PEM throughout

# SPDX-License-Identifier: MIT

"""
Shared fixtures and helpers for pysnputils tests.
"""

import datetime
import pathlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from pysnputils.types import SNP_ATTESTATION_REPORT_LEN

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Report binary builder
# ---------------------------------------------------------------------------


def build_report_bytes(
    *,
    version: int = 3,
    guest_svn: int = 0,
    guest_policy: bytes = b"\x00" * 8,
    family_id: bytes = b"\x00" * 16,
    image_id: bytes = b"\x00" * 16,
    vmpl: int = 0,
    sig_algo: int = 1,
    current_tcb: bytes = b"\x00" * 8,
    platform_info: bytes = b"\x00" * 8,
    key_info: bytes = b"\x00" * 4,
    report_data: bytes = b"\x00" * 64,
    measurement: bytes = b"\x00" * 48,
    host_data: bytes = b"\x00" * 32,
    id_key_digest: bytes = b"\x00" * 48,
    author_key_digest: bytes = b"\x00" * 48,
    report_id: bytes = b"\x00" * 32,
    report_id_ma: bytes = b"\x00" * 32,
    reported_tcb: bytes = b"\x00" * 8,
    cpuid_fam_id: int = 0x19,
    cpuid_mod_id: int = 0x11,
    cpuid_step: int = 0,
    chip_id: bytes = b"\x00" * 64,
    committed_tcb: bytes = b"\x00" * 8,
    current_build: int = 0,
    current_minor: int = 0,
    current_major: int = 0,
    committed_build: int = 0,
    committed_minor: int = 0,
    committed_major: int = 0,
    launch_tcb: bytes = b"\x00" * 8,
    signature: bytes = b"\x00" * 512,
) -> bytes:
    """Build a 1184-byte attestation report binary with the given fields."""
    buf = bytearray(SNP_ATTESTATION_REPORT_LEN)

    buf[0x00:0x04] = version.to_bytes(4, "little")
    buf[0x04:0x08] = guest_svn.to_bytes(4, "little")
    buf[0x08:0x10] = guest_policy
    buf[0x10:0x20] = family_id
    buf[0x20:0x30] = image_id
    buf[0x30:0x34] = vmpl.to_bytes(4, "little")
    buf[0x34:0x38] = sig_algo.to_bytes(4, "little")
    buf[0x38:0x40] = current_tcb
    buf[0x40:0x48] = platform_info
    buf[0x48:0x4C] = key_info
    buf[0x50:0x90] = report_data
    buf[0x90:0xC0] = measurement
    buf[0xC0:0xE0] = host_data
    buf[0xE0:0x110] = id_key_digest
    buf[0x110:0x140] = author_key_digest
    buf[0x140:0x160] = report_id
    buf[0x160:0x180] = report_id_ma
    buf[0x180:0x188] = reported_tcb
    buf[0x188] = cpuid_fam_id
    buf[0x189] = cpuid_mod_id
    buf[0x18A] = cpuid_step
    buf[0x1A0:0x1E0] = chip_id
    buf[0x1E0:0x1E8] = committed_tcb
    buf[0x1E8] = current_build
    buf[0x1E9] = current_minor
    buf[0x1EA] = current_major
    buf[0x1EC] = committed_build
    buf[0x1ED] = committed_minor
    buf[0x1EE] = committed_major
    buf[0x1F0:0x1F8] = launch_tcb
    buf[0x2A0:0x4A0] = signature

    return bytes(buf)


def build_signed_report_bytes(
    signing_key: ec.EllipticCurvePrivateKey,
    **kwargs,
) -> bytes:
    """Build a report binary and sign the TBS portion with *signing_key*.

    All keyword arguments are forwarded to ``build_report_bytes``.
    The signature field is overwritten with the real ECDSA-P384/SHA-384 signature.
    """
    raw = bytearray(build_report_bytes(**kwargs))
    tbs = bytes(raw[0x00:0x2A0])
    dss_sig = signing_key.sign(tbs, ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(dss_sig)
    raw[0x2A0 : 0x2A0 + 0x48] = r.to_bytes(0x48, "little")
    raw[0x2A0 + 0x48 : 0x2A0 + 0x90] = s.to_bytes(0x48, "little")
    return bytes(raw)


# ---------------------------------------------------------------------------
# Certificate helpers
# ---------------------------------------------------------------------------


def _generate_ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


def generate_self_signed_cert(
    cn: str = "Test CA",
    key: ec.EllipticCurvePrivateKey | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    if key is None:
        key = _generate_ec_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA384())
    )
    return key, cert


def generate_signed_cert(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    cn: str = "Test Subject",
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = _generate_ec_key()
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(ca_key, hashes.SHA384())
    )
    return key, cert


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def report_v3_genoa_bytes() -> bytes:
    """Minimal V3 Genoa attestation report binary."""
    return build_report_bytes(
        version=3,
        cpuid_fam_id=0x19,
        cpuid_mod_id=0x11,
        sig_algo=1,
    )


@pytest.fixture()
def report_v5_turin_bytes() -> bytes:
    """Minimal V5 Turin attestation report binary."""
    return build_report_bytes(
        version=5,
        cpuid_fam_id=0x1A,
        cpuid_mod_id=0x00,
        sig_algo=1,
    )


@pytest.fixture()
def report_v2_milan_bytes() -> bytes:
    """Minimal V2 Milan attestation report binary (no CPUID fields)."""
    return build_report_bytes(version=2, sig_algo=1)


@pytest.fixture()
def ca_key_and_cert():
    """Self-signed EC P-384 CA key + certificate."""
    return generate_self_signed_cert("Test ARK")


@pytest.fixture()
def subject_key_and_cert(ca_key_and_cert):
    """EC P-384 certificate signed by the CA."""
    ca_key, ca_cert = ca_key_and_cert
    return generate_signed_cert(ca_key, ca_cert, "Test VCEK")


@pytest.fixture()
def signed_report_and_cert():
    """A report whose TBS is signed by a freshly generated EC P-384 key, plus the matching cert."""
    key, cert = generate_self_signed_cert("Test VCEK Signer")
    raw = build_signed_report_bytes(key, version=3, cpuid_fam_id=0x19, cpuid_mod_id=0x11)
    return raw, cert


@pytest.fixture()
def crl_der(ca_key_and_cert) -> bytes:
    """DER-encoded CRL signed by the CA."""
    ca_key, ca_cert = ca_key_and_cert
    now = datetime.datetime.now(datetime.UTC)
    crl = x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject).last_update(now).next_update(now + datetime.timedelta(days=1)).sign(ca_key, hashes.SHA384())
    return crl.public_bytes(Encoding.DER)

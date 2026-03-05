# SPDX-License-Identifier: MIT

"""
Tests for pysnputils.verify.
"""

from conftest import generate_self_signed_cert
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from pysnputils.types import AttestationReport
from pysnputils.verify import verify_certs, verify_report_signature, verify_signature

# ---------------------------------------------------------------------------
# verify_certs
# ---------------------------------------------------------------------------


class TestVerifyCerts:
    def test_self_signed_valid(self, ca_key_and_cert):
        _, ca_cert = ca_key_and_cert
        assert verify_certs(ca_cert, ca_cert) is True

    def test_signed_by_ca_valid(self, ca_key_and_cert, subject_key_and_cert):
        _, ca_cert = ca_key_and_cert
        _, subj_cert = subject_key_and_cert
        assert verify_certs(subj_cert, ca_cert) is True

    def test_wrong_issuer(self, ca_key_and_cert, subject_key_and_cert):
        _, subj_cert = subject_key_and_cert
        # Subject cert was NOT signed by itself
        assert verify_certs(subj_cert, subj_cert) is False

    def test_unrelated_certs(self):
        _, cert_a = generate_self_signed_cert("A")
        _, cert_b = generate_self_signed_cert("B")
        assert verify_certs(cert_a, cert_b) is False


# ---------------------------------------------------------------------------
# verify_signature
# ---------------------------------------------------------------------------


class TestVerifySignature:
    def test_valid_ecdsa_signature(self, ca_key_and_cert):
        ca_key, ca_cert = ca_key_and_cert
        data = b"test data to sign"
        hash_alg = hashes.SHA384()
        dss_sig = ca_key.sign(data, ec.ECDSA(hash_alg))
        assert verify_signature(dss_sig, data, ca_cert, hash_alg) is True

    def test_invalid_signature(self, ca_key_and_cert):
        _, ca_cert = ca_key_and_cert
        assert verify_signature(b"\x00" * 64, b"data", ca_cert, hashes.SHA384()) is False

    def test_tampered_data(self, ca_key_and_cert):
        ca_key, ca_cert = ca_key_and_cert
        data = b"original"
        hash_alg = hashes.SHA384()
        dss_sig = ca_key.sign(data, ec.ECDSA(hash_alg))
        assert verify_signature(dss_sig, b"tampered", ca_cert, hash_alg) is False


# ---------------------------------------------------------------------------
# verify_report_signature
# ---------------------------------------------------------------------------


class TestVerifyReportSignature:
    def test_valid_report_signature(self, signed_report_and_cert):
        raw, cert = signed_report_and_cert
        report = AttestationReport.from_bytes(raw)
        assert verify_report_signature(report, cert) is True

    def test_tampered_report(self, signed_report_and_cert):
        raw, cert = signed_report_and_cert
        tampered = bytearray(raw)
        tampered[0x04] = 0xFF  # corrupt guest_svn (inside TBS)
        report = AttestationReport.from_bytes(bytes(tampered))
        assert verify_report_signature(report, cert) is False

    def test_wrong_cert(self, signed_report_and_cert):
        raw, _ = signed_report_and_cert
        _, unrelated_cert = generate_self_signed_cert("Unrelated")
        report = AttestationReport.from_bytes(raw)
        assert verify_report_signature(report, unrelated_cert) is False

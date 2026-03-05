# SPDX-License-Identifier: MIT

"""
Tests for pysnputils.fetch.
"""

from unittest.mock import MagicMock, patch

from conftest import build_report_bytes
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from pysnputils.fetch import (
    AMD_KDS_BASE_URL,
    fetch_ca,
    fetch_crl,
    fetch_vcek,
    get_ca_url,
    get_crl_url,
    get_vcek_url,
)
from pysnputils.types import AttestationReport

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_report(version=3, cpuid_fam_id=0x19, cpuid_mod_id=0x11, **kw):
    raw = build_report_bytes(version=version, cpuid_fam_id=cpuid_fam_id, cpuid_mod_id=cpuid_mod_id, **kw)
    return AttestationReport.from_bytes(raw)


def _make_turin_report():
    raw = build_report_bytes(
        version=5,
        cpuid_fam_id=0x1A,
        cpuid_mod_id=0x00,
        chip_id=bytes(range(64)),
        reported_tcb=bytes([10, 11, 12, 13, 0, 0, 0, 14]),
    )
    return AttestationReport.from_bytes(raw)


# ---------------------------------------------------------------------------
# URL generation
# ---------------------------------------------------------------------------


class TestGetVcekUrl:
    def test_genoa_url_format(self):
        report = _make_report()
        url = get_vcek_url(report)
        assert url.startswith(f"{AMD_KDS_BASE_URL}/vcek/v1/Genoa/")
        assert "blSPL=" in url
        assert "teeSPL=" in url
        assert "snpSPL=" in url
        assert "ucodeSPL=" in url
        assert "fmcSPL=" not in url

    def test_genoa_url_contains_full_hwid(self):
        chip = bytes(range(64))
        report = _make_report(chip_id=chip)
        url = get_vcek_url(report)
        assert chip.hex() in url

    def test_turin_url_has_fmc_and_short_hwid(self):
        report = _make_turin_report()
        url = get_vcek_url(report)
        assert url.startswith(f"{AMD_KDS_BASE_URL}/vcek/v1/Turin/")
        assert "fmcSPL=" in url
        hwid_in_url = url.split("/Turin/")[1].split("?")[0]
        assert len(hwid_in_url) == 16

    def test_turin_tcb_values(self):
        report = _make_turin_report()
        url = get_vcek_url(report)
        assert "fmcSPL=10" in url
        assert "blSPL=11" in url
        assert "teeSPL=12" in url
        assert "snpSPL=13" in url
        assert "ucodeSPL=14" in url


class TestGetCaUrl:
    def test_format(self):
        report = _make_report()
        url = get_ca_url(report)
        assert url == f"{AMD_KDS_BASE_URL}/vcek/v1/Genoa/cert_chain"

    def test_turin(self):
        report = _make_turin_report()
        assert get_ca_url(report) == f"{AMD_KDS_BASE_URL}/vcek/v1/Turin/cert_chain"


class TestGetCrlUrl:
    def test_format(self):
        report = _make_report()
        url = get_crl_url(report)
        assert url == f"{AMD_KDS_BASE_URL}/vcek/v1/Genoa/crl"


# ---------------------------------------------------------------------------
# Fetch functions (mocked HTTP)
# ---------------------------------------------------------------------------


class TestFetchVcek:
    def test_returns_certificate(self, ca_key_and_cert):
        _, cert = ca_key_and_cert
        cert_der = cert.public_bytes(Encoding.DER)

        mock_resp = MagicMock()
        mock_resp.content = cert_der
        mock_resp.raise_for_status = MagicMock()

        report = _make_report()
        with patch("pysnputils.fetch.requests.get", return_value=mock_resp) as mock_get:
            result = fetch_vcek(report)
            mock_get.assert_called_once()
            assert isinstance(result, x509.Certificate)
            assert result.subject == cert.subject

    def test_calls_correct_url(self, ca_key_and_cert):
        _, cert = ca_key_and_cert
        mock_resp = MagicMock()
        mock_resp.content = cert.public_bytes(Encoding.DER)
        mock_resp.raise_for_status = MagicMock()

        report = _make_report()
        expected_url = get_vcek_url(report)

        with patch("pysnputils.fetch.requests.get", return_value=mock_resp) as mock_get:
            fetch_vcek(report)
            mock_get.assert_called_once_with(expected_url, verify=True, timeout=10)


class TestFetchCa:
    def test_returns_cert_list(self, ca_key_and_cert):
        _, cert = ca_key_and_cert
        pem = cert.public_bytes(Encoding.PEM)
        two_certs_pem = pem + pem

        mock_resp = MagicMock()
        mock_resp.content = two_certs_pem
        mock_resp.raise_for_status = MagicMock()

        report = _make_report()
        with patch("pysnputils.fetch.requests.get", return_value=mock_resp):
            result = fetch_ca(report)
            assert len(result) == 2
            assert all(isinstance(c, x509.Certificate) for c in result)


class TestFetchCrl:
    def test_returns_crl(self, crl_der):
        mock_resp = MagicMock()
        mock_resp.content = crl_der
        mock_resp.raise_for_status = MagicMock()

        report = _make_report()
        with patch("pysnputils.fetch.requests.get", return_value=mock_resp):
            result = fetch_crl(report)
            assert isinstance(result, x509.CertificateRevocationList)

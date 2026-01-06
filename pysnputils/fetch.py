# SPDX-License-Identifier: MIT

"""
Fetch VCEK certificate chains and CRLs from AMD KDS.
"""

__all__ = [
    "get_vcek_url",
    "get_ca_url",
    "get_crl_url",
    "fetch_vcek",
    "fetch_ca",
    "fetch_crl",
]

import base64
import requests
from cryptography import x509
from pysnputils.types import AttestationReport

# AMD KDS Base URL
AMD_KDS_BASE_URL = "https://kdsintf.amd.com"

# Timeout
DEFAULT_TIMEOUT = 10

# AMD KDS API Endpoints
def get_vcek_url(report: AttestationReport) -> str:
    """
    Get the URL for a VCEK certificate from AMD KDS.

    Args:
        report: AttestationReport

    Returns:
        str
    """
    processor_model = report.processor_model.name.capitalize()
    bl = report.reported_tcb.boot_loader
    tee = report.reported_tcb.tee
    snp = report.reported_tcb.snp
    ucode = report.reported_tcb.microcode

    if processor_model == "Turin":
        fmc = report.reported_tcb.fmc
        hwid = report.chip_id.hex()[0:16] # first 8 octets = 16 hex characters
        return f"{AMD_KDS_BASE_URL}/vcek/v1/{processor_model}/{hwid}?fmcSPL={fmc}&blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={ucode}"

    hwid = report.chip_id.hex() # full 64 octets = 128 hex characters
    return f"{AMD_KDS_BASE_URL}/vcek/v1/{processor_model}/{hwid}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={ucode}"


def get_ca_url(report: AttestationReport) -> str:
    """
    Get the URL for AMD's CA certificates from AMD KDS.

    Args:
        report: AttestationReport

    Returns:
        str
    """
    processor_model = report.processor_model.name.capitalize()
    return f"{AMD_KDS_BASE_URL}/vcek/v1/{processor_model}/cert_chain"


def get_crl_url(report: AttestationReport) -> str:
    """
    Get the URL for a CRL from AMD KDS.

    Args:
        report: AttestationReport

    Returns:
        str
    """
    processor_model = report.processor_model.name.capitalize()
    return f"{AMD_KDS_BASE_URL}/vcek/v1/{processor_model}/crl"


# Fetch Functions
def fetch_vcek(report: AttestationReport, timeout: int = DEFAULT_TIMEOUT) -> x509.Certificate:
    """
    Fetch a VCEK certificate from AMD KDS.

    Args:
        report: AttestationReport

    Returns:
        x509.Certificate
    """
    url = get_vcek_url(report)
    response = requests.get(url, verify=True, timeout=timeout)
    response.raise_for_status()
    vcek_der = base64.b64encode(response.content)
    vcek_pem = "-----BEGIN CERTIFICATE-----\n" + vcek_der.decode("utf-8") + "\n-----END CERTIFICATE-----"
    return x509.load_pem_x509_certificate(vcek_pem.encode("utf-8"))


def fetch_ca(report: AttestationReport, timeout: int = DEFAULT_TIMEOUT) -> list[x509.Certificate]:
    """
    Fetch AMD's CA certificates (ASK + ARK) from AMD KDS.

    Args:
        report: AttestationReport

    Returns:
        list[x509.Certificate]
    """
    url = get_ca_url(report)
    response = requests.get(url, verify=True, timeout=timeout)
    response.raise_for_status()
    ca_pem = response.content
    return x509.load_pem_x509_certificates(ca_pem)


def fetch_crl(report: AttestationReport, timeout: int = DEFAULT_TIMEOUT) -> x509.CertificateRevocationList:
    """
    Fetch a CRL from AMD KDS.

    Args:
        report: AttestationReport

    Returns:
        x509.CertificateRevocationList
    """
    url = get_crl_url(report)
    response = requests.get(url, verify=True, timeout=timeout)
    response.raise_for_status()
    crl_der = response.content
    return x509.load_der_x509_crl(crl_der)

"""
Verify SNP attestation reports and VCEK certificate chains.
"""

import os
from cryptography import x509
from pysnputils.verify import verify_certs, verify_report_signature
from pysnputils.types import AttestationReport

DEFAULT_VCEK_PATH = os.path.join(os.path.dirname(__file__), "vcek.pem")
DEFAULT_ASK_PATH = os.path.join(os.path.dirname(__file__), "ask.pem")
DEFAULT_ARK_PATH = os.path.join(os.path.dirname(__file__), "ark.pem")
DEFAULT_REPORT_PATH = os.path.join(os.path.dirname(__file__), "reportV3.bin")

def main():
    input_vcek_path = input(f"Enter the VCEK path (default: {DEFAULT_VCEK_PATH}): ") or DEFAULT_VCEK_PATH
    input_ask_path = input(f"Enter the ASK path (default: {DEFAULT_ASK_PATH}): ") or DEFAULT_ASK_PATH
    input_ark_path = input(f"Enter the ARK path (default: {DEFAULT_ARK_PATH}): ") or DEFAULT_ARK_PATH
    input_report_path = input(f"Enter the report path (default: {DEFAULT_REPORT_PATH}): ") or DEFAULT_REPORT_PATH
    input_proc_model = input(f"Enter the processor model (default: autodetect): ") or None
    with open(input_vcek_path, "rb") as f:
        vcek = x509.load_pem_x509_certificate(f.read())
    with open(input_ask_path, "rb") as f:
        ask = x509.load_pem_x509_certificate(f.read())
    with open(input_ark_path, "rb") as f:
        ark = x509.load_pem_x509_certificate(f.read())
    with open(input_report_path, "rb") as f:
        report_bin = f.read()
    parsed_report = AttestationReport.from_bytes(report_bin, processor_model=input_proc_model)
    if verify_report_signature(parsed_report, vcek):
        print("Report is signed by VCEK")
    else:
        print("Report is not signed by VCEK")
    if verify_certs(vcek, ask):
        print("VCEK is signed by ASK")
    else:
        print("VCEK is not signed by ASK")
    if verify_certs(ask, ark):
        print("ASK is signed by ARK")
    else:
        print("ASK is not signed by ARK")
    if verify_certs(ark, ark):
        print("ARK is signed by ARK")
    else:
        print("ARK is not signed by ARK")

if __name__ == "__main__":
    main()

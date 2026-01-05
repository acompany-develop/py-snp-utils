#!/usr/bin/env python3

"""
Verify SNP attestation reports and VCEK certificate chains.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography import x509
from pysnputils.verify import verify_certs, verify_report_signature
from pysnputils.types import AttestationReport, ProcessorModel

def main():
    parser = argparse.ArgumentParser(description="Verify SNP report signature and VCEK certificate chain.")
    parser.add_argument(
        "-r",
        "--report",
        dest="report_path",
        required=True,
        help="Path to SNP attestation report",
    )
    parser.add_argument(
        "-c",
        "--certs",
        dest="certs_dir",
        required=True,
        help="Directory containing vcek.pem/ask.pem/ark.pem",
    )
    parser.add_argument(
        "-p",
        "--processor-model",
        dest="processor_model",
        default=None,
        help="""
        Specify processor model (default: autodetect). Examples: Milan, Genoa, Turin.
        For V2 reports, processor model must be specified.
        """,
    )
    args = parser.parse_args()

    certs_dir = Path(args.certs_dir)
    vcek_path = certs_dir / "vcek.pem"
    ask_path = certs_dir / "ask.pem"
    ark_path = certs_dir / "ark.pem"

    with open(vcek_path, "rb") as f:
        vcek = x509.load_pem_x509_certificate(f.read())
    with open(ask_path, "rb") as f:
        ask = x509.load_pem_x509_certificate(f.read())
    with open(ark_path, "rb") as f:
        ark = x509.load_pem_x509_certificate(f.read())
    with open(args.report_path, "rb") as f:
        report_bin = f.read()

    proc_model = ProcessorModel(args.processor_model.capitalize()) if args.processor_model else None
    parsed_report = AttestationReport.from_bytes(report_bin, processor_model=proc_model)

    ok = True

    report_ok = verify_report_signature(parsed_report, vcek)
    print("Report is signed by VCEK" if report_ok else "Report is not signed by VCEK")
    ok &= report_ok

    vcek_ok = verify_certs(vcek, ask)
    print("VCEK is signed by ASK" if vcek_ok else "VCEK is not signed by ASK")
    ok &= vcek_ok

    ask_ok = verify_certs(ask, ark)
    print("ASK is signed by ARK" if ask_ok else "ASK is not signed by ARK")
    ok &= ask_ok

    ark_ok = verify_certs(ark, ark)
    print("ARK is signed by ARK" if ark_ok else "ARK is not signed by ARK")
    ok &= ark_ok

    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()

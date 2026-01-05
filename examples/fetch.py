#!/usr/bin/env python3

"""
Example usage of pysnputils.fetch.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding
from pysnputils.types import AttestationReport, ProcessorModel
from pysnputils.fetch import fetch_vcek, fetch_ca, fetch_crl

def main():
    parser = argparse.ArgumentParser(description="Fetch VCEK/ASK/ARK/CRL from AMD KDS and write them to a directory.")
    parser.add_argument(
        "-i",
        "--in",
        dest="in_path",
        required=True,
        help="Path to SNP attestation report",
    )
    parser.add_argument(
        "-o",
        "--outdir",
        dest="outdir",
        required=True,
        help="Output directory to write certs",
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

    with open(args.in_path, "rb") as f:
        report_bin = f.read()
    proc_model = ProcessorModel(args.processor_model.capitalize()) if args.processor_model else None
    parsed_report = AttestationReport.from_bytes(report_bin, processor_model=proc_model)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    vcek = fetch_vcek(parsed_report)
    with open(outdir / "vcek.pem", "wb") as f:
        f.write(vcek.public_bytes(encoding=Encoding.PEM))
    ca = fetch_ca(parsed_report)
    with open(outdir / "ask.pem", "wb") as f:
        f.write(ca[0].public_bytes(encoding=Encoding.PEM))
    with open(outdir / "ark.pem", "wb") as f:
        f.write(ca[1].public_bytes(encoding=Encoding.PEM))
    crl = fetch_crl(parsed_report)
    with open(outdir / "crl.pem", "wb") as f:
        f.write(crl.public_bytes(encoding=Encoding.PEM))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

"""
Example usage of pysnputils.
"""

from __future__ import annotations

import argparse
import json

from pysnputils.types import AttestationReport, ProcessorModel

def main():
    parser = argparse.ArgumentParser(description="Display SNP attestation report in JSON format.")
    parser.add_argument(
        "-i",
        "--in",
        dest="in_path",
        required=True,
        help="Path to SNP attestation report",
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


    proc_model = ProcessorModel(args.processor_model.capitalize()) if args.processor_model else None
    with open(args.in_path, "rb") as f:
        report_bin = f.read()
    parsed_report = AttestationReport.from_bytes(report_bin, processor_model=proc_model)
    print(json.dumps(parsed_report.to_dict(), indent=4))
    print(f"Processor model: {parsed_report.processor_model}")

if __name__ == "__main__":
    main()

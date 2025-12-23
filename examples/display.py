"""
Example usage of pysnputils.
"""
import json
import os

from pysnputils.types import AttestationReport

DEFAULT_REPORT_PATH = os.path.join(os.path.dirname(__file__), "reportV3.bin")


def main():
    input_path = input(f"Enter the path to the report file (default: {DEFAULT_REPORT_PATH}): ") or DEFAULT_REPORT_PATH
    proc_model = input("Enter the processor model (default: autodetect): ") or None
    with open(input_path, "rb") as f:
        report_bin = f.read()
    parsed_report = AttestationReport.from_bytes(report_bin, processor_model=proc_model)
    print(json.dumps(parsed_report.to_dict(), indent=4))
    print(f"Processor model: {parsed_report.processor_model}")


if __name__ == "__main__":
    main()

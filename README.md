# py-snp-utils

**py-snp-utils** (`pysnputils`) is a Python library for parsing SNP reports, fetching VCEK certificate chains, and verifying them.

## Installation

### Requirements

- Python 3.12+ (Tested with Python 3.12.7)

### Install from repository

```shell
pip install git+https://github.com/acompany-develop/py-snp-utils
```

## Usage

The Python module `pysnputils` consists of the following submodules:
| Submodules | Descriptions |
| :- | :- |
| `types` | attestation report types and parsers |
| `fetch` | functions to fetch VCEK certificate chains from AMD KDS |
| `verify` | functions to verify VCEK certificate chains and SNP reports |

### Example code

```python
from pysnputils.types import AttestationReport
from pysnputils.fetch import fetch_vcek, fetch_ca, fetch_crl

with open("report.bin", "rb") as f:
    report_bin = f.read()

# parse report, auto-detect processor model
report_parsed = AttestationReport.from_bytes(report_bin)

# fetch VCEK cert chain and CRL
vcek = fetch_vcek(parsed_report)
ca = fetch_ca(parsed_report)
ask = ca[0]
ark = ca[1]
crl = fetch_crl(parsed_report)

# verify chain of trust
ok = verify_report_signature(parsed_report, vcek)
ok &= verify_certs(vcek, ask)
ok &= verify_certs(ask, ark)
ok &= verify_certs(ark, ark)
```

### CLI Tools / Example Scripts

The `examples/` directory contains scripts that serve as both usage examples and command-line tools.

| Script | Description |
|--------|-------------|
| `display.py` | Display SNP attestation report in JSON format |
| `fetch.py` | Fetch ARK, ASK, VCEK and CRL from AMD KDS in PEM format |
| `verify.py` | Verify VCEK certificate chain and SNP report signature |

# py-snp-utils

**py-snp-utils** (`pysnputils`) is a Python library for parsing SNP reports, fetching VCEK certificate chains, and verifying them.

## Installation

### Requirements

- Python 3.12+ (Tested with Python 3.12.7)

### Install from repository

```bash
git clone https://github.com/acompany-develop/py-snp-utils
cd py-snp-utils
pip install -e .
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
report_dict = report_parsed.to_dict()

# fetch VCEk cert chain and CRL
vcek = fetch_vcek(parsed_report)
ca = fetch_ca(parsed_report)
ask = ca[0]
ark = ca[1]
crl = fetch_crl(parsed_report)
```

### CLI Tools / Example Scripts

The `examples/` directory contains scripts that serve as both usage examples and (interactive) command-line tools. Sample inputs are also included.

| Script | Description |
|--------|-------------|
| `display.py` | Display SNP attestation report in JSON format |
| `fetch.py` | Fetch ARK, ASK, VCEK and CRL from AMD KDS in PEM format |
| `verify.py` | Verify VCEK certificate chain and SNP report signature |

```bash
# Display SNP report in JSON format
python examples/display.py
# Default input report: ./examples/reportV3.bin
# Default input model: autodetect

# Fetch VCEK cert chain and CRL
python examples/fetch.py
# Default input report: ./examples/reportV3.bin
# Default input model: autodetect
# Default output: ./examples/{ark|ask|vcek|crl}.pem

# Verify VCEK cert chain and SNP report signature
python examples/verify.py
# Default input certs: ./examples/{ark|ask|vcek}.pem
# Default input report: ./examples/reportV3.bin
# Default input model: autodetect
```

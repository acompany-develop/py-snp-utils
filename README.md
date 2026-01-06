# py-snp-utils

![SemVer](https://img.shields.io/badge/pysnputils-0.1.0-blue)
![Python Version](https://img.shields.io/badge/Python-3.12+-blue)
[![License](https://img.shields.io/badge/License-MIT-red)](/LICENSE)

**py-snp-utils** (`pysnputils`) is a Python library for implementing attestation verification of AMD SEV-SNP confidential VMs. It provides functionality to parse SNP reports, fetch VCEK certificate chains and CRLs, and verify attestation evidences.

## Compatibility

### SEV-SNP Revision

- SEV-SNP Firmware ABI Spec: Rev. 1.58 (May 2025)
- KDS Interface Spec: Rev. 1.00 (January 2025)

### Tested Environments

- Ubuntu 24.04.1 + AMD64 (x86_64)
- macOS 15.6.1 + Aarch64

## Getting Started

### Requirements

- Python 3.12+

### Install from Repository

```shell
pip install git+https://github.com/acompany-develop/py-snp-utils.git
```

## What's Inside?

### Submodules

The Python module `pysnputils` consists of the following submodules:
| Submodules | Descriptions |
| :- | :- |
| `types` | attestation report types and parsers |
| `fetch` | functions to fetch VCEK certificate chains from AMD KDS |
| `verify` | functions to verify VCEK certificate chains and SNP reports |

### CLI Tools / Example Scripts

The `examples/` directory contains scripts that serve as both usage examples and command-line tools.

| Script | Description |
|--------|-------------|
| `display.py` | Display SNP attestation report in JSON format |
| `fetch.py` | Fetch ARK, ASK, VCEK and CRL from AMD KDS in PEM format |
| `verify.py` | Verify VCEK certificate chain and SNP report signature |

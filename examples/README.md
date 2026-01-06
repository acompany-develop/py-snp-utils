# Example CLI tools using pysnputils

This directory includes several command-line tools using pysnputils. These are intended to demonstrate the use of pysnputils, whilst also providing standalone utilities for SEV-SNP attestation verification.

## Usage

### Common

```shell
python $SCRIPT_PATH [OPTIONS...]
```

or

```shell
# grant permission to execute
chmod +x $SCRIPT_PATH
$SCRIPT_PATH [OPTIONS...]
```

### display

```shell
python display.py -i $REPORT_PATH [-p $PROCESSOR_MODEL]
```

```shell
python display.py --in $REPORT_PATH [--processor-model $PROCESSOR_MODEL]
```

- `-i, --in`: Path to SNP attestation report
- `-p, --processor-model`: Specify processor model (default: autodetect). For V2 reports, processor model must be specified.

### fetch

```shell
python fetch.py -i $REPORT_PATH -o $CERTS_DIR [-p $PROCESSOR_MODEL]
```

```shell
python fetch.py --in $REPORT_PATH --outdir $CERTS_DIR [--processor-model $PROCESSOR_MODEL]
```

- `-i, --in`: Path to SNP attestation report
- `-o, --outdir`: Output directory to write certs
- `-p, --processor-model`: Specify processor model (default: autodetect). For V2 reports, processor model must be specified.

### verify

```shell
python verify.py -r $REPORT_PATH -c $CERTS_DIR [-p $PROCESSOR_MODEL]
```

```shell
python verify.py --report $REPORT_PATH --certs $CERTS_DIR [--processor-model $PROCESSOR_MODEL]
```

- `-r, --report`: Path to SNP attestation report
- `-c, --certs`: Directory containing vcek.pem/ask.pem/ark.pem
- `-p, --processor-model`: Specify processor model (default: autodetect). For V2 reports, processor model must be specified.

## Notes

- **`-p/--processor-model` is optional**: If omitted, it will attempt to automatically detect the processor model from the report.
  - Automatic detection is supported from report version 3 or later.
  - Report version 2 does not support automatic detection. `-p/--processor-model` must be specified.
- **`fetch.py`**: requires network access to AMD KDS. It writes `vcek.pem`, `ask.pem`, `ark.pem`, and `crl.pem` into `$CERTS_DIR`.
- **`verify.py`**: expects `$CERTS_DIR` to contain `vcek.pem`, `ask.pem`, and `ark.pem`.

## Sample reports

### reportV3.bin

- Report Version: 3
- Processor Model: Genoa

### reportV5.bin

- Report Version: 5
- Processor Model: Milan

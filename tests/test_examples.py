# SPDX-License-Identifier: MIT

"""
Tests for example CLI scripts in examples/.
"""

import datetime
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from conftest import (
    PROJECT_ROOT,
    build_report_bytes,
    generate_self_signed_cert,
    generate_signed_cert,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.serialization import Encoding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_example(name: str):
    """Import an example script as a module."""
    path = PROJECT_ROOT / "examples" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_report(tmp_path: Path, *, version=3, cpuid_fam_id=0x19, cpuid_mod_id=0x11, **kw) -> Path:
    """Write a synthetic report binary and return its path."""
    p = tmp_path / "report.bin"
    p.write_bytes(build_report_bytes(version=version, cpuid_fam_id=cpuid_fam_id, cpuid_mod_id=cpuid_mod_id, **kw))
    return p


def _write_certs(tmp_path: Path):
    """Generate and write PEM certs (vcek.pem, ask.pem, ark.pem) into tmp_path. Returns (ark_key, ark_cert)."""
    ark_key, ark_cert = generate_self_signed_cert("Test ARK")
    ask_key, ask_cert = generate_signed_cert(ark_key, ark_cert, "Test ASK")
    _, vcek_cert = generate_signed_cert(ask_key, ask_cert, "Test VCEK")

    (tmp_path / "ark.pem").write_bytes(ark_cert.public_bytes(Encoding.PEM))
    (tmp_path / "ask.pem").write_bytes(ask_cert.public_bytes(Encoding.PEM))
    (tmp_path / "vcek.pem").write_bytes(vcek_cert.public_bytes(Encoding.PEM))

    return ark_key, ark_cert


# ---------------------------------------------------------------------------
# examples/display.py
# ---------------------------------------------------------------------------


class TestDisplayCli:
    def test_help(self):
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "examples" / "display.py"), "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Display SNP attestation report" in result.stdout

    def test_display_v3_report(self, tmp_path):
        report_path = _write_report(tmp_path)
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "examples" / "display.py"), "-i", str(report_path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        lines = result.stdout.strip().split("\n")
        json_text = "\n".join(lines[:-1])
        data = json.loads(json_text)
        assert data["version"] == 3
        assert "Processor model: Genoa" in lines[-1]

    def test_display_with_processor_model(self, tmp_path):
        report_path = _write_report(tmp_path, version=2)
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "examples" / "display.py"), "-i", str(report_path), "-p", "Milan"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Processor model: Milan" in result.stdout

    def test_display_missing_args(self):
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "examples" / "display.py")],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0


# ---------------------------------------------------------------------------
# examples/fetch.py
# ---------------------------------------------------------------------------


class TestFetchCli:
    def test_help(self):
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "examples" / "fetch.py"), "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Fetch VCEK" in result.stdout

    def test_fetch_writes_certs(self, tmp_path):
        """Test fetch.py by mocking the fetch_* functions at the module level."""
        report_path = _write_report(tmp_path)
        outdir = tmp_path / "certs"

        ark_key, ark_cert = generate_self_signed_cert("ARK")
        ask_key, ask_cert = generate_signed_cert(ark_key, ark_cert, "ASK")
        _, vcek_cert = generate_signed_cert(ask_key, ask_cert, "VCEK")

        now = datetime.datetime.now(datetime.UTC)
        crl = x509.CertificateRevocationListBuilder().issuer_name(ark_cert.subject).last_update(now).next_update(now + datetime.timedelta(days=1)).sign(ark_key, _hashes.SHA384())

        fetch_mod = _load_example("fetch")

        with (
            patch.object(fetch_mod, "fetch_vcek", return_value=vcek_cert),
            patch.object(fetch_mod, "fetch_ca", return_value=[ask_cert, ark_cert]),
            patch.object(fetch_mod, "fetch_crl", return_value=crl),
            patch("sys.argv", ["fetch.py", "-i", str(report_path), "-o", str(outdir)]),
        ):
            fetch_mod.main()

        assert (outdir / "vcek.pem").exists()
        assert (outdir / "ask.pem").exists()
        assert (outdir / "ark.pem").exists()
        assert (outdir / "crl.pem").exists()


# ---------------------------------------------------------------------------
# examples/verify.py
# ---------------------------------------------------------------------------


class TestVerifyCli:
    def test_help(self):
        result = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "examples" / "verify.py"), "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Verify SNP report signature" in result.stdout

    def test_verify_valid_chain(self, tmp_path):
        """Mock verify functions to simulate a passing verification."""
        report_path = _write_report(tmp_path)
        certs_dir = tmp_path / "certs"
        certs_dir.mkdir()
        _write_certs(certs_dir)

        verify_mod = _load_example("verify")

        with (
            patch.object(verify_mod, "verify_report_signature", return_value=True),
            patch.object(verify_mod, "verify_certs", return_value=True),
            patch("sys.argv", ["verify.py", "-r", str(report_path), "-c", str(certs_dir)]),
        ):
            with pytest.raises(SystemExit) as exc_info:
                verify_mod.main()
            assert exc_info.value.code == 0

    def test_verify_invalid_signature(self, tmp_path):
        """Mock verify functions to simulate a failing report signature."""
        report_path = _write_report(tmp_path)
        certs_dir = tmp_path / "certs"
        certs_dir.mkdir()
        _write_certs(certs_dir)

        verify_mod = _load_example("verify")

        with (
            patch.object(verify_mod, "verify_report_signature", return_value=False),
            patch.object(verify_mod, "verify_certs", return_value=True),
            patch("sys.argv", ["verify.py", "-r", str(report_path), "-c", str(certs_dir)]),
        ):
            with pytest.raises(SystemExit) as exc_info:
                verify_mod.main()
            assert exc_info.value.code == 1

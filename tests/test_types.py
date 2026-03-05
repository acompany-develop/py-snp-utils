# SPDX-License-Identifier: MIT

"""
Tests for pysnputils.types.
"""

import pytest
from conftest import build_report_bytes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pysnputils.types import (
    ECDSA_SIGNATURE_SIZE,
    GUEST_POLICY_SIZE,
    PLATFORM_INFO_SIZE,
    TCB_VERSION_SIZE,
    AttestationReport,
    EcdsaSignature,
    GuestPolicy,
    KeyInfo,
    PlatformInfo,
    ProcessorModel,
    ReportVariant,
    SignatureAlgorithm,
    SigningKey,
    TcbVersion,
    detect_processor_model,
    get_bit,
    get_bits,
    report_version_to_variant,
)

# ---- Helper functions --------------------------------------------------------


class TestGetBit:
    def test_bit_zero_set(self):
        assert get_bit(b"\x01", 0) == 1

    def test_bit_zero_unset(self):
        assert get_bit(b"\x02", 0) == 0

    def test_high_bit(self):
        assert get_bit(b"\x80", 7) == 1

    def test_multi_byte(self):
        # 0x0100 in little-endian = b"\x00\x01" → bit 8 is set
        assert get_bit(b"\x00\x01", 8) == 1
        assert get_bit(b"\x00\x01", 0) == 0


class TestGetBits:
    def test_lower_nibble(self):
        assert get_bits(b"\xab", 0, 4) == 0xB

    def test_upper_nibble(self):
        assert get_bits(b"\xab", 4, 8) == 0xA

    def test_cross_byte(self):
        # b"\xFF\x00" → bits 0..7 = 0xFF, bit 8 = 0
        assert get_bits(b"\xff\x00", 0, 8) == 0xFF
        assert get_bits(b"\xff\x00", 4, 12) == 0x0F


# ---- Enum sanity checks -----------------------------------------------------


class TestEnums:
    def test_signature_algorithm(self):
        assert SignatureAlgorithm.ECDSA_P384_SHA384 == 1

    def test_signing_key(self):
        assert SigningKey.VCEK == 0
        assert SigningKey.VLEK == 1
        assert SigningKey.NONE == 7

    def test_report_variant(self):
        assert ReportVariant.V2 == 2
        assert ReportVariant.V3 == 3
        assert ReportVariant.V5 == 5


# ---- report_version_to_variant -----------------------------------------------


class TestReportVersionToVariant:
    @pytest.mark.parametrize(
        "version, expected",
        [
            (2, ReportVariant.V2),
            (3, ReportVariant.V3),
            (4, ReportVariant.V3),
            (5, ReportVariant.V5),
        ],
    )
    def test_valid(self, version, expected):
        assert report_version_to_variant(version) == expected

    @pytest.mark.parametrize("version", [0, 1, 6, 100])
    def test_invalid(self, version):
        with pytest.raises(ValueError, match="invalid or unsupported"):
            report_version_to_variant(version)


# ---- detect_processor_model ---------------------------------------------------


class TestDetectProcessorModel:
    @pytest.mark.parametrize(
        "fam, mod, expected",
        [
            (0x19, 0x01, ProcessorModel.MILAN),
            (0x19, 0x00, ProcessorModel.MILAN),
            (0x19, 0x0F, ProcessorModel.MILAN),
            (0x19, 0x11, ProcessorModel.GENOA),
            (0x19, 0x1F, ProcessorModel.GENOA),
            (0x19, 0xA0, ProcessorModel.GENOA),
            (0x19, 0xAF, ProcessorModel.GENOA),
            (0x1A, 0x00, ProcessorModel.TURIN),
            (0x1A, 0x11, ProcessorModel.TURIN),
        ],
    )
    def test_valid(self, fam, mod, expected):
        assert detect_processor_model(fam, mod) == expected

    def test_invalid_family(self):
        with pytest.raises(ValueError, match="invalid CPU family"):
            detect_processor_model(0x20, 0x00)

    def test_invalid_model_fam19(self):
        with pytest.raises(ValueError, match="invalid CPU model"):
            detect_processor_model(0x19, 0x50)

    def test_invalid_model_fam1a(self):
        with pytest.raises(ValueError, match="invalid CPU model"):
            detect_processor_model(0x1A, 0x20)


# ---- GuestPolicy -------------------------------------------------------------


class TestGuestPolicy:
    def test_from_bytes_basic(self):
        raw = b"\x00" * GUEST_POLICY_SIZE
        gp = GuestPolicy.from_bytes(raw)
        assert gp.abi_minor == 0
        assert gp.abi_major == 0
        assert gp.smt is False

    def test_abi_versions(self):
        raw = bytearray(GUEST_POLICY_SIZE)
        raw[0] = 0x05  # abi_minor
        raw[1] = 0x02  # abi_major
        gp = GuestPolicy.from_bytes(bytes(raw))
        assert gp.abi_minor == 5
        assert gp.abi_major == 2

    def test_bitfields(self):
        raw = bytearray(GUEST_POLICY_SIZE)
        # Set bits: SMT(16), DEBUG(19), CXL_ALLOW(21)
        val = (1 << 16) | (1 << 19) | (1 << 21)
        raw[0:8] = val.to_bytes(8, "little")
        gp = GuestPolicy.from_bytes(bytes(raw))
        assert gp.smt is True
        assert gp.migrate_ma is False
        assert gp.debug is True
        assert gp.single_socket is False
        assert gp.cxl_allow is True
        assert gp.mem_aes_256_xts is False

    def test_page_swap_disabled_v5(self):
        raw = bytearray(GUEST_POLICY_SIZE)
        raw[0:8] = (1 << 25).to_bytes(8, "little")
        gp = GuestPolicy.from_bytes(bytes(raw), report_version=5)
        assert gp.page_swap_disabled is True

    def test_page_swap_disabled_v3_returns_none(self):
        raw = bytearray(GUEST_POLICY_SIZE)
        raw[0:8] = (1 << 25).to_bytes(8, "little")
        gp = GuestPolicy.from_bytes(bytes(raw), report_version=3)
        assert gp.page_swap_disabled is None

    def test_to_dict_keys(self):
        gp = GuestPolicy.from_bytes(b"\x00" * GUEST_POLICY_SIZE)
        d = gp.to_dict()
        expected_keys = {
            "abi_minor",
            "abi_major",
            "smt",
            "migrate_ma",
            "debug",
            "single_socket",
            "cxl_allow",
            "mem_aes_256_xts",
            "rapl_dis",
            "ciphertext_hiding",
            "page_swap_disabled",
        }
        assert set(d.keys()) == expected_keys

    def test_invalid_size(self):
        with pytest.raises(ValueError, match="Invalid GuestPolicy length"):
            GuestPolicy(b"\x00" * 4)


# ---- PlatformInfo ------------------------------------------------------------


class TestPlatformInfo:
    def test_from_bytes_basic(self):
        pi = PlatformInfo.from_bytes(b"\x00" * PLATFORM_INFO_SIZE)
        assert pi.smt_en is False
        assert pi.tsme_en is False

    def test_bitfields(self):
        raw = bytearray(PLATFORM_INFO_SIZE)
        val = (1 << 0) | (1 << 2) | (1 << 4)  # SMT_EN, ECC_EN, CIPHERTEXT_HIDING_DRAM_EN
        raw[0:8] = val.to_bytes(8, "little")
        pi = PlatformInfo.from_bytes(bytes(raw))
        assert pi.smt_en is True
        assert pi.tsme_en is False
        assert pi.ecc_en is True
        assert pi.rapl_dis is False
        assert pi.ciphertext_hiding_dram_en is True

    def test_alias_check_complete_v3(self):
        raw = bytearray(PLATFORM_INFO_SIZE)
        raw[0:8] = (1 << 5).to_bytes(8, "little")
        pi = PlatformInfo.from_bytes(bytes(raw), report_version=3)
        assert pi.alias_check_complete is True

    def test_alias_check_complete_v2_returns_none(self):
        pi = PlatformInfo.from_bytes(b"\x00" * PLATFORM_INFO_SIZE, report_version=2)
        assert pi.alias_check_complete is None

    def test_tio_en_v5(self):
        raw = bytearray(PLATFORM_INFO_SIZE)
        raw[0:8] = (1 << 7).to_bytes(8, "little")
        pi = PlatformInfo.from_bytes(bytes(raw), report_version=5)
        assert pi.tio_en is True

    def test_tio_en_v3_returns_none(self):
        pi = PlatformInfo.from_bytes(b"\x00" * PLATFORM_INFO_SIZE, report_version=3)
        assert pi.tio_en is None

    def test_to_dict_keys(self):
        d = PlatformInfo.from_bytes(b"\x00" * PLATFORM_INFO_SIZE).to_dict()
        expected_keys = {
            "smt_en",
            "tsme_en",
            "ecc_en",
            "rapl_dis",
            "ciphertext_hiding_dram_en",
            "alias_check_complete",
            "tio_en",
        }
        assert set(d.keys()) == expected_keys

    def test_invalid_size(self):
        with pytest.raises(ValueError, match="Invalid PlatformInfo length"):
            PlatformInfo(b"\x00" * 4)


# ---- KeyInfo -----------------------------------------------------------------


class TestKeyInfo:
    def test_from_bytes_vcek(self):
        # bits 2-4 = 0 → VCEK
        ki = KeyInfo.from_bytes(b"\x00\x00\x00\x00")
        assert ki.author_key_en is False
        assert ki.mask_chip_key is False
        assert ki.signing_key == SigningKey.VCEK

    def test_author_key_en(self):
        ki = KeyInfo.from_bytes((1).to_bytes(4, "little"))
        assert ki.author_key_en is True

    def test_mask_chip_key(self):
        ki = KeyInfo.from_bytes((1 << 1).to_bytes(4, "little"))
        assert ki.mask_chip_key is True

    def test_signing_key_vlek(self):
        # VLEK = 1, stored in bits 2-4 → value 1 << 2 = 4
        ki = KeyInfo.from_bytes((1 << 2).to_bytes(4, "little"))
        assert ki.signing_key == SigningKey.VLEK

    def test_signing_key_none(self):
        # NONE = 7, stored in bits 2-4 → value 7 << 2 = 28
        ki = KeyInfo.from_bytes((7 << 2).to_bytes(4, "little"))
        assert ki.signing_key == SigningKey.NONE

    def test_to_dict(self):
        ki = KeyInfo.from_bytes(b"\x00\x00\x00\x00")
        d = ki.to_dict()
        assert d["signing_key"] == "VCEK"

    def test_invalid_size(self):
        with pytest.raises(ValueError, match="Invalid KeyInfo length"):
            KeyInfo(b"\x00\x00")


# ---- TcbVersion --------------------------------------------------------------


class TestTcbVersion:
    def test_pre_turin_layout(self):
        raw = bytearray(TCB_VERSION_SIZE)
        raw[0] = 1  # boot_loader (pre-Turin byte 0)
        raw[1] = 2  # tee (pre-Turin byte 1)
        raw[6] = 3  # snp (pre-Turin byte 6)
        raw[7] = 4  # microcode (byte 7)
        tcb = TcbVersion.from_bytes(bytes(raw), ProcessorModel.GENOA)
        assert tcb.boot_loader == 1
        assert tcb.tee == 2
        assert tcb.snp == 3
        assert tcb.microcode == 4
        assert tcb.fmc is None

    def test_turin_layout(self):
        raw = bytearray(TCB_VERSION_SIZE)
        raw[0] = 10  # fmc (Turin byte 0)
        raw[1] = 11  # boot_loader (Turin byte 1)
        raw[2] = 12  # tee (Turin byte 2)
        raw[3] = 13  # snp (Turin byte 3)
        raw[7] = 14  # microcode (byte 7)
        tcb = TcbVersion.from_bytes(bytes(raw), ProcessorModel.TURIN)
        assert tcb.fmc == 10
        assert tcb.boot_loader == 11
        assert tcb.tee == 12
        assert tcb.snp == 13
        assert tcb.microcode == 14

    def test_to_dict(self):
        tcb = TcbVersion.from_bytes(b"\x00" * TCB_VERSION_SIZE, ProcessorModel.MILAN)
        d = tcb.to_dict()
        assert set(d.keys()) == {"fmc", "boot_loader", "tee", "snp", "microcode"}
        assert d["fmc"] is None

    def test_invalid_size(self):
        with pytest.raises(ValueError, match="Invalid TcbVersion length"):
            TcbVersion(b"\x00" * 4, ProcessorModel.MILAN)


# ---- EcdsaSignature ----------------------------------------------------------


class TestEcdsaSignature:
    def test_from_bytes(self):
        raw = bytearray(ECDSA_SIGNATURE_SIZE)
        raw[0] = 0xAA
        raw[0x48] = 0xBB
        sig = EcdsaSignature.from_bytes(bytes(raw))
        assert sig.sig_r[0] == 0xAA
        assert sig.sig_s[0] == 0xBB

    def test_sig_r_length(self):
        sig = EcdsaSignature.from_bytes(b"\x00" * ECDSA_SIGNATURE_SIZE)
        assert len(sig.sig_r) == 0x48

    def test_sig_s_length(self):
        sig = EcdsaSignature.from_bytes(b"\x00" * ECDSA_SIGNATURE_SIZE)
        assert len(sig.sig_s) == 0x48

    def test_to_dss_signature_roundtrip(self):

        raw = bytearray(ECDSA_SIGNATURE_SIZE)
        r_int = 42
        s_int = 99
        raw[0:0x48] = r_int.to_bytes(0x48, "little")
        raw[0x48:0x90] = s_int.to_bytes(0x48, "little")
        sig = EcdsaSignature.from_bytes(bytes(raw))
        dss = sig.to_dss_signature()
        r_out, s_out = decode_dss_signature(dss)
        assert r_out == r_int
        assert s_out == s_int

    def test_to_dict(self):
        sig = EcdsaSignature.from_bytes(b"\x00" * ECDSA_SIGNATURE_SIZE)
        d = sig.to_dict()
        assert "sig_r" in d and "sig_s" in d

    def test_invalid_size(self):
        with pytest.raises(ValueError, match="Invalid EcdsaSignature length"):
            EcdsaSignature(b"\x00" * 10)


# ---- AttestationReport -------------------------------------------------------


class TestAttestationReport:
    # --- Construction ---------------------------------------------------------

    def test_from_bytes_autodetect_genoa(self, report_v3_genoa_bytes):
        report = AttestationReport.from_bytes(report_v3_genoa_bytes)
        assert report.version == 3
        assert report.processor_model == ProcessorModel.GENOA

    def test_from_bytes_autodetect_turin(self, report_v5_turin_bytes):
        report = AttestationReport.from_bytes(report_v5_turin_bytes)
        assert report.version == 5
        assert report.processor_model == ProcessorModel.TURIN

    def test_from_bytes_explicit_model(self, report_v2_milan_bytes):
        report = AttestationReport.from_bytes(report_v2_milan_bytes, processor_model=ProcessorModel.MILAN)
        assert report.version == 2
        assert report.processor_model == ProcessorModel.MILAN

    def test_v2_without_model_raises(self, report_v2_milan_bytes):
        with pytest.raises(ValueError):
            AttestationReport.from_bytes(report_v2_milan_bytes)

    def test_invalid_size(self):
        with pytest.raises(ValueError, match="Invalid AttestationReport length"):
            AttestationReport(b"\x00" * 100)

    # --- Scalar properties ----------------------------------------------------

    def test_guest_svn(self):
        raw = build_report_bytes(guest_svn=42, version=3, cpuid_fam_id=0x19, cpuid_mod_id=0x11)
        r = AttestationReport.from_bytes(raw)
        assert r.guest_svn == 42

    def test_vmpl(self):
        raw = build_report_bytes(vmpl=2, version=3, cpuid_fam_id=0x19, cpuid_mod_id=0x11)
        r = AttestationReport.from_bytes(raw)
        assert r.vmpl == 2

    def test_signature_algorithm(self, report_v3_genoa_bytes):
        r = AttestationReport.from_bytes(report_v3_genoa_bytes)
        assert r.signature_algorithm == SignatureAlgorithm.ECDSA_P384_SHA384

    # --- Byte-slice properties ------------------------------------------------

    def test_report_data_length(self, report_v3_genoa_bytes):
        r = AttestationReport.from_bytes(report_v3_genoa_bytes)
        assert len(r.report_data) == 64

    def test_measurement_length(self, report_v3_genoa_bytes):
        r = AttestationReport.from_bytes(report_v3_genoa_bytes)
        assert len(r.measurement) == 48

    def test_host_data_length(self, report_v3_genoa_bytes):
        r = AttestationReport.from_bytes(report_v3_genoa_bytes)
        assert len(r.host_data) == 32

    def test_chip_id_length(self, report_v3_genoa_bytes):
        r = AttestationReport.from_bytes(report_v3_genoa_bytes)
        assert len(r.chip_id) == 64

    def test_report_data_content(self):
        rd = bytes(range(64))
        raw = build_report_bytes(report_data=rd, version=3, cpuid_fam_id=0x19, cpuid_mod_id=0x11)
        r = AttestationReport.from_bytes(raw)
        assert r.report_data == rd

    # --- CPUID fields ---------------------------------------------------------

    def test_cpuid_fields_v3(self):
        raw = build_report_bytes(version=3, cpuid_fam_id=0x19, cpuid_mod_id=0x11, cpuid_step=0x05)
        r = AttestationReport.from_bytes(raw)
        assert r.cpuid_fam_id == 0x19
        assert r.cpuid_mod_id == 0x11
        assert r.cpuid_step == 0x05

    def test_cpuid_fields_v2_returns_none(self, report_v2_milan_bytes):
        r = AttestationReport.from_bytes(report_v2_milan_bytes, processor_model=ProcessorModel.MILAN)
        assert r.cpuid_fam_id is None
        assert r.cpuid_mod_id is None
        assert r.cpuid_step is None

    # --- Build / version fields -----------------------------------------------

    def test_build_fields(self):
        raw = build_report_bytes(
            version=3,
            cpuid_fam_id=0x19,
            cpuid_mod_id=0x11,
            current_build=10,
            current_minor=20,
            current_major=30,
            committed_build=1,
            committed_minor=2,
            committed_major=3,
        )
        r = AttestationReport.from_bytes(raw)
        assert r.current_build == 10
        assert r.current_minor == 20
        assert r.current_major == 30
        assert r.committed_build == 1
        assert r.committed_minor == 2
        assert r.committed_major == 3

    # --- Mitigation vectors (v5+) ---------------------------------------------

    def test_mit_vectors_v5(self, report_v5_turin_bytes):
        r = AttestationReport.from_bytes(report_v5_turin_bytes)
        assert r.launch_mit_vector is not None
        assert r.current_mit_vector is not None

    def test_mit_vectors_v3_returns_none(self, report_v3_genoa_bytes):
        r = AttestationReport.from_bytes(report_v3_genoa_bytes)
        assert r.launch_mit_vector is None
        assert r.current_mit_vector is None

    # --- Nested types ---------------------------------------------------------

    def test_guest_policy_type(self, report_v3_genoa_bytes):
        r = AttestationReport.from_bytes(report_v3_genoa_bytes)
        assert isinstance(r.guest_policy, GuestPolicy)

    def test_platform_info_type(self, report_v3_genoa_bytes):
        r = AttestationReport.from_bytes(report_v3_genoa_bytes)
        assert isinstance(r.platform_info, PlatformInfo)

    def test_key_info_type(self, report_v3_genoa_bytes):
        r = AttestationReport.from_bytes(report_v3_genoa_bytes)
        assert isinstance(r.key_info, KeyInfo)

    def test_signature_type(self, report_v3_genoa_bytes):
        r = AttestationReport.from_bytes(report_v3_genoa_bytes)
        assert isinstance(r.signature, EcdsaSignature)

    # --- TBS ------------------------------------------------------------------

    def test_tbs_length(self, report_v3_genoa_bytes):
        r = AttestationReport.from_bytes(report_v3_genoa_bytes)
        assert len(r.tbs) == 0x2A0

    # --- to_dict --------------------------------------------------------------

    def test_to_dict_has_all_keys(self, report_v3_genoa_bytes):
        r = AttestationReport.from_bytes(report_v3_genoa_bytes)
        d = r.to_dict()
        required = {
            "version",
            "guest_svn",
            "guest_policy",
            "family_id",
            "image_id",
            "vmpl",
            "signature_algorithm",
            "current_tcb",
            "platform_info",
            "key_info",
            "report_data",
            "measurement",
            "host_data",
            "id_key_digest",
            "author_key_digest",
            "report_id",
            "report_id_ma",
            "reported_tcb",
            "cpuid_fam_id",
            "cpuid_mod_id",
            "cpuid_step",
            "chip_id",
            "committed_tcb",
            "current_major",
            "current_minor",
            "current_build",
            "committed_major",
            "committed_minor",
            "committed_build",
            "launch_tcb",
            "launch_mit_vector",
            "current_mit_vector",
            "signature",
        }
        assert required.issubset(set(d.keys()))

"""
AMD SEV-SNP Attestation Report Type Definitions.
"""

__all__ = [
    # Constants
    "SNP_ATTESTATION_REPORT_LEN",
    "ECDSA_SIGNATURE_SIZE",
    "TCB_VERSION_SIZE",
    "KEY_INFO_SIZE",
    "GUEST_POLICY_SIZE",
    "PLATFORM_INFO_SIZE",
    # Types
    "SignatureAlgorithm",
    "SigningKey",
    "ReportVariant",
    "GuestPolicy",
    "PlatformInfo",
    "KeyInfo",
    "TcbVersion",
    "EcdsaSignature",
    "AttestationReport",
    # Functions
    "report_version_to_variant",
    "turin_like",
    "detect_processor_model",
]


from dataclasses import dataclass
from enum import IntEnum, StrEnum
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes

# Helper functions
def get_bit(raw: bytes, bit: int) -> int:
    """Get a bit from a byte array."""
    return (int.from_bytes(raw, "little") >> bit) & 1


def get_bits(raw: bytes, begin: int, end: int) -> int:
    """Get bits from a byte array."""
    return (int.from_bytes(raw, "little") >> begin) & ((1 << (end - begin)) - 1)


# Enums
class SignatureAlgorithm(IntEnum):
    """Signature algorithm used in the attestation report."""
    ECDSA_P384_SHA384 = 1


class SigningKey(IntEnum):
    """The key used to sign the attestation report."""
    VCEK = 0
    VLEK = 1
    NONE = 7


class MaskChipId(IntEnum):
    """Chip ID masking options."""
    UNMASKED = 0
    MASKED = 1


class ProcessorModel(StrEnum):
    """Host processor model."""
    MILAN = "Milan"
    GENOA = "Genoa"
    BERGAMO = "Bergamo"
    SIENA = "Siena"
    TURIN = "Turin"


class ReportVariant(IntEnum):
    """Report variant."""
    V2 = 2
    V3 = 3
    V5 = 5


# Functions
def report_version_to_variant(version: int) -> ReportVariant:
    """Convert a report version to a report variant."""
    if version == 2:
        return ReportVariant.V2
    if version in [3, 4]:
        return ReportVariant.V3
    if version == 5:
        return ReportVariant.V5
    raise ValueError(f"invalid or unsupported report version: {version}")


def turin_like(chip_id: bytes) -> bool:
    """Determine if the Chip ID is from a Turin-like processor."""
    if len(chip_id) != 64:
        raise ValueError("invalid chip ID length: expected 64 bytes, got {len(chip_id)}")
    if chip_id[8:64] == bytes(56):
        return True
    return False


def detect_processor_model(report_version: int, cpuid_fam_id: int | None, cpuid_mod_id: int | None, chip_id: bytes) -> ProcessorModel:
    """Detect the processor model from the CPUID family, model, stepping, and Chip ID."""
    if report_version < 3:
        if chip_id == bytes(64):
            raise ValueError("chip ID may be masked; check host's MASK_CHIP_ID setting")
        if turin_like(chip_id):
            return ProcessorModel.TURIN
        raise ValueError("Processor model could not be determined; update SEV-SNP firmware to bump report version")
    if cpuid_fam_id is None:
        raise ValueError("missing CPUID family ID")
    if cpuid_mod_id is None:
        raise ValueError("missing CPUID model ID")
    if cpuid_fam_id == 0x19:
        if cpuid_mod_id in range(0x00, 0x10):
            return ProcessorModel.MILAN
        if cpuid_mod_id in range(0x10, 0x20) or cpuid_mod_id in range(0xA0, 0xB0):
            return ProcessorModel.GENOA
        raise ValueError("invalid CPU model ID")
    if cpuid_fam_id == 0x1A:
        if cpuid_mod_id in range(0x00, 0x12):
            return ProcessorModel.TURIN
        raise ValueError("invalid CPU model ID")
    raise ValueError("invalid CPU family ID")


# Types
GUEST_POLICY_SIZE: int = 8

@dataclass
class GuestPolicy:
    """
    GUEST_POLICY bitfield.
    
    | Bit(s) | Name | Description |
    |--------|------|-------------|
    | 0-7    | ABI_MINOR | ABI minor version |
    | 8-15   | ABI_MAJOR | ABI major version |
    | 16     | SMT | Symmetric Multi-Threading (SMT) must be disabled (0) or is allowed to be enabled (1) |
    | 17     | Reserved | Reserved. Must be 1. |
    | 18     | MIGRATE_MA | Migration agent is allowed (1) or not (0). |
    | 19     | DEBUG | Debug mode is allowed (1) or not (0). |
    | 20     | SINGLE_SOCKET | Single socket is required (1) or not (0). |
    | 21     | CXL_ALLOW | Compute Express Link (CXL) is allowed (1) or not (0). |
    | 22     | MEM_AES_256_XTS | AES-256-XTS is required (1) or not (0). |
    | 23     | RAPL_DIS | Running Average Power Limit (RAPL) is required to be disabled (1) or not (0). |
    | 24     | CIPHERTEXT_HIDING | Ciphertext hiding is required (1) or not (0). |
    | 25     | PAGE_SWAP_DISABLED | Guest access to page swap commands (SNP_PAGE_MOVE, SNP_SWAP_OUT and SNP_SWAP_IN) is required to be disabled (1) or not (0). Report Version 5 or later only. |
    | 26-63  | -     | Reserved. Must be 0. |
    """
    # Fields
    raw: bytes
    report_version: int

    # Methods
    def __init__(self, raw: bytes, report_version: int = 5):
        if len(raw) != GUEST_POLICY_SIZE:
            raise ValueError(f"Invalid GuestPolicy length: expected {GUEST_POLICY_SIZE} bytes, got {len(raw)}")
        self.raw = raw
        self.report_version = report_version

    def to_dict(self) -> dict:
        """Convert GuestPolicy to a dictionary."""
        return {
            "abi_minor": self.abi_minor,
            "abi_major": self.abi_major,
            "smt": self.smt,
            "migrate_ma": self.migrate_ma,
            "debug": self.debug,
            "single_socket": self.single_socket,
            "cxl_allow": self.cxl_allow,
            "mem_aes_256_xts": self.mem_aes_256_xts,
            "rapl_dis": self.rapl_dis,
            "ciphertext_hiding": self.ciphertext_hiding,
            "page_swap_disabled": self.page_swap_disabled,
        }

    # Class Methods
    @classmethod
    def from_bytes(cls, raw: bytes, report_version: int = 5) -> "GuestPolicy":
        """Create GuestPolicy from 8 bytes (64 bits).
        
        Args:
            raw: bytes
            report_version: int (default: 5)

        Returns:
            GuestPolicy
        """
        return cls(raw=raw, report_version=report_version)

    # Properties
    @property
    def abi_minor(self) -> int:
        """ABI minor version."""
        return int.from_bytes(self.raw[0:1], "little")

    @property
    def abi_major(self) -> int:
        """ABI major version."""
        return int.from_bytes(self.raw[1:2], "little")

    @property
    def smt(self) -> bool:
        """Symmetric Multi-Threading is allowed."""
        return bool(get_bit(self.raw, 16))

    @property
    def migrate_ma(self) -> bool:
        """Migration agent is allowed."""
        return bool(get_bit(self.raw, 18))

    @property
    def debug(self) -> bool:
        """Debug mode is allowed."""
        return bool(get_bit(self.raw, 19))

    @property
    def single_socket(self) -> bool:
        """Single socket is required."""
        return bool(get_bit(self.raw, 20))

    @property
    def cxl_allow(self) -> bool:
        """Compute Express Link (CXL) is allowed."""
        return bool(get_bit(self.raw, 21))

    @property
    def mem_aes_256_xts(self) -> bool:
        """AES-256-XTS is required."""
        return bool(get_bit(self.raw, 22))

    @property
    def rapl_dis(self) -> bool:
        """Running Average Power Limit (RAPL) is required to be disabled."""
        return bool(get_bit(self.raw, 23))

    @property
    def ciphertext_hiding(self) -> bool:
        """Ciphertext hiding is required."""
        return bool(get_bit(self.raw, 24))

    @property
    def page_swap_disabled(self) -> bool | None:
        """Guest access to page swap commands (SNP_PAGE_MOVE, SNP_SWAP_OUT and SNP_SWAP_IN) is required to be disabled. Report Version 5 or later only."""
        if self.report_version < 5:
            return None
        return bool(get_bit(self.raw, 25))


PLATFORM_INFO_SIZE: int = 8

@dataclass
class PlatformInfo:
    """
    PLATFORM_INFO bitfield.
    
    | Bit(s) | Name | Description |
    |--------|------|-------------|
    | 0      | SMT_EN | Symmetric Multi-Threading (SMT) is enabled (1) or not (0). |
    | 1      | TSME_EN | Transparent Secure Memory Encryption (TSME) is enabled (1) or not (0). |
    | 2      | ECC_EN  | Error Correction Code (ECC) is enabled (1) or not (0). |
    | 3      | RAPL_DIS | Running Average Power Limit (RAPL) is disabled (1) or not (0). |
    | 4      | CIPHERTEXT_HIDING_DRAM_EN | Ciphertext hiding is required for DRAM (1) or not (0). |
    | 5      | ALIAS_CHECK_COMPLETE | Alias check has completed (1) or not (0). Report Version 3 or later only. |
    | 6      | -        | Reserved |
    | 7      | TIO_EN   | SEV-TIO is enabled (1) or not (0). Report Version 5 or later only. |
    | 8-63   | -        | Reserved |
    """
    # Fields
    raw: bytes
    report_version: int

    # Methods
    def __init__(self, raw: bytes, report_version: int = 5):
        if len(raw) != PLATFORM_INFO_SIZE:
            raise ValueError(
                f"Invalid PlatformInfo length: expected {PLATFORM_INFO_SIZE} bytes, got {len(raw)}"
            )
        self.raw = raw
        self.report_version = report_version

    def _get_bit(self, bit: int) -> int:
        val = int.from_bytes(self.raw, "little")
        return (val >> bit) & 1

    def to_dict(self) -> dict:
        """Convert PlatformInfo to a dictionary."""
        return {
            "smt_en": self.smt_en,
            "tsme_en": self.tsme_en,
            "ecc_en": self.ecc_en,
            "rapl_dis": self.rapl_dis,
            "ciphertext_hiding_dram_en": self.ciphertext_hiding_dram_en,
            "alias_check_complete": self.alias_check_complete,
            "tio_en": self.tio_en,
        }

    # Class Methods
    @classmethod
    def from_bytes(cls, data: bytes, report_version: int = 5) -> "PlatformInfo":
        """Create PlatformInfo from 8 bytes (64 bits).
        
        Args:
            data: bytes
            report_version: int (default: 5)

        Returns:
            PlatformInfo
        """
        return cls(raw=data, report_version=report_version)

    # Properties
    @property
    def smt_en(self) -> bool:
        """Symmetric Multi-Threading is enabled."""
        return bool(get_bit(self.raw, 0))

    @property
    def tsme_en(self) -> bool:
        """Transparent Secure Memory Encryption (TSME) is enabled."""
        return bool(get_bit(self.raw, 1))

    @property
    def ecc_en(self) -> bool:
        """Error Correction Code (ECC) is enabled."""
        return bool(get_bit(self.raw, 2))

    @property
    def rapl_dis(self) -> bool:
        """Running Average Power Limit (RAPL) is disabled."""
        return bool(get_bit(self.raw, 3))

    @property
    def ciphertext_hiding_dram_en(self) -> bool:
        """Ciphertext hiding is required for DRAM."""
        return bool(get_bit(self.raw, 4))

    @property
    def alias_check_complete(self) -> bool | None:
        """Alias check has completed. Report Version 3 or later only."""
        if self.report_version < 3:
            return None
        return bool(get_bit(self.raw, 5))

    @property
    def tio_en(self) -> bool | None:
        """SEV-TIO is enabled. Report Version 5 or later only."""
        if self.report_version < 5:
            return None
        return bool(get_bit(self.raw, 7))


KEY_INFO_SIZE: int = 4

@dataclass
class KeyInfo:
    """
    KEY_INFO bitfield.
    
    | Bit(s) | Name          | Description |
    |--------|---------------|-------------|
    | 0      | AUTHOR_KEY_EN | The digest of the author key is present in AUTHOR_KEY_DIGEST (1) or not (0). |
    | 1      | MASK_CHIP_KEY | 0: Firmware signs the report with VCEK or VLEK, 1: Fill 0s in the SIGNATURE field. |
    | 2-4    | SIGNING_KEY   | The signing key selection (0=VCEK, 1=VLEK, 2-6: Reserved, 7: None) |
    | 5-31   | -             | Reserved. Must be 0. |
    """
    # Fields
    raw: bytes

    # Methods
    def __init__(self, raw: bytes):
        if len(raw) != KEY_INFO_SIZE:
            raise ValueError(
                f"Invalid KeyInfo length: expected {KEY_INFO_SIZE} bytes, got {len(raw)}"
            )
        self.raw = raw

    def to_dict(self) -> dict:
        """Convert KeyInfo to a dictionary."""
        return {
            "author_key_en": self.author_key_en,
            "mask_chip_key": self.mask_chip_key,
            "signing_key": self.signing_key.name,
        }

    # Class Methods
    @classmethod
    def from_bytes(cls, data: bytes) -> "KeyInfo":
        """Create KeyInfo from 4 bytes (32 bits).
        
        Args:
            data: bytes

        Returns:
            KeyInfo
        """
        return cls(raw=data)

    @property
    def author_key_en(self) -> bool:
        """The digest of the author key is present in AUTHOR_KEY_DIGEST."""
        return bool(get_bit(self.raw, 0))

    @property
    def mask_chip_key(self) -> bool:
        """The SIGNATURE field is masked (filled with 0s)"""
        return bool(get_bit(self.raw, 1))

    @property
    def signing_key(self) -> SigningKey:
        """The signing key selection (0=VCEK, 1=VLEK, 2-6: Reserved, 7: None)"""
        return SigningKey(get_bits(self.raw, 2, 5))



TCB_VERSION_SIZE: int = 8

@dataclass
class TcbVersion:
    """
    TCB_VERSION structure.
    
    Each component represents a version number for different parts of the TCB.

    Pre-Turin:
    | Bit(s) | Field       |
    |--------|-------------|
    | 0-7    | BOOT_LOADER |
    | 8-15   | TEE         |
    | 16-47  | RESERVED    |
    | 48-55  | SNP         |
    | 56-63  | MICROCODE   |

    Turin:
    | Bit(s) | Field       |
    |--------|-------------|
    | 0-7    | FMC         |
    | 8-15   | BOOT_LOADER |
    | 16-23  | TEE         |
    | 24-31  | SNP         |
    | 32-55  | RESERVED    |
    | 56-63  | MICROCODE   |
    """
    # Fields
    raw: bytes = bytes(TCB_VERSION_SIZE)
    turin: bool = False

    # Methods
    def __init__(self, raw: bytes, turin: bool = False):
        if len(raw) != TCB_VERSION_SIZE:
            raise ValueError(f"Invalid TcbVersion length: expected {TCB_VERSION_SIZE} bytes, got {len(raw)}")
        self.raw = raw
        self.turin = turin

    def to_dict(self) -> dict:
        """Convert TcbVersion to a dictionary."""
        return {
            "fmc": self.fmc,
            "boot_loader": self.boot_loader,
            "tee": self.tee,
            "snp": self.snp,
            "microcode": self.microcode,
        }

    # Class Methods
    @classmethod
    def from_bytes(cls, data: bytes, turin: bool = False) -> "TcbVersion":
        """Create TcbVersion from 8 bytes (64 bits).
        
        Args:
            data: bytes
            turin: bool (default: False)

        Returns:
            TcbVersion
        """
        return cls(raw=data, turin=turin)

    # Properties
    @property
    def boot_loader(self) -> int:
        """Boot loader version."""
        if self.turin:
            return int.from_bytes(self.raw[1:2], "little")
        return int.from_bytes(self.raw[0:1], "little")

    @property
    def tee(self) -> int:
        """TEE version."""
        if self.turin:
            return int.from_bytes(self.raw[2:3], "little")
        return int.from_bytes(self.raw[1:2], "little")

    @property
    def snp(self) -> int:
        """SNP version."""
        if self.turin:
            return int.from_bytes(self.raw[3:4], "little")
        return int.from_bytes(self.raw[6:7], "little")

    @property
    def microcode(self) -> int:
        """Microcode version."""
        return int.from_bytes(self.raw[7:8], "little")

    @property
    def fmc(self) -> int | None:
        """FMC version. Turin or later models only."""
        if self.turin:
            return int.from_bytes(self.raw[0:1], "little")
        return None


ECDSA_SIGNATURE_SIZE: int = 0x200

@dataclass
class EcdsaSignature:
    """
    ECDSA_SIGNATURE structure.
    
    | Offset | Size  | Name     | Description |
    |--------|-------|----------|-------------|
    | 0x0    | 0x48  | SIG_R    | Signature r component in zero-extended little-endian |
    | 0x48   | 0x48  | SIG_S    | Signature s component in zero-extended little-endian |
    | 0x90   | 0x170 | RESERVED | Reserved. Must be 0. |
    """
    # Fields
    raw: bytes = bytes(ECDSA_SIGNATURE_SIZE)

    # Methods
    def __init__(self, raw: bytes):
        if len(raw) != ECDSA_SIGNATURE_SIZE:
            raise ValueError(f"Invalid EcdsaSignature length: expected {ECDSA_SIGNATURE_SIZE} bytes, got {len(raw)}")
        self.raw = raw

    def to_dict(self) -> dict:
        """Convert EcdsaSignature to a dictionary."""
        return {
            "sig_r": self.sig_r.hex(),
            "sig_s": self.sig_s.hex(),
        }

    def to_dss_signature(self) -> bytes:
        """Convert EcdsaSignature to an ASN.1 encoded DSS signature."""
        int_r = int.from_bytes(self.sig_r, "little")
        int_s = int.from_bytes(self.sig_s, "little")
        return encode_dss_signature(int_r, int_s)

    # Class Methods
    @classmethod
    def from_bytes(cls, data: bytes) -> "EcdsaSignature":
        """Create EcdsaSignature from 512 bytes.
        
        Args:
            data: bytes

        Returns:
            EcdsaSignature
        """
        return cls(raw=data)

    # Properties
    @property
    def sig_r(self) -> bytes:
        """Signature r component in zero-extended little-endian."""
        return self.raw[0:0x48]

    @property
    def sig_s(self) -> bytes:
        """Signature s component in zero-extended little-endian."""
        return self.raw[0x48:0x90]


SNP_ATTESTATION_REPORT_LEN: int = 1184

@dataclass
class AttestationReport:
    """
    AMD SEV-SNP Attestation Report structure.
    
    This structure contains the attestation report returned by the SNP firmware
    in response to a guest request.
    
    Total size: 1184 bytes

    Offsets/Sizes are in bytes. Little-endian order.

    | Offset | Size | Name               | Description |
    |--------|------|--------------------|-------------|
    | 0x00   | 4    | VERSION            | Report version |
    | 0x04   | 4    | GUEST_SVN          | Guest SVN |
    | 0x08   | 8    | GUEST_POLICY       | Guest policy |
    | 0x10   | 16   | FAMILY_ID          | Family ID |
    | 0x20   | 16   | IMAGE_ID           | Image ID |
    | 0x30   | 4    | VMPL               | VMPL |
    | 0x34   | 4    | SIGNATURE_ALGO     | Signature algorithm |
    | 0x38   | 8    | CURRENT_TCB        | Current TCB |
    | 0x40   | 8    | PLATFORM_INFO      | Platform info |
    | 0x48   | 4    | KEY_INFO           | Key info |
    | 0x4C   | 4    | -                  | Reserved. Must be 0. |
    | 0x50   | 64   | REPORT_DATA        | Data provided by the guest at report request |
    | 0x90   | 48   | MEASUREMENT        | Measurement of the guest's memory at launch |
    | 0xC0   | 32   | HOST_DATA          | Data provided by hypervisor at launch |
    | 0xE0   | 48   | ID_KEY_DIGEST      | SHA-384 digest of the ID public key |
    | 0x110  | 48   | AUTHOR_KEY_DIGEST  | SHA-384 digest of the author public key |
    | 0x140  | 32   | REPORT_ID          | Report ID of the guest |
    | 0x160  | 32   | REPORT_ID_MA       | Report ID of the guest's migration agent |
    | 0x180  | 8    | REPORTED_TCB       | Reported TCB |
    | 0x188  | 1    | CPUID_FAM_ID       | CPU family ID. Only available in Report Version 3 or later. |
    | 0x189  | 1    | CPUID_MOD_ID       | CPU model ID. Only available in Report Version 3 or later. |
    | 0x18A  | 1    | CPUID_STEP         | CPUID stepping. Only available in Report Version 3 or later. |
    | 0x18B  | 20   | -                  | Reserved |
    | 0x1A0  | 64   | CHIP_ID            | Chip ID |
    | 0x1E0  | 8    | COMMITTED_TCB      | Committed TCB |
    | 0x1E8  | 1    | CURRENT_BUILD      | Current build number |
    | 0x1E9  | 1    | CURRENT_MINOR      | Current minor number |
    | 0x1EA  | 1    | CURRENT_MAJOR      | Current major number |
    | 0x1EB  | 1    | -                  | Reserved |
    | 0x1EC  | 1    | COMMITTED_BUILD    | Committed build number |
    | 0x1ED  | 1    | COMMITTED_MINOR    | Committed minor number |
    | 0x1EE  | 1    | COMMITTED_MAJOR    | Committed major number |
    | 0x1EF  | 1    | -                  | Reserved |
    | 0x1F0  | 8    | LAUNCH_TCB         | Launch TCB |
    | 0x1F8  | 8    | LAUNCH_MIT_VECTOR  | Launch mitigation vector. Only available in Report Version 5 or later. |
    | 0x200  | 8    | CURRENT_MIT_VECTOR | Current mitigation vector. Only available in Report Version 5 or later. |
    | 0x208  | 152  | -                  | Reserved |
    | 0x2A0  | 512  | SIGNATURE          | ECDSA P-384 with SHA-384 signature |
    """
    # Fields
    raw: bytes = bytes(SNP_ATTESTATION_REPORT_LEN)
    processor_model: ProcessorModel = ProcessorModel.MILAN

    # Methods
    def __init__(self, raw: bytes, processor_model: ProcessorModel | None = None):
        if len(raw) != SNP_ATTESTATION_REPORT_LEN:
            raise ValueError(f"Invalid AttestationReport length: expected {SNP_ATTESTATION_REPORT_LEN} bytes, got {len(raw)}")
        self.raw = raw
        if processor_model is None:
            version = int.from_bytes(raw[0x00:4], "little")
            if version < 3:
                raise ValueError("Report version must be 3+ or processor model must be specified")
            cpuid_fam_id = int.from_bytes(raw[0x188:0x189], "little")
            cpuid_mod_id = int.from_bytes(raw[0x189:0x18A], "little")
            chip_id = raw[0x1A0:0x1E0]
            self.processor_model = detect_processor_model(version, cpuid_fam_id, cpuid_mod_id, chip_id)
        else:
            self.processor_model = ProcessorModel(processor_model)

    def to_dict(self) -> dict:
        """Convert AttestationReport to a dictionary."""
        return {
            "version": self.version,
            "guest_svn": self.guest_svn,
            "guest_policy": self.guest_policy.to_dict(),
            "family_id": self.family_id.hex(),
            "image_id": self.image_id.hex(),
            "vmpl": self.vmpl,
            "signature_algorithm": self.signature_algorithm.name,
            "current_tcb": self.current_tcb.to_dict(),
            "platform_info": self.platform_info.to_dict(),
            "key_info": self.key_info.to_dict(),
            "report_data": self.report_data.hex(),
            "measurement": self.measurement.hex(),
            "host_data": self.host_data.hex(),
            "id_key_digest": self.id_key_digest.hex(),
            "author_key_digest": self.author_key_digest.hex(),
            "report_id": self.report_id.hex(),
            "report_id_ma": self.report_id_ma.hex(),
            "reported_tcb": self.reported_tcb.to_dict(),
            "cpuid_fam_id": self.cpuid_fam_id,
            "cpuid_mod_id": self.cpuid_mod_id,
            "cpuid_step": self.cpuid_step,
            "chip_id": self.chip_id.hex(),
            "committed_tcb": self.committed_tcb.to_dict(),
            "current_major": self.current_major,
            "current_minor": self.current_minor,
            "current_build": self.current_build,
            "committed_major": self.committed_major,
            "committed_minor": self.committed_minor,
            "committed_build": self.committed_build,
            "launch_tcb": self.launch_tcb.to_dict(),
            "launch_mit_vector": self.launch_mit_vector.hex() if self.version >= 5 else None,
            "current_mit_vector": self.current_mit_vector.hex() if self.version >= 5 else None,
            "signature": self.signature.to_dict(),
        }

    # Class Methods
    @classmethod
    def from_bytes(cls, data: bytes, processor_model: ProcessorModel | None = None) -> "AttestationReport":
        """
        Create AttestationReport from 1184 bytes.
        If processor_model is not specified, it will be auto-detected from the report (report version >= 3).
        If processor_model is specified, it will be used instead of auto-detecting from the report.

        Args:
            data: bytes
            processor_model: ProcessorModel | None (default: None)

        Returns:
            AttestationReport
        """
        return cls(raw=data, processor_model=processor_model)

    # Properties
    @property
    def version(self) -> int:
        """Report version."""
        return int.from_bytes(self.raw[0x00:4], "little")

    @property
    def guest_svn(self) -> int:
        """Guest SVN (Security Version Number)."""
        return int.from_bytes(self.raw[0x04:0x08], "little")

    @property
    def guest_policy(self) -> GuestPolicy:
        """Guest policy."""
        return GuestPolicy.from_bytes(self.raw[0x08:0x10], self.version)

    @property
    def family_id(self) -> bytes:
        """Family ID."""
        return self.raw[0x10:0x20]

    @property
    def image_id(self) -> bytes:
        """Image ID."""
        return self.raw[0x20:0x30]

    @property
    def vmpl(self) -> int:
        """VMPL (Virtual Machine Privilege Level)."""
        return int.from_bytes(self.raw[0x30:0x34], "little")

    @property
    def signature_algorithm(self) -> SignatureAlgorithm:
        """Signature algorithm."""
        return SignatureAlgorithm(int.from_bytes(self.raw[0x34:0x38], "little"))

    @property
    def current_tcb(self) -> TcbVersion:
        """Current TCB."""
        turin = self.processor_model == ProcessorModel.TURIN
        return TcbVersion.from_bytes(self.raw[0x38:0x40], turin=turin)

    @property
    def platform_info(self) -> PlatformInfo:
        """Platform information."""
        return PlatformInfo.from_bytes(self.raw[0x40:0x48], self.version)

    @property
    def key_info(self) -> KeyInfo:
        """Key information."""
        return KeyInfo.from_bytes(self.raw[0x48:0x4C])

    @property
    def report_data(self) -> bytes:
        """Report data (64 bytes)."""
        return self.raw[0x50:0x8C]

    @property
    def measurement(self) -> bytes:
        """Measurement (48 bytes)."""
        return self.raw[0x90:0xC0]

    @property
    def host_data(self) -> bytes:
        """Host data (32 bytes)."""
        return self.raw[0xC0:0xE0]

    @property
    def id_key_digest(self) -> bytes:
        """ID key digest (48 bytes)."""
        return self.raw[0xE0:0x110]

    @property
    def author_key_digest(self) -> bytes:
        """Author key digest (48 bytes)."""
        return self.raw[0x110:0x140]

    @property
    def report_id(self) -> bytes:
        """Report ID (32 bytes)."""
        return self.raw[0x140:0x160]

    @property
    def report_id_ma(self) -> bytes:
        """Report ID MA (32 bytes)."""
        return self.raw[0x160:0x180]

    @property
    def reported_tcb(self) -> TcbVersion:
        """Reported TCB."""
        turin = self.processor_model == ProcessorModel.TURIN
        return TcbVersion.from_bytes(self.raw[0x180:0x188], turin=turin)

    @property
    def cpuid_fam_id(self) -> int | None:
        """CPUID family ID. Report Version 3 or later only."""
        if self.version < 3:
            return None
        return int.from_bytes(self.raw[0x188:0x189], "little")

    @property
    def cpuid_mod_id(self) -> int | None:
        """CPUID model ID. Report Version 3 or later only."""
        if self.version < 3:
            return None
        return int.from_bytes(self.raw[0x189:0x18A], "little")

    @property
    def cpuid_step(self) -> int | None:
        """CPUID stepping. Report Version 3 or later only."""
        if self.version < 3:
            return None
        return int.from_bytes(self.raw[0x18A:0x18B], "little")

    @property
    def chip_id(self) -> bytes:
        """Chip ID (64 bytes)."""
        return self.raw[0x1A0:0x1E0]

    @property
    def committed_tcb(self) -> TcbVersion:
        """Committed TCB."""
        turin = self.processor_model == ProcessorModel.TURIN
        return TcbVersion.from_bytes(self.raw[0x1E0:0x1E8], turin=turin)

    @property
    def current_build(self) -> int:
        """Current build."""
        return int.from_bytes(self.raw[0x1E8:0x1E9], "little")

    @property
    def current_minor(self) -> int:
        """Current minor."""
        return int.from_bytes(self.raw[0x1E9:0x1EA], "little")

    @property
    def current_major(self) -> int:
        """Current major."""
        return int.from_bytes(self.raw[0x1EA:0x1EB], "little")

    @property
    def committed_build(self) -> int:
        """Committed build."""
        return int.from_bytes(self.raw[0x1EC:0x1ED], "little")

    @property
    def committed_minor(self) -> int:
        """Committed minor."""
        return int.from_bytes(self.raw[0x1ED:0x1EE], "little")

    @property
    def committed_major(self) -> int:
        """Committed major."""
        return int.from_bytes(self.raw[0x1EE:0x1EF], "little")

    @property
    def launch_tcb(self) -> TcbVersion:
        """Launch TCB."""
        turin = self.processor_model == ProcessorModel.TURIN
        return TcbVersion.from_bytes(self.raw[0x1F0:0x1F8], turin=turin)

    @property
    def launch_mit_vector(self) -> bytes | None:
        """Launch mitigation vector. Report Version 5 or later only."""
        if self.version < 5:
            return None
        return self.raw[0x1F8:0x200]

    @property
    def current_mit_vector(self) -> bytes | None:
        """Current mitigation vector. Report Version 5 or later only."""
        if self.version < 5:
            return None
        return self.raw[0x200:0x208]

    @property
    def signature(self) -> EcdsaSignature:
        """ECDSA signature (512 bytes)."""
        return EcdsaSignature.from_bytes(self.raw[0x2A0:0x4A0])

    @property
    def tbs(self) -> bytes:
        """TBS (To Be Signed) data."""
        return self.raw[0x00:0x2A0]

    @property
    def signature_hash_algorithm(self) -> hashes.HashAlgorithm:
        """Signature hash algorithm."""
        if self.signature_algorithm == SignatureAlgorithm.ECDSA_P384_SHA384:
            return hashes.SHA384()
        raise ValueError(f"Unknown signature hash algorithm: {self.signature_algorithm}")

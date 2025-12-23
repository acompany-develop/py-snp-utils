"""
Verify SNP attestation reports and VCEK certificate chains.
"""

__all__ = [
    "verify_certs",
    "verify_signature",
    "verify_report_signature",
]


from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import SignatureAlgorithmOID
from cryptography.hazmat.primitives import hashes
from pysnputils.types import AttestationReport


def verify_certs(subject_cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """
    Verify that subject certificate was signed by issuer certificate.

    Args:
        subject_cert: x509.Certificate
        issuer_cert: x509.Certificate

    Returns:
        bool
    """
    issuer_pubkey = issuer_cert.public_key()
    sig = subject_cert.signature
    tbs = subject_cert.tbs_certificate_bytes
    hash_alg = subject_cert.signature_hash_algorithm
    oid = subject_cert.signature_algorithm_oid
    try:
        # Key type: RSA
        if isinstance(issuer_pubkey, rsa.RSAPublicKey):
            if oid == SignatureAlgorithmOID.RSASSA_PSS:
                issuer_pubkey.verify(
                    sig,
                    tbs,
                    padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size),
                    hash_alg,
                )
            else:
                issuer_pubkey.verify(sig, tbs, padding.PKCS1v15(), hash_alg)
        # Key type: ECDSA
        elif isinstance(issuer_pubkey, ec.EllipticCurvePublicKey):
            issuer_pubkey.verify(sig, tbs, ec.ECDSA(hash_alg))
        # Key type: Other
        else:
            if hash_alg is None:
                issuer_pubkey.verify(sig, tbs)
            else:
                issuer_pubkey.verify(sig, tbs, hash_alg)
        # If no exception was raised, the certificate is valid
        return True
    except InvalidSignature:
        # If an InvalidSignature exception was raised, the certificate is invalid
        return False


def verify_signature(dss_sig: bytes, tbs: bytes, cert: x509.Certificate, hash_alg: hashes.HashAlgorithm) -> bool:
    """
    Verify a DSS signature.

    Args:
        dss_sig: bytes
        tbs: bytes
        cert: x509.Certificate
        hash_alg: hashes.HashAlgorithm

    Returns:
        bool
    """
    pubkey = cert.public_key()
    try:
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey.verify(
                dss_sig,
                tbs,
                padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size),
                hash_alg,
            )
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(dss_sig, tbs, ec.ECDSA(hash_alg))
        else:
            pubkey.verify(dss_sig, tbs, hash_alg)
        return True
    except InvalidSignature:
        return False


def verify_report_signature(report: AttestationReport, vcek: x509.Certificate) -> bool:
    """
    Verify a report signature.

    Args:
        report: AttestationReport
        vcek: x509.Certificate

    Returns:
        bool
    """
    return verify_signature(report.signature.to_dss_signature(), report.tbs, vcek, report.signature_hash_algorithm)

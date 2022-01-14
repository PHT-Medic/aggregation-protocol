from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def derive_shared_key(private_key: EllipticCurvePrivateKey, public_key: EllipticCurvePublicKey,
                      data: bytes = None) -> bytes:
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    if data:
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=data
        ).derive(shared_key)
        return derived_key
    return shared_key


def load_public_key(public_key_hex: str) -> EllipticCurvePublicKey:
    public_key_bytes = bytes.fromhex(public_key_hex)
    return load_pem_public_key(public_key_bytes)


def load_private_key(private_key_hex: str) -> EllipticCurvePrivateKey:
    private_key_bytes = bytes.fromhex(private_key_hex)
    private_key = load_pem_private_key(
        private_key_bytes,
        password=None
    )
    return private_key

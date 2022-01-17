from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


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

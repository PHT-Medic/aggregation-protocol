from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def derive_shared_key(private_key: EllipticCurvePrivateKey, public_key: EllipticCurvePublicKey,
                      length: int = 32) -> bytes:
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=None,
    ).derive(shared_key)
    return derived_key

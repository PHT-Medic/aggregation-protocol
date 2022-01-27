from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def derive_shared_key(private_key: EllipticCurvePrivateKey, public_key: EllipticCurvePublicKey,
                      length: int = 32) -> bytes:
    """
    Derive a shared key of the given length from an elliptic curve private key and a public key.
    :param private_key: elliptic curve private key
    :param public_key: elliptic curve public key
    :param length: byte length of the derived key
    :return:
    """
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=None,
    ).derive(shared_key)
    return derived_key

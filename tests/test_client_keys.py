import pytest
from protocol.models.client_keys import ClientKeys
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKeyWithSerialization as ECPrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes


def test_client_keys_init():
    """
    Test ClientKeys class initialization
    """
    keys = ClientKeys()
    assert keys.sharing_key
    assert keys.cipher_key

    priv_key_1 = ec.generate_private_key(ec.SECP384R1())
    priv_key_2 = ec.generate_private_key(ec.SECP384R1())

    keys = ClientKeys(priv_key_1, priv_key_2)
    assert keys.cipher_key == priv_key_1
    assert keys.sharing_key == priv_key_2

    with pytest.raises(ValueError):
        keys = ClientKeys(signing_key=priv_key_1)
    with pytest.raises(ValueError):
        keys = ClientKeys(verification_keys=["1", "2"])

    with pytest.raises(ValueError):
        keys = ClientKeys(1, 2)

    keys = ClientKeys(signing_key=priv_key_1, verification_keys=["1", "2"])

    assert keys.signing_key == priv_key_1
    assert keys.sharing_key
    assert keys.cipher_key


def test_client_keys_hex():
    priv_key_1 = ec.generate_private_key(ec.SECP384R1())
    priv_key_2 = ec.generate_private_key(ec.SECP384R1())

    pub_key_1 = priv_key_1.public_key()
    pub_key_2 = priv_key_2.public_key()

    keys = ClientKeys(priv_key_1, priv_key_2)

    private_hex_1 = priv_key_1.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()

    private_hex_2 = priv_key_2.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()

    public_hex_1 = pub_key_1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).hex()
    public_hex_2 = pub_key_2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).hex()

    assert keys.hex_cipher_key == private_hex_1
    assert keys.hex_sharing_key == private_hex_2

    assert keys.hex_cipher_key_public == public_hex_1
    assert keys.hex_sharing_key_public == public_hex_2

    keys = ClientKeys(private_hex_1, private_hex_2)

    assert keys.hex_cipher_key == private_hex_1
    assert keys.hex_sharing_key == private_hex_2


def test_client_keys_key_broadcast():
    keys = ClientKeys()
    broadcast = keys.key_broadcast()

    assert broadcast.cipher_public_key == keys.hex_cipher_key_public
    assert broadcast.sharing_public_key == keys.hex_sharing_key_public

    with pytest.raises(NotImplementedError):
        keys = ClientKeys(signing_key=ec.generate_private_key(ec.SECP384R1()), verification_keys=["1", "2"])
        keys.key_broadcast()

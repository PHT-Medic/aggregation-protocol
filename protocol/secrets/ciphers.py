import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKeyWithSerialization as ECPubKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKeyWithSerialization as ECPrivateKey

from protocol.models.secrets import Cipher, KeyShare, SeedShare
from protocol.secrets.key_agreement import derive_shared_key


def generate_encrypted_cipher(sender: str,
                              private_key: ECPrivateKey,
                              recipient: str,
                              recipient_key: ECPubKey,
                              key_share: KeyShare,
                              seed_share: SeedShare) -> str:
    """
    Create an encrypted cipher for the recipient. The cipher contains the recipient's secret shares of the sender's
    random seed and private sharing key and is encrypted with a symmetric Fernet key, derived from the
    private key of the sender and the public key of the recipient. The cipher is then serialized as a hex string.

    :param sender: user id of the sender
    :param private_key: private key of the sender
    :param recipient: user id of the recipient
    :param recipient_key: public key of the recipient
    :param key_share: a shamir share of the private sharing key addressed to the recipient
    :param seed_share: a shamir share of the random seed addressed to the recipient
    :return: the encrypted serialized cipher in hex format
    """
    # derive the shared key with the public key of the recipient and private key of the sender
    secret = derive_shared_key(private_key, recipient_key)

    # Setup fernet with the key for symmetric encryption
    fernet = Fernet(base64.b64encode(secret))

    # Set up the cipher and encrypt it
    cipher = Cipher(
        recipient=recipient,
        sender=sender,
        key_share=key_share,
        seed_share=seed_share,
    )
    cypher_bytes = cipher.json().encode("utf-8")
    encrypted_cypher = fernet.encrypt(cypher_bytes)
    del fernet

    return encrypted_cypher.hex()


def decrypt_cipher(recipient: str,
                   recipient_key: ECPrivateKey,
                   sender: str,
                   sender_key: ECPubKey,
                   encrypted_cypher: str) -> Cipher:
    """
    Decrypts an encrypted cipher received from a peer via the server. The cipher is decrypted with a symmetric Fernet
    key, derived from the private key of the recipient and the public key of the sender. Validates that the decrypted
    cipher is valid, belongs to the recipient and was sent by the sender.

    :param recipient: the user id of the recipient
    :param recipient_key: the private key of the recipient
    :param sender: the user id of the sender
    :param sender_key: the public key of the sender
    :param encrypted_cypher: the cipher encrypted by the sender for the recipient, in HEX format
    :return: the decrypted cipher

    """
    # derive the shared key with the public key of the recipient and private key of the sender
    secret = derive_shared_key(recipient_key, sender_key)


    # Setup fernet with the key for symmetric encryption
    fernet = Fernet(base64.b64encode(secret))

    # Decrypt the cypher
    cypher_bytes = bytes.fromhex(encrypted_cypher)
    cypher_bytes = fernet.decrypt(cypher_bytes)
    # Parse the cypher
    cipher = Cipher.parse_raw(cypher_bytes)
    # Check that the cypher is valid
    if not cipher.recipient == recipient:
        raise ValueError("Cipher recipient does not match the recipient")
    if not cipher.sender == sender:
        raise ValueError("Cipher sender does not match the sender")

    return cipher

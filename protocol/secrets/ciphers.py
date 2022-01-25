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
    # derive the shared key with the public key of the recipient and private key of the sender
    secret = derive_shared_key(private_key, recipient_key)

    # Setup fernet with the key for symmetric encryption
    fernet = Fernet(base64.b64encode(secret))

    # Setup the cipher and encrypt it
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

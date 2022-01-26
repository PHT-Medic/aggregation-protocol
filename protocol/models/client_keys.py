from typing import Union, List
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKeyWithSerialization as ECPubKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKeyWithSerialization as ECPrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel

from protocol.models.client_messages import ClientKeyBroadCast
from protocol.models import HexString
from protocol.secrets import create_key_shares


class KeyShare(BaseModel):
    """
    A key share for a participant
    """
    recipient: Union[int, str]
    segments: List[HexString]


class KeyShares(BaseModel):
    shares: List[KeyShare]


class ClientKeys:
    cipher_key: ECPrivateKey
    sharing_key: ECPrivateKey
    signing_key: ECPrivateKey = None
    verification_keys: List[ECPubKey] = None  # todo this needs certificates

    def __init__(self,
                 cipher_key: Union[ECPrivateKey, str] = None,
                 sharing_key: Union[ECPrivateKey, str] = None,
                 signing_key: Union[ECPrivateKey, str] = None,
                 verification_keys: List[Union[ECPubKey, str]] = None):

        # validate signing and verification key arguments
        if not (signing_key or verification_keys):
            # print("No signing or verification keys given, protocol not secure against adversarial server")
            pass
        elif signing_key and not verification_keys:
            raise ValueError("Signing key given but no verification keys")
        elif not signing_key and verification_keys:
            raise ValueError("Verification keys given but no signing key")
        else:
            self.signing_key = signing_key
            self.verification_keys = verification_keys

        # validate/generate cipher key
        if not cipher_key:
            self.cipher_key = self._generate_private_key()
        else:
            self.cipher_key = self._process_key_parameter(cipher_key)

        # validate/generate sharing key
        if not sharing_key:
            self.sharing_key = self._generate_private_key()
        else:
            self.sharing_key = self._process_key_parameter(sharing_key)

    def key_broadcast(self) -> ClientKeyBroadCast:

        broadcast_dict = {
            "cipher_public_key": self.hex_cipher_key_public,
            "sharing_public_key": self.hex_sharing_key_public
        }
        if self.signing_key and self.verification_keys:
            # todo
            # broadcast_dict["signature"] = self.sign_keys()
            raise NotImplementedError("Signing and verification keys not implemented")

        broadcast = ClientKeyBroadCast(**broadcast_dict)
        return broadcast

    def create_key_shares(self, n: int, k: int = 3) -> List[KeyShare]:
        shares = create_key_shares(self.hex_sharing_key, n, k)
        return shares

    def _process_key_parameter(self, input_key: Union[ECPrivateKey, str]) -> ECPrivateKey:
        # parse from hex string
        if isinstance(input_key, str):
            return self._load_private_key_from_hex(input_key)
        # return instance directly
        elif isinstance(input_key, ECPrivateKey):
            return input_key
        else:
            raise ValueError(f"Invalid key format: {type(input_key)}")

    @property
    def hex_signing_key(self) -> str:
        return self._serialize_private_key_to_hex(self.signing_key)

    @property
    def hex_sharing_key(self) -> str:
        return self._serialize_private_key_to_hex(self.sharing_key)

    @property
    def hex_cipher_key(self) -> str:
        return self._serialize_private_key_to_hex(self.cipher_key)

    @property
    def signing_key_public(self) -> ECPubKey:
        return self.signing_key.public_key()

    @property
    def sharing_key_public(self) -> ECPubKey:
        return self.sharing_key.public_key()

    @property
    def cipher_key_public(self) -> ECPubKey:
        return self.cipher_key.public_key()

    @property
    def hex_signing_key_public(self) -> str:
        return self._serialize_public_key_to_hex(self.signing_key_public)

    @property
    def hex_sharing_key_public(self) -> str:
        return self._serialize_public_key_to_hex(self.sharing_key_public)

    @property
    def hex_cipher_key_public(self) -> str:
        return self._serialize_public_key_to_hex(self.cipher_key_public)

    @staticmethod
    def _generate_private_key() -> ECPrivateKey:
        return ec.generate_private_key(ec.SECP384R1())

    @staticmethod
    def _load_private_key_from_hex(key: str):
        private_key = serialization.load_pem_private_key(bytes.fromhex(key), password=None)
        return private_key

    @staticmethod
    def _serialize_private_key_to_hex(key: ECPrivateKey) -> str:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()

    @staticmethod
    def _serialize_public_key_to_hex(key: ECPubKey) -> str:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()

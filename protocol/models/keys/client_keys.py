import math
from typing import Union, List, Tuple

from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKeyWithSerialization as ECPubKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKeyWithSerialization as ECPrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


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
        if not (signing_key and verification_keys):
            print("No signing of verification keys given, protocol not secure against adversarial server")
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

    def _process_key_parameter(self, input_key: Union[ECPrivateKey, str]) -> ECPrivateKey:
        # parse from hex string
        if isinstance(input_key, str):
            return self._load_private_key_from_hex(input_key)
        # return instance directly
        elif isinstance(input_key, ECPrivateKey):
            return input_key
        else:
            raise ValueError(f"Invalid key format: {type(input_key)}")

    def create_key_shares(self, n: int, t: int = 3) -> List[List[Tuple[int, bytes]]]:
        sharing_key_bytes = bytes.fromhex(self.hex_sharing_key)
        blocks = math.floor(len(sharing_key_bytes) / 16.0)
        block_shares = []
        for i in range(blocks):
            key_block = sharing_key_bytes[i * 16: (i + 1) * 16]
            block = self._share_secret_pycryptodome(key_block, t, n)
            block_shares.append(block)
        # Add the incomplete block
        remainder = sharing_key_bytes[blocks * 16:]
        pad_size = 16 - len(remainder)
        remainder += b"\0" * pad_size
        block_shares.append(self._share_secret_pycryptodome(remainder, t, n))

        return block_shares

    @staticmethod
    def _share_secret_pycryptodome(secret: bytes, t: int, n: int):
        if len(secret) < 16:
            padded_secret = secret + b"\0" * (16 - len(secret))
            shares = Shamir.split(t, n, padded_secret, ssss=False)
            return shares
        shares = Shamir.split(t, n, secret, ssss=False)
        return shares

    @staticmethod
    def _combine_secret_pycryptodome(shares: List[Tuple[int, bytes]]) -> bytes:
        secret = Shamir.combine(shares, ssss=False)
        return secret

    def recover_sharing_key(self, shares: List[List[Tuple[int, bytes]]]) -> str:
        recovered = ""
        for block in shares:
            recovered += self._combine_secret_pycryptodome(block).hex()

        # remove padding (last 14 bytes/28 hex chars in current implementation)
        # TODO improve this hack
        recovered = recovered[:-28]

        return recovered

    def derive_shared_key(self, private_key: ECPrivateKey, public_key: ECPubKey,
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
            format=serialization.PublicFormat.PKCS1
        ).hex()

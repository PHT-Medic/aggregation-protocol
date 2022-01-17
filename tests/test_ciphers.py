from protocol.secrets.ciphers import generate_encrypted_cipher, decrypt_cipher
from protocol.models.client_keys import ClientKeys


def test_cipher_generation():
    keys_1 = ClientKeys()
    keys_2 = ClientKeys()




import pytest
from protocol.client import ClientProtocol


def test_protocol_setup():
    protocol = ClientProtocol()
    keys = protocol.setup()
    assert keys.hex_sharing_key
    assert keys.hex_cipher_key


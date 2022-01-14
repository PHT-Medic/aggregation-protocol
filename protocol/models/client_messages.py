from typing import Optional, List, Union

from pydantic import BaseModel


class ClientKeyBroadCast(BaseModel):
    """
    The client key broadcast message is sent by the client to the server.
    The client broadcasts the public keys and an optional signature of the public keys.
    Keys are encoded in hex format
    """
    cipher_public_key: str
    sharing_public_key: str
    signature: Optional[str] = None

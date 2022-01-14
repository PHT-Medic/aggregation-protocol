from pydantic import BaseModel
from typing import Union, List, Optional
from protocol.models import HexString


class KeyShare(BaseModel):
    """
    A key share for a participant
    """
    shamir_index: int
    segments: List[HexString]


class SeedShare(BaseModel):
    """
    A seed share for a participant
    """
    shamir_index: int
    seed: HexString


class SecretShares(BaseModel):
    key_shares: List[KeyShare]
    seed_shares: List[SeedShare]


class ShareKeysMessage(BaseModel):
    """
    Message sent to the participants to share their keys
    """
    user_id: str
    recipient: str
    secret_shares: SecretShares

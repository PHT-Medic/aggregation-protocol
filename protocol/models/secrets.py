from pydantic import BaseModel
from typing import Union, List
from protocol.models import HexString


class KeyShare(BaseModel):
    """
    A key share for a participant
    """
    recipient: int
    segments: List[HexString]


class SeedShare(BaseModel):
    """
    A seed share for a participant
    """
    recipient: int
    seed: HexString


class SecretShares(BaseModel):
    key_shares: List[KeyShare]
    seed_shares: List[SeedShare]

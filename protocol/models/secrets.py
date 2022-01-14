from pydantic import BaseModel
from typing import Union, List
from protocol.models import HexString


class KeyShare(BaseModel):
    """
    A key share for a participant
    """
    recipient: int
    segments: List[HexString]


class KeyShares(BaseModel):
    shares: List[KeyShare]

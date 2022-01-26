from typing import Optional, List, Union

from pydantic import BaseModel
from protocol.models.client_messages import ClientKeyBroadCast
from protocol.models import HexString


class BroadCastClientKeys(BaseModel):
    user_id: Union[int, str]
    broadcast: ClientKeyBroadCast


class ServerKeyBroadcast(BaseModel):
    """
    Broadcast the keys of users registered in round 1 of the protocol.
    """

    participants: List[BroadCastClientKeys]


class UserCipher(BaseModel):
    """
    Broadcast the ciphers of users registered in round 1 of the protocol.
    """

    sender: Union[int, str]
    receiver: Union[int, str]
    cipher: HexString


class ServerCipherBroadcast(BaseModel):
    ciphers: List[UserCipher]


class Round4Participant(BaseModel):
    """
    Broadcast the ciphers of users registered in round 1 of the protocol.
    """

    user_id: Union[int, str]
    signature: Optional[HexString] = None


class ServerUnmaskBroadCast(BaseModel):
    """
    Broadcast the participants of round 4 of the protocol to the users
    """

    participants: List[Round4Participant]


class AggregatedParameters(BaseModel):
    """
    Broadcast the aggregated parameters of the protocol to the users
    """

    params: List[float]

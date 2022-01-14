from typing import Optional, List, Union

from pydantic import BaseModel
from protocol.models.client_messages import ClientKeyBroadCast


class BroadCastClientKeys(ClientKeyBroadCast):
    user_id: Union[int, str]


class ServerKeyBroadcast(BaseModel):
    """
    Broadcast the keys of users registered in round 1 of the protocol.
    """

    participants: List[BroadCastClientKeys]

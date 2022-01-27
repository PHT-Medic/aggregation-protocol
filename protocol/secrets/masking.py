import os
from typing import List

import numpy as np
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

from protocol.models.client_keys import ClientKeys
from protocol.models.server_messages import BroadCastClientKeys
from protocol.secrets.key_agreement import derive_shared_key
from protocol.secrets.util import load_public_key


def create_mask(user_id: str, user_keys: ClientKeys, participants: List[BroadCastClientKeys], seed: str,
                n_params: int) -> np.ndarray:
    """
    Generate a mask for a user based on the broadcast messages participants and the user's private random seed.
    :param user_id: id of the user
    :param user_keys: key pair for the user
    :param participants: participants public keys with which to generate the shared mask
    :param seed: hex random seed to expand into a private mask
    :param n_params: size of the mask
    :return: numpy array of the mask
    """
    private_mask = _generate_private_mask(seed, n_params)
    mask = generate_user_masks(private_mask, user_id, user_keys, participants, n_params)

    return mask


def _generate_private_mask(seed: str, n_items: int) -> np.ndarray:
    """
    Expand the seed into a private mask vector.
    :param seed: hex seed
    :param n_items: size of the mask
    :return:
    """
    seed = integer_seed_from_hex(seed)
    return expand_seed(seed, n_items)


def generate_user_masks(private_mask: np.ndarray, user_id: str, user_keys: ClientKeys,
                        participants: List[BroadCastClientKeys],
                        n_params: int) -> np.ndarray:
    """
    For each other participant, generate a shared mask with the user's private mask and the participant's public key.

    :param private_mask: the private mask based on the user's seed
    :param user_id: the id of the user
    :param user_keys: the user's key pair
    :param participants: the public keys and id's of the other participants
    :param n_params: the size of the mask
    :return: numpy array of final mask containing the seed based mask and the shared masks from the other participants
    """
    user_index = len(participants)
    for i, participant in enumerate(participants):
        # set the user index when the id matches the broadcast id
        if participant.user_id == user_id:
            user_index = i

        else:
            # load public key from broadcast
            public_key = load_public_key(participant.broadcast.sharing_public_key)
            # multiplier for mask based on index in list
            if i > user_index:
                private_mask -= generate_shared_mask(user_keys.sharing_key, public_key, n_params)
            else:
                private_mask += generate_shared_mask(user_keys.sharing_key, public_key, n_params)

    return private_mask


def generate_shared_mask(private_key: EllipticCurvePrivateKey, public_key: EllipticCurvePublicKey,
                         n_items: int) -> np.ndarray:
    """
    Generate a shared mask between two users, with the random seed derived from a public and private key
    :param private_key: private key of the user
    :param public_key: public key of the other user
    :param n_items: size of the mask
    :return:
    """
    # derive the key and transform into random seed
    shared_key = derive_shared_key(private_key, public_key, length=4)
    seed = integer_seed_from_hex(shared_key.hex())

    # generate the random vector
    mask = expand_seed(seed, n_items=n_items)

    return mask


def expand_seed(seed: int, n_items: int) -> np.ndarray:
    """
    Expand the seed into a random vector of the given size.
    :param seed:
    :param n_items:
    :return:
    """
    np.random.seed(seed)

    mask = np.random.random(n_items)

    return mask


def generate_random_seed() -> str:
    return os.urandom(4).hex()


def integer_seed_from_hex(hex_seed: str) -> int:
    return int(hex_seed, 16)

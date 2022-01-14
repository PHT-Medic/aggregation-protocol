import itertools
from typing import List, Tuple

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKeyWithSerialization as ECPrivateKey
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives import serialization

from protocol.models.secrets import KeyShares, KeyShare

# Number of sharing key chunks
NUM_KEY_CHUNKS = 20
SHAMIR_SIZE = 16
KEY_BYTES = 306


def create_key_shares(hex_sharing_key: str, n: int, k: int) -> KeyShares:
    key_bytes = bytes.fromhex(hex_sharing_key)
    # chunk the key
    key_chunks = _chunk_key_bytes(key_bytes)
    # create shares from chunks
    chunked_shares = _create_shares_from_chunks(key_chunks, n, k)
    # distribute the chunked shares to the users and create the KeyShares object
    key_shares = _distribute_chunked_shares(chunked_shares)
    # print(segments)
    return key_shares


def combine_key_shares(shares: List[KeyShare], k: int = 3) -> bytes:
    if len(shares) < k:
        raise ValueError(f"Not enough shares to combine. Found {len(shares)} shares, but need at least {k}.")

    segmented_shares = [_process_key_segment(share) for share in shares]
    private_bytes = _process_chunked_shares(segmented_shares)

    return private_bytes


def _process_chunked_shares(chunked_shares: List[List[Tuple[int, bytes]]]) -> bytes:
    zipped_shares = zip(*chunked_shares)
    combined_shares = [list(chunk) for chunk in zipped_shares]

    # combine the shares
    combined_shares = [Shamir.combine(share_list, ssss=False) for share_list in combined_shares]
    # todo improve this
    # remove the padding
    combined_shares[-1] = combined_shares[-1][:KEY_BYTES % SHAMIR_SIZE]

    key = b"".join(list(combined_shares))
    return key


def _process_key_segment(key_share: KeyShare) -> List[Tuple[int, bytes]]:
    shamir_shares = [(key_share.recipient, segment.get_bytes()) for segment in key_share.segments]
    return shamir_shares


def _distribute_chunked_shares(chunked_shares: List[List[Tuple[int, bytes]]]) -> KeyShares:
    # create dictionary with user ids as key and the hex conversion of the initial share as initial value
    segment_dict = {user_id: [first_chunk.hex()] for user_id, first_chunk in chunked_shares[0]}

    # Start from index 1 as the first item has already been processed
    for chunk_shares in chunked_shares[1:]:
        for user_id, share in chunk_shares:
            # append the hex conversion of the share to the list of segments
            segment_dict[user_id].append(share.hex())

    # convert the dictionary to a list of Keyshare
    key_shares = []
    for user_id, share_segment in segment_dict.items():
        key_shares.append(KeyShare(recipient=user_id, segments=share_segment))

    return KeyShares(shares=key_shares)


def _chunk_key_bytes(key_bytes: bytes) -> List[bytes]:
    """
    Chunks the key bytes into chunks of bytes equal in length to the maximum SHAMIR input size. Padds the last element
    in the list accordingly.
    :param key_bytes: byte representation of the EC private sharing key
    :return: list of byte chunks
    """
    chunks = []
    for i in range(0, len(key_bytes), SHAMIR_SIZE):
        chunks.append(key_bytes[i:i + SHAMIR_SIZE])
    # add padding to last chunk
    if len(chunks[-1]) < SHAMIR_SIZE:
        # fill the empty space with zero bytes
        chunks[-1] = chunks[-1] + b"\0" * (SHAMIR_SIZE - len(chunks[-1]))
    return chunks


def _create_shares_from_chunks(chunks: List[bytes], n: int, k: int) -> List[List[Tuple[int, bytes]]]:
    shares = []
    # perform shamir secret sharing on each chunk
    for chunk in chunks:
        chunk_shares = Shamir.split(k, n, chunk, ssss=False)
        shares.append(chunk_shares)

    return shares

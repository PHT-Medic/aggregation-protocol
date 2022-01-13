from typing import Union, List, Tuple

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKeyWithSerialization as ECPrivateKey
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives import serialization

from protocol.models.keys import KeyShare

# Number of sharing key chunks
NUM_KEY_CHUNKS = 20
SHAMIR_SIZE = 16


def create_key_shares(hex_sharing_key: str, n: int, k: int) -> List[KeyShare]:
    key_bytes = bytes.fromhex(hex_sharing_key)
    # chunk the key
    key_chunks = _chunk_key_bytes(key_bytes)
    # create shares from chunks
    chunked_shares = _create_shares_from_chunks(key_chunks, n, k)
    # create key segments from chunked shares
    segments = _make_key_segments_from_chunks(chunked_shares)
    # print(segments)
    return segments


def combine_sharing_key_shares(shares: List[KeyShare]) -> ECPrivateKey:
    segmented_shares = [_process_key_segment(share) for share in shares]
    private_bytes = _process_chunked_shares(segmented_shares)

    return private_bytes


def _process_chunked_shares(chunked_shares: List[List[Tuple[int, bytes]]]) -> bytes:
    pass


def _process_key_segment(key_segment: KeyShare) -> List[Tuple[int, bytes]]:
    appended_shares = bytes.fromhex(key_segment.key_share)
    # split the shares
    segment_shares = []
    for i in range(NUM_KEY_CHUNKS):
        # take each 16 byte chunk and append it to the segment shares along with the user id
        chunk = appended_shares[i * SHAMIR_SIZE: (i + 1) * SHAMIR_SIZE]
        segment_shares.append((key_segment.user_id, chunk))

    return segment_shares


def _make_key_segments_from_chunks(chunked_shares: List[List[Tuple[int, bytes]]]) -> List[KeyShare]:
    # create dictionary with user ids as key and the hex conversion of the initial share as initial value
    segment_dict = {user_id: first_chunk.hex() for user_id, first_chunk in chunked_shares[0]}

    # Start from index 1 as the first item has already been processed
    for chunk_shares in chunked_shares[1:]:
        for user_id, share in chunk_shares:
            # append the hex conversion of the share to the initial value
            segment_dict[user_id] = segment_dict[user_id] + share.hex()

    # convert the dictionary to a list of KeySegments
    key_segments = []
    for user_id, share in segment_dict.items():
        key_segments.append(KeyShare(user_id=user_id, key_share=share))
    return key_segments


def _chunk_key_bytes(key_bytes: bytes, chunk_size: int = 16) -> List[bytes]:
    chunks = []
    for i in range(0, len(key_bytes), chunk_size):
        chunks.append(key_bytes[i:i + chunk_size])
    # add padding to last chunk
    if len(chunks[-1]) < chunk_size:
        # fill the empty space with zero bytes
        chunks[-1] = chunks[-1] + b"\0" * (chunk_size - len(chunks[-1]))
    return chunks


def _create_shares_from_chunks(chunks: List[bytes], n: int, k: int) -> List[List[Tuple[int, bytes]]]:
    shares = []
    # perform shamir secret sharing on each chunk
    for chunk in chunks:
        chunk_shares = Shamir.split(k, n, chunk, ssss=False)
        shares.append(chunk_shares)
    return shares

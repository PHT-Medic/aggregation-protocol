from typing import List, Tuple
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKeyWithSerialization as ECPrivateKey
from cryptography.hazmat.primitives import serialization


from protocol.models.secrets import SecretShares, KeyShare, SeedShare

# Number of sharing key chunks
NUM_KEY_CHUNKS = 20
SHAMIR_SIZE = 16
KEY_BYTES = 306
SEED_LENGTH = 4


def create_secret_shares(hex_sharing_key: str, hex_seed: str, n: int, k: int = 3) -> SecretShares:
    """
    Create shares to distribute to the server in the second round of the protocol.
    :param hex_sharing_key: hex representation of the EC private sharing key
    :param hex_seed: 16 byte hex string representing the integer seed of the mask generator
    :param n: number of participants
    :param k: minimum number of keys necessary to recover the secrets
    :return: SecretShares object containing the chunked key shares as well as the seed shares for each participating
        user
    """
    key_shares = create_key_shares(hex_sharing_key, n, k)
    seed_shares = create_seed_shares(hex_seed, n, k)

    return SecretShares(key_shares=key_shares, seed_shares=seed_shares)


def create_key_shares(hex_sharing_key: str, n: int, k: int = 3) -> List[KeyShare]:
    """
    Create a key shares object from a hex representation of the EC private sharing key.
    :param hex_sharing_key: hex string representation of the EC private sharing key
    :param n: number of participants
    :param k: minimum number of keys necessary to recover the secret
    :return: A KeyShares object containing the chunked sharing key shares associated with user ids
    """
    key_bytes = bytes.fromhex(hex_sharing_key)
    # chunk the key
    key_chunks = _chunk_key_bytes(key_bytes)
    # create shares from chunks
    chunked_shares = _create_shares_from_chunks(key_chunks, n, k)
    # distribute the chunked shares to the users and create the KeyShares object
    key_shares = _distribute_chunked_shares(chunked_shares)
    # print(segments)
    return key_shares


def create_seed_shares(seed: str, n: int, k: int = 3) -> List[SeedShare]:
    """
    Create a secret shares object from a seed.
    :param seed: the seed to split
    :param n: number of participants
    :param k: minimum number of keys necessary to recover the secret
    :return: A SecretShares object containing the chunked secret shares associated with user ids
    """

    seed_bytes = bytes.fromhex(seed)

    if len(seed_bytes) != SEED_LENGTH:
        raise ValueError(f"Seed must be {SEED_LENGTH} bytes long (8 hex characters). Found length {len(seed_bytes)}.")

    # todo remove for better shamir solution
    seed_bytes = seed_bytes + b"\0" * (SHAMIR_SIZE - SEED_LENGTH)
    # create the secret shares
    secret_shares = Shamir.split(k=k, n=n, secret=seed_bytes, ssss=False)
    # convert to list of SeedShare models
    seed_shares = [SeedShare(shamir_index=i, seed=share.hex()) for i, share in secret_shares]

    return seed_shares


def combine_key_shares(shares: List[KeyShare], k: int = 3) -> ECPrivateKey:
    """
    Combine a list of key shares to get the recovery keys
    :param shares:
    :param k:
    :return:
    """
    if len(shares) < k:
        raise ValueError(f"Not enough shares to combine. Found {len(shares)} shares, but need at least {k}.")

    segmented_shares = [_process_key_segment(share) for share in shares]
    private_bytes = _process_chunked_shares(segmented_shares)

    try:
        private_key = serialization.load_pem_private_key(private_bytes, password=None)
    except ValueError:
        raise ValueError("Could combine the shares to recover the secret key.")

    return private_key


def combine_seed_shares(shares: List[SeedShare]) -> bytes:
    """
    Combine a list of seed shares to get the secret
    :param shares:
    :return:
    """
    secret_shares = [(share.shamir_index, share.seed.get_bytes()) for share in shares]
    secret = Shamir.combine(secret_shares, ssss=False)
    # todo remove for better shamir solution
    # remove padding
    secret = secret[:SEED_LENGTH]
    return secret


def _process_chunked_shares(chunked_shares: List[List[Tuple[int, bytes]]]) -> bytes:
    """
    Convert the shares of a chunk of the sharing key
    :param chunked_shares: Crypto Shamir shares of the sharing key
    :return: the combined bytes of the key
    """
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
    """
    Turn the segments of a key share into (int, bytes) tuples to be processed by secret sharing
    :param key_share: a users key share
    :return: list of tuples representing the shared secrets usy by pycryptodome
    """
    shamir_shares = [(key_share.shamir_index, segment.get_bytes()) for segment in key_share.segments]
    return shamir_shares


def _distribute_chunked_shares(chunked_shares: List[List[Tuple[int, bytes]]]) -> List[KeyShare]:
    """
    Distribute the chunked shares to the users Key shares
    :param chunked_shares: List of shamir shares
    :return: a list KeyShare objects containing the key segments associated with a participant
    """
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
        key_shares.append(KeyShare(shamir_index=user_id, segments=share_segment))

    return key_shares


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
    """
    Perform shamir secret sharing on the chunks of the key and return the shares
    :param chunks: a list of 16 byte chunks making up the private sharing key
    :param n: the number of secrets to generate
    :param k: the minimum number of shares required to recover the secret
    :return:
    """
    shares = []
    # perform shamir secret sharing on each chunk
    for chunk in chunks:
        chunk_shares = Shamir.split(k, n, chunk, ssss=False)
        shares.append(chunk_shares)
    return shares

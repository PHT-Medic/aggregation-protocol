import os


def generate_random_seed() -> str:
    return os.urandom(16).hex()


def integer_seed_from_hex(hex_seed: str) -> int:
    return int(hex_seed, 16)

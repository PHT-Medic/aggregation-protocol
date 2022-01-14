import os


def generate_random_seed() -> int:
    return int(os.urandom(16).hex(), 16)

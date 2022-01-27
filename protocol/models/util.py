
class HexString(str):
    """
    A byte string that is hex-encoded.
    """

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, str) or isinstance(v, bytes):
            raise ValueError(f'{v} only string and byte values allowed as input')

        if isinstance(v, str):
            try:
                hex_bytes = bytes.fromhex(v)
                return cls(v)
            except ValueError:
                raise ValueError(f'{v} is not a valid hex string')
        if isinstance(v, bytes):
            return cls(v.hex())

    def get_bytes(self):
        return bytes.fromhex(self)

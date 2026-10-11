from enum import StrEnum


class EncodingMethod(StrEnum):
    XOR = "xor"
    B64 = "b64"
    ROT13 = "rot13"
    B64_ROT13 = "b64-rot13"
    XOR_B64_ROT13 = "xor-b64-rot13"


class ObfuscationAlgos(StrEnum):
    RANDOM_CHARACTER_INSERTION = "rci"
    SPLIT_AND_CONCATENATE = "sac"
    REVERSIBLE_TRANSFORMATION = "rit"
    ESCAPE_SEQUENCE_OBFUSCATION = "eso"


class DecodingMethod(StrEnum):
    FROM_XOR = "xor"
    FROM_B64 = "b64"
    FROM_ROT13 = "rot13"
    FROM_B64_ROT13 = "b64-rot13"
    FROM_XOR_B64_ROT13 = "xor-b64-rot13"


class DeobfuscationAlgos(StrEnum):
    REVERSE_RANDOM_CHARACTER_INSERTION = "rci"
    REVERSE_SPLIT_AND_CONCATENATE = "sac"
    REVERSE_REVERSIBLE_TRANSFORMATION = "rit"
    REVERSE_ESCAPE_SEQUENCE_OBFUSCATION = "eso"

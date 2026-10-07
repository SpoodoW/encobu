import base64
import codecs
import itertools


def from_base64(payload: str) -> str:
    return base64.b64decode(payload.encode("utf-8")).decode("utf-8")


def from_rot13(payload: str) -> str:
    return codecs.encode(payload, encoding="rot13")


def from_xor(payload: str, key: str) -> str:
    key_in_bytes = key.encode("utf-8")
    xor_str = from_base64(payload).encode("utf-8")
    return bytes(p ^ k for p, k in zip(xor_str, itertools.cycle(key_in_bytes))).decode(
        "utf-8"
    )


def from_base64_rot13(payload: str) -> str:
    return from_base64(from_rot13(payload))


def from_xor_base64_rot13(payload: str, key: str) -> str:
    return from_xor(from_rot13(payload), key)

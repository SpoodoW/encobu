import base64
import codecs
import itertools


def to_base64(payload: str) -> str:
    return base64.b64encode(payload.encode("utf-8")).decode("utf-8")

def to_rot13(payload: str) -> str:
    return codecs.encode(payload, "rot13")


def to_base64_rot13(payload: str) -> str:
    return to_rot13(to_base64(payload))


def apply_xor(payload: str, key: str) -> str:
    payload_bytes = payload.encode("utf-8")
    key_bytes = key.encode("utf-8")
    xor_bytes = bytes(p^k for p,k in zip(payload_bytes, itertools.cycle(key_bytes)))
    return base64.b64encode(xor_bytes).decode("utf-8")


def apply_xor_base64_rot13(payload: str, key: str) -> str:
    return to_rot13(apply_xor(payload, key))

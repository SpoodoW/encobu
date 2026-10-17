import base64
import codecs
import itertools


def to_base64(payload: str) -> str:
    return base64.b64encode(payload.encode("utf-8")).decode("utf-8")


def to_rot13(payload: str) -> str:
    return codecs.encode(payload, encoding="rot13")


def to_base64_rot13(payload: str) -> str:
    return to_rot13(to_base64(payload))


def apply_xor(payload: str, key: str) -> str:
    xor_bytes = bytes(
        p ^ k
        for p, k in zip(
            payload.encode(encoding="utf-8"),
            itertools.cycle(key.encode(encoding="utf-8")),
        )
    )
    return base64.b64encode(xor_bytes).decode("utf-8")


def apply_xor_base64_rot13(payload: str, key: str) -> str:
    return to_rot13(apply_xor(payload, key))

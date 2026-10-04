import random
import string
import textwrap

ABTASH_MAP = str.maketrans(
    string.ascii_uppercase + string.ascii_lowercase,
    string.ascii_uppercase[::-1] + string.ascii_lowercase[::-1],
)


def rand_char_insert(payload: str, stride: int, noise_len: int) -> str:
    payload_stripped = payload.replace(" ", "_")
    chunks = []
    for i in range(0, len(payload_stripped), stride):
        chunk = payload_stripped[i : i + stride]
        chunks.append(chunk)

        if i + stride < len(payload_stripped):
            noise_char = "".join(random.choices(string.ascii_letters, k=noise_len))
            chunks.append(noise_char)

    return "".join(chunks)


def split_and_concat(payload: str, stride: int, concat_operator: str = "+") -> str:
    payload_stripped = payload.replace(" ", "_")
    chunks = textwrap.wrap(payload_stripped, width=stride)

    return f" {concat_operator} ".join(f'"{chunk}"' for chunk in chunks)


def reverse_transform(payload: str) -> str:
    return payload.replace(" ", "_").translate(ABTASH_MAP)


def escape_sequence(
    payload: str, escape_type: str = "hex", polymorphic: bool = False
) -> str:
    if not polymorphic:
        if escape_type == "octal":
            return "".join(f"\\{ord(char):03o}" for char in payload)
        return "".join(f"\\x{ord(char):02x}" for char in payload)

    result = []

    if escape_type == "ocatal":
        for char in payload:
            result.append(
                char if random.choice([True, False]) else f"\\{ord(char):03o}"
            )
    else:
        for char in payload:
            result.append(
                char if random.choice([True, False]) else f"\\x{ord(char):02x}"
            )

    return "".join(result)

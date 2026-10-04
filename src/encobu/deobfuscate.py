import codecs

from encobu.obfuscate import ABTASH_MAP


def rev_rand_char_insert(payload: str, stride: int, noise_len: int) -> str:
    chunks = []
    chunk_size = stride + noise_len

    for i in range(0, len(payload), chunk_size):
        chunks.append(payload[i : i + stride])

    original_payload = "".join(chunks)
    return original_payload.replace("_", " ")


def rev_split_and_concat(payload: str, concat_opr: str = "+") -> str:
    payload_glued = payload.split(f" {concat_opr} ")
    original_payload = "".join(chunk.strip('"') for chunk in payload_glued)
    return original_payload.replace("_", " ")


def rev_reverse_transform(payload: str) -> str:
    return payload.translate(ABTASH_MAP).replace("_", " ")


def rev_escape_sequence(payload: str) -> str:
    original_payload = codecs.decode(payload, encoding="unicode_escape")
    return original_payload

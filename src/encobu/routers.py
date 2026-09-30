import sys
from argparse import Namespace

from . import decode, encode, enums, obfuscate


def routing_encode(args: Namespace) -> int:
    if args.file:
        with args.file as f:
            payload_to_enc = f.read()
    else:
        payload_to_enc = args.payload

    match args.method:
        case enums.EncodingMethod.B64:
            result = encode.to_base64(payload_to_enc)
        case enums.EncodingMethod.ROT13:
            result = encode.to_rot13(payload_to_enc)
        case enums.EncodingMethod.XOR:
            if not args.key:
                print(
                    "Error: The XOR cipher requires the key to be specified with -k OR --key.",
                    file=sys.stderr,
                )
                return 1
            result = encode.apply_xor(payload_to_enc, args.key)
        case enums.EncodingMethod.B64_ROT13:
            result = encode.to_base64_rot13(payload_to_enc)
        case enums.EncodingMethod.XOR_B64_ROT13:
            if not args.key:
                print(
                    "Error: The XOR cipher requires the key to be specified with -k OR --key.",
                    file=sys.stderr,
                )
                return 1
            result = encode.apply_xor_base64_rot13(payload_to_enc, args.key)
        case _:
            raise NotImplementedError(
                f"Invalid or Unavailable choice of method: {args.method}"
            )

    print(result)

    return 0


def routing_obfuscation(args: Namespace) -> int:
    if args.file:
        with args.file as f:
            payload_to_obfus = f.read()
    else:
        payload_to_obfus = args.payload

    match args.algo:
        case enums.ObfuscationAlgos.RANDOM_CHARACTER_INSERTION:
            result = obfuscate.rand_char_insert(
                payload_to_obfus, args.stride, args.noise_length
            )

        case enums.ObfuscationAlgos.SPLIT_AND_CONCATENATE:
            result = obfuscate.split_and_concat(
                payload_to_obfus, args.stride, args.operator
            )

        case enums.ObfuscationAlgos.REVERSIBLE_TRANSFORMATION:
            result = obfuscate.reverse_transform(payload_to_obfus)

        case enums.ObfuscationAlgos.ESCAPE_SEQUENCE_OBFUSCATION:
            result = obfuscate.escape_sequence(
                payload_to_obfus, args.escape_type, args.poly
            )

        case _:
            print("Error specified algorithm not recognized", file=sys.stderr)
            return 1

    print(result)
    return 0


def routing_decode(args: Namespace) -> int:
    if args.file:
        with args.file as f:
            encoded_payload = f.read()
    else:
        encoded_payload = args.payload

    match args.method:
        case enums.DecodingMethod.FROM_B64:
            result = decode.from_base64(encoded_payload)
        case enums.DecodingMethod.FROM_ROT13:
            result = decode.from_rot13(encoded_payload)
        case enums.DecodingMethod.FROM_XOR:
            if not args.key:
                print(
                    "Error: The XOR cipher requires the key to be specified with -k OR --key.",
                    file=sys.stderr,
                )
                return 1
            result = decode.from_xor(encoded_payload, args.key)
        case enums.DecodingMethod.FROM_B64_ROT13:
            result = decode.from_base64_rot13(encoded_payload)
        case enums.DecodingMethod.FROM_XOR_B64_ROT13:
            if not args.key:
                print(
                    "Error: The XOR cipher requires the key to be specified with -k OR --key.",
                    file=sys.stderr,
                )
                return 1
            result = decode.from_xor_base64_rot13(encoded_payload, args.key)
        case _:
            print("Error specified algorithm not recognized", file=sys.stderr)
            return 1
    print(result)
    return 0

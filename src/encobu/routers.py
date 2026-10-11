from argparse import Namespace

from . import decode, deobfuscate, encode, enums, obfuscate, report, test
from .console import print_error


def routing_encode(args: Namespace) -> int:
    if args.file:
        try:
            payload_to_enc = args.file.read_text(encoding="utf-8")
        except FileNotFoundError:
            print_error(f"The file {args.file} was not found.")
            return 1
    else:
        payload_to_enc = args.payload

    match args.method:
        case enums.EncodingMethod.B64:
            result = encode.to_base64(payload=payload_to_enc)
        case enums.EncodingMethod.ROT13:
            result = encode.to_rot13(payload=payload_to_enc)
        case enums.EncodingMethod.XOR:
            if not args.key:
                print_error(
                    "The XOR cipher requires the key to be specified with -k OR --key."
                )
                return 1
            result = encode.apply_xor(payload=payload_to_enc, key=args.key)
        case enums.EncodingMethod.B64_ROT13:
            result = encode.to_base64_rot13(payload=payload_to_enc)
        case enums.EncodingMethod.XOR_B64_ROT13:
            if not args.key:
                print_error(
                    "The XOR cipher requires the key to be specified with -k OR --key."
                )
                return 1
            result = encode.apply_xor_base64_rot13(payload=payload_to_enc, key=args.key)
        case _:
            print_error(f"Specified method not recognized: {args.method}")
            return 1

    print(result)

    return 0


def routing_obfuscation(args: Namespace) -> int:
    if args.file:
        try:
            payload_to_obfus = args.file.read_text(encoding="utf-8")
        except FileNotFoundError:
            print_error(f"The file {args.file} was not found.")
            return 1
    else:
        payload_to_obfus = args.payload

    match args.algorithm:
        case enums.ObfuscationAlgos.RANDOM_CHARACTER_INSERTION:
            result = obfuscate.rand_char_insert(
                payload=payload_to_obfus,
                stride=args.stride,
                noise_len=args.noise_length,
            )

        case enums.ObfuscationAlgos.SPLIT_AND_CONCATENATE:
            result = obfuscate.split_and_concat(
                payload=payload_to_obfus,
                stride=args.stride,
                concat_operator=args.concat_operator,
            )

        case enums.ObfuscationAlgos.REVERSIBLE_TRANSFORMATION:
            result = obfuscate.reverse_transform(payload=payload_to_obfus)

        case enums.ObfuscationAlgos.ESCAPE_SEQUENCE_OBFUSCATION:
            result = obfuscate.escape_sequence(
                payload=payload_to_obfus,
                escape_type=args.escape_type,
                polymorphic=args.poly,
            )

        case _:
            print_error(f"Specified algorithm not recognized: {args.algorithm}")
            return 1

    print(result)
    return 0


def routing_decode(args: Namespace) -> int:
    if args.file:
        try:
            encoded_payload = args.file.read_text(encoding="utf-8")
        except FileNotFoundError:
            print_error(f"The file {args.file} was not found.")
            return 1
    else:
        encoded_payload = args.payload

    match args.method:
        case enums.DecodingMethod.FROM_B64:
            result = decode.from_base64(payload=encoded_payload)
        case enums.DecodingMethod.FROM_ROT13:
            result = decode.from_rot13(payload=encoded_payload)
        case enums.DecodingMethod.FROM_XOR:
            if not args.key:
                print_error(
                    "The XOR cipher requires the key to be specified with -k OR --key."
                )
                return 1
            result = decode.from_xor(payload=encoded_payload, key=args.key)
        case enums.DecodingMethod.FROM_B64_ROT13:
            result = decode.from_base64_rot13(payload=encoded_payload)
        case enums.DecodingMethod.FROM_XOR_B64_ROT13:
            if not args.key:
                print_error(
                    "The XOR cipher requires the key to be specified with -k OR --key."
                )
                return 1
            result = decode.from_xor_base64_rot13(payload=encoded_payload, key=args.key)
        case _:
            print_error(f"Specified method not recognized: {args.method}")
            return 1
    print(result)
    return 0


def routing_deobfuscation(args: Namespace) -> int:
    if args.file:
        try:
            obfuscated_payload = args.file.read_text(encoding="utf-8")
        except FileNotFoundError:
            print_error(f"The file {args.file} was not found.")
            return 1
    else:
        obfuscated_payload = args.payload

    match args.algorithm:
        case enums.DeobfuscationAlgos.REVERSE_RANDOM_CHARACTER_INSERTION:
            result = deobfuscate.rev_rand_char_insert(
                payload=obfuscated_payload,
                stride=args.stride,
                noise_len=args.noise_length,
            )
        case enums.DeobfuscationAlgos.REVERSE_SPLIT_AND_CONCATENATE:
            result = deobfuscate.rev_split_and_concat(
                payload=obfuscated_payload, concat_opr=args.concat_operator
            )
        case enums.DeobfuscationAlgos.REVERSE_REVERSIBLE_TRANSFORMATION:
            result = deobfuscate.rev_reverse_transform(payload=obfuscated_payload)
        case enums.DeobfuscationAlgos.REVERSE_ESCAPE_SEQUENCE_OBFUSCATION:
            result = deobfuscate.rev_escape_sequence(payload=obfuscated_payload)
        case _:
            print_error(f"Specified algorithm not recognized: {args.algorithm}")
            return 1

    print(result)
    return 0


def routing_test(args: Namespace) -> int:
    if args.add_rules:
        return test.add_rule(rule_file=args.add_rules)

    if not args.rules:
        print_error("You must specify a YARA rule file (-r) to run a test.")
        return 1

    if args.file:
        try:
            payload = args.file.read_text(encoding="utf-8")
            identifier = args.file.name
        except OSError as e:
            print_error(f"Could not read payload file {args.file}: {e}")
            return 1
    elif args.payload:
        payload = args.payload
        identifier = "inline_payload"
    else:
        print_error("You must provide a payload using either -P (inline) or -F (file).")
        return 1

    try:
        return test.run_test(
            payload=payload,
            rule_paths=args.rules,
            output_dir=args.output_dir,
            identifier=identifier,
        )
    except KeyboardInterrupt:
        print_error("\n Test aborted by user.")
        return 1


def routing_report(args: Namespace) -> int:
    if args.summary and (args.original or args.modified):
        print_error("Cannot combine summary mode (-s) with comparison mode (-o/-m).")
        return 1

    if args.summary:
        return report.generate_summary(report_paths=args.summary)

    if args.original and args.modified:
        return report.generate_comparison(
            original_path=args.original, modified_path=args.modified
        )

    if args.original or args.modified:
        print_error(
            "Comparative analysis requires both (-o/--original) AND (-m/--modified)."
        )
        return 1

    print_error(
        "You must specify either (-s) for summary mode or both (-o and -m) for comparison mode."
    )
    return 1

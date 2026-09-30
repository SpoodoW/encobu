import sys
from argparse import (
    ArgumentParser,
    FileType,
    RawTextHelpFormatter,
)

from . import constants, enums, routers


def creating_parser() -> ArgumentParser:

    parser = ArgumentParser(
        prog="encobu",
        description=constants.MainCommand.DESCRIPTION,
        epilog=constants.MainCommand.EPILOG,
        formatter_class=RawTextHelpFormatter,
    )

    subparser = parser.add_subparsers(
        dest="command",
        required=True,
        title=constants.MainCommand.SUB_PARSER_TITLE,
        metavar=constants.MainCommand.SUB_PARSER_METAVAR,
    )

    encode_parser = subparser.add_parser(
        "encode",
        description=constants.EncodeSubCommand.DESCRIPTION,
        help=constants.EncodeSubCommand.HELP,
        epilog=constants.EncodeSubCommand.EPILOG,
        formatter_class=RawTextHelpFormatter,
    )

    encode_parser.set_defaults(func=routers.routing_encode)

    enc_parser_group = encode_parser.add_mutually_exclusive_group(required=True)

    enc_parser_group.add_argument(
        "-P",
        "--payload",
        type=str,
        help=constants.EncodeSubCommand.PAYLOAD_HELP,
        metavar=constants.EncodeSubCommand.PAYLOAD_METAVAR,
    )

    enc_parser_group.add_argument(
        "-F",
        "--file",
        type=FileType("r", encoding="utf-8"),
        help=constants.EncodeSubCommand.FILE_HELP,
        metavar=constants.EncodeSubCommand.FILE_METAVAR,
    )

    encode_parser.add_argument(
        "-m",
        "--method",
        type=enums.EncodingMethod,
        choices=list(enums.EncodingMethod),
        required=True,
        help=constants.EncodeSubCommand.METHOD_HELP,
        metavar=constants.EncodeSubCommand.METHOD_METAVAR,
    )

    encode_parser.add_argument(
        "-k",
        "--key",
        metavar=constants.EncodeSubCommand.KEY_METAVAR,
        help=constants.EncodeSubCommand.KEY_HELP,
    )

    obfuscate_parser = subparser.add_parser(
        "obfus",
        description=constants.ObfusSubCommand.DESCRIPTION,
        help=constants.ObfusSubCommand.HELP,
        epilog=constants.ObfusSubCommand.EPILOG,
        formatter_class=RawTextHelpFormatter,
    )

    obfuscate_parser.set_defaults(func=routers.routing_obfuscation)

    obfus_parser_group = obfuscate_parser.add_mutually_exclusive_group(required=True)

    obfus_parser_group.add_argument(
        "-P",
        "--payload",
        type=str,
        help=constants.ObfusSubCommand.PAYLOAD_HELP,
        metavar=constants.ObfusSubCommand.PAYLOAD_METAVAR,
    )

    obfus_parser_group.add_argument(
        "-F",
        "--file",
        type=FileType("r", encoding="utf-8"),
        help=constants.ObfusSubCommand.FILE_HELP,
        metavar=constants.ObfusSubCommand.FILE_METAVAR,
    )

    obfuscate_parser.add_argument(
        "-a",
        "--algo",
        type=enums.ObfuscationAlgos,
        choices=list(enums.ObfuscationAlgos),
        required=True,
        help=constants.ObfusSubCommand.ALGO_HELP,
        metavar=constants.ObfusSubCommand.ALGO_METAVAR,
    )

    obfuscate_parser.add_argument(
        "-s",
        "--stride",
        type=int,
        default=3,
        help=constants.ObfusSubCommand.STRIDE_HELP,
        metavar=constants.ObfusSubCommand.STRIDE_METAVAR,
    )

    obfuscate_parser.add_argument(
        "-n",
        "--noise-length",
        type=int,
        default=1,
        help=constants.ObfusSubCommand.NOISE_LEN_HELP,
        metavar=constants.ObfusSubCommand.NOISE_LEN_METAVAR,
    )

    obfuscate_parser.add_argument(
        "-o",
        "--operator",
        type=str,
        default="+",
        help=constants.ObfusSubCommand.OPERATOR_HELP,
        metavar=constants.ObfusSubCommand.OPERATOR_METAVAR,
    )

    obfuscate_parser.add_argument(
        "-e",
        "--escape-type",
        type=str,
        choices=["hex", "octal"],
        default="hex",
        help=constants.ObfusSubCommand.ESCAPE_TYPE_HELP,
        metavar=constants.ObfusSubCommand.ESCAPE_TYPE_METAVAR,
    )

    obfuscate_parser.add_argument(
        "-p",
        "--poly",
        action="store_true",
        help=constants.ObfusSubCommand.POLY_HELP,
    )

    decode_parser = subparser.add_parser(
        "decode",
        description=constants.DecodingCommand.DESCRIPTION,
        help=constants.DecodingCommand.HELP,
        epilog=constants.DecodingCommand.EPILOG,
        formatter_class=RawTextHelpFormatter,
    )

    decode_parser.set_defaults(func=routers.routing_decode)

    decode_parser_group = decode_parser.add_mutually_exclusive_group(required=True)

    decode_parser_group.add_argument(
        "-P",
        "--payload",
        type=str,
        help=constants.DecodingCommand.PAYLOAD_HELP,
        metavar=constants.DecodingCommand.PAYLOAD_METAVAR,
    )

    decode_parser_group.add_argument(
        "-F",
        "--file",
        type=FileType("r", encoding="utf-8"),
        help=constants.DecodingCommand.FILE_HELP,
        metavar=constants.DecodingCommand.FILE_METAVAR,
    )

    decode_parser.add_argument(
        "-m",
        "--method",
        type=enums.DecodingMethod,
        choices=list(enums.DecodingMethod),
        required=True,
        help=constants.DecodingCommand.METHOD_HELP,
        metavar=constants.DecodingCommand.METHOD_METAVAR,
    )

    decode_parser.add_argument(
        "-k",
        "--key",
        type=str,
        help=constants.DecodingCommand.KEY_HELP,
        metavar=constants.DecodingCommand.KEY_METAVAR,
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = creating_parser()
    args = parser.parse_args(argv)

    if hasattr(args, "func"):
        return args.func(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())

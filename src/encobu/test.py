import hashlib
import json
import sys
from pathlib import Path

import yara_x


def run_test(payload: str, rules_path: Path, output_dir: Path, identifier: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        rule_text = rules_path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"Filesystem error reading yara rules: {e}", file=sys.stderr)
        sys.exit(1)
    except UnicodeDecodeError as e:
        print(f"Encoding error: Rules file must be UTF-8: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        rules = yara_x.compile(rule_text)
    except yara_x.CompileError as e:
        print(f"YARA syntax or compilation error: {e}", file=sys.stderr)
        sys.exit(1)

    payload_bytes = payload.encode("utf-8")

    if identifier == "inline_payload":
        payload_hash = hashlib.md5(payload_bytes).hexdigest()[:8]
        safe_identifier = f"inline_{payload_hash}"
    else:
        safe_identifier = Path(identifier).name

    try:
        results = rules.scan(payload_bytes)
    except RuntimeError as e:
        print(f"Runtime error during YARA scan execution: {e}", file=sys.stderr)
        sys.exit(1)

    matched_rules = [match.identifier for match in results.matching_rules]

    report_data = {
        "target_test": safe_identifier,
        "rules_file": rules_path.name,
        "status": "Detected" if matched_rules else "Bypassed",
        "total_detections": len(matched_rules),
        "triggered_rules": matched_rules,
    }

    output_filepath = output_dir / f"{safe_identifier}_results.json"
    try:
        output_filepath.write_text(json.dumps(report_data, indent=4), encoding="utf-8")
        print(f"[+] Test complete. Results saved to: {output_filepath}")
    except OSError as e:
        print(f"Error saving results: {e}", file=sys.stderr)
        sys.exit(1)

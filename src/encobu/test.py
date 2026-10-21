import hashlib
import json
from pathlib import Path

import yara_x

from .console import print_error, print_success, print_warning


def _collect_rule_files(rule_paths: list[Path]) -> list[Path]:
    rule_files = []
    seen = set()
    for path in rule_paths:
        if not path.exists():
            print_warning(f"Rule path {path} does not exist. Skipping.")
            continue
        if path.is_file() and path.suffix.lower() in [".yar", ".yara"]:
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                rule_files.append(path)
        elif path.is_dir():
            for f in path.rglob("*"):
                if f.is_file() and f.suffix.lower() in [".yar", ".yara"]:
                    resolved = f.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        rule_files.append(f)
    return rule_files


def run_test(
    payload: str, rule_paths: list[Path], output_dir: Path, identifier: str
) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    rule_files = _collect_rule_files(rule_paths)
    if not rule_files:
        print_error("No valid .yar or .yara rule files found.")
        return 1
    compiler = yara_x.Compiler()
    compiled_rule_files = []
    for rule_file in rule_files:
        try:
            rule_text = rule_file.read_text(encoding="utf-8")
        except OSError as e:
            print_error(f"Filesystem error reading yara rules: {e}")
            continue
        except UnicodeDecodeError as e:
            print_error(f"Encoding error: Rules file must be UTF-8: {e}")
            continue

        try:
            compiler.add_source(rule_text, origin=rule_file.name)
            compiled_rule_files.append(rule_file)
        except yara_x.CompileError as e:
            print_error(f"YARA syntax or compilation error: {e}")
            continue

    if not compiled_rule_files:
        print_error("No rules were compiled successfully.")
        return 1

    rules = compiler.build()

    payload_bytes = payload.encode("utf-8")

    if identifier == "inline_payload":
        payload_hash = hashlib.md5(payload_bytes).hexdigest()[:8]
        safe_identifier = f"inline_{payload_hash}"
    else:
        safe_identifier = Path(identifier).name

    try:
        results = rules.scan(payload_bytes)
    except RuntimeError as e:
        print_error(f"Runtime error during YARA scan execution: {e}")
        return 1

    matched_rules = []
    for match in results.matching_rules:
        meta_dict = dict(match.metadata)
        rule_details = {
            "rule_name": match.identifier,
            "mitre_attack": meta_dict.get("mitre_attack", "Unknown"),
            "severity": meta_dict.get("severity", "Unknown"),
            "score": meta_dict.get("score", 0.0),
        }
        matched_rules.append(rule_details)

    matched_rules.sort(key=lambda meta_score: meta_score["score"], reverse=True)

    report_data = {
        "target_test": safe_identifier,
        "rule_file": [rule_file.name for rule_file in compiled_rule_files],
        "status": "Detected" if matched_rules else "Bypassed",
        "total_detections": len(matched_rules),
        "triggered_rules": matched_rules,
    }

    output_filepath = output_dir / f"{safe_identifier}_results.json"
    try:
        output_filepath.write_text(json.dumps(report_data, indent=4), encoding="utf-8")
        print_success(f"Results saved to: {output_filepath}")
        return 0
    except OSError as e:
        print_error(f"Error saving results: {e}")
        return 1


def add_rule(rules_path: list[Path]) -> int:
    rule_files = _collect_rule_files(rules_path)
    if not rule_files:
        print_error("No valid .yar or .yara rule files found.")
        return 1

    rules_dir = Path("./rules")

    try:
        rules_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print_error(f"Error creating rules directory: {e}")
        return 1

    failed = False
    added = 0

    for rule_file in rule_files:
        try:
            rule_text = rule_file.read_text(encoding="utf-8")
        except OSError as e:
            print_error(f"Filesystem error reading yara rules: {e}")
            failed = True
            continue
        except UnicodeDecodeError as e:
            print_error(f"Encoding error: Rules file must be UTF-8: {e}")
            failed = True
            continue
        try:
            yara_x.compile(rule_text)
        except yara_x.CompileError as e:
            print_error(f"YARA syntax or compilation error: {e}")
            failed = True
            continue

        dest = rules_dir / rule_file.name

        try:
            dest.write_text(rule_text, encoding="utf-8")
        except OSError as e:
            print_error(f"Error: Saving rule: {e}")
            failed = True
            continue

        added += 1
    
    if added:
        print_success(f"Successfully added {added} rule file(s).")

    return 1 if failed else 0

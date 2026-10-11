import json
import sys
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "blue",
}


def _format_severity(severity: str) -> str:
    color = SEVERITY_STYLES.get(severity.lower(), "white")
    return f"[{color}]{severity}[/{color}]"


def _collect_report_files(report_paths: list[Path]) -> list[Path]:
    json_files = []
    for path in report_paths:
        if not path.exists():
            print(f"Error: {path} does not exist. Skipping.", file=sys.stderr)
            continue
        if path.is_file():
            if path.suffix.lower() == ".json":
                json_files.append(path)
            else:
                print(
                    f"Warning: {path} is not a .json file. Skipping.", file=sys.stderr
                )
        elif path.is_dir():
            for file in path.rglob("*.json"):
                if file.is_file():
                    json_files.append(file)
        else:
            print(f"Warning: {path} is an unsupported file type.", file=sys.stderr)
            continue
    return json_files


def _load_report_data(json_files: list[Path]) -> list[dict]:
    report_data = []

    for file in json_files:
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"Warning: could not read {file}: {e}", file=sys.stderr)
            continue

        if not isinstance(data, dict) or "target_test" not in data:
            print(
                f"Warning: {file} is not a valid encobu report file. Skipping.",
                file=sys.stderr,
            )
            continue

        report_data.append(
            {
                "target": data.get("target_test", "Unknown"),
                "status": data.get("status", "Unknown"),
                "detections": data.get("total_detections", 0),
                "rules": data.get("triggered_rules", []),
            }
        )
    return report_data


def _build_summary_table(report_data: list[dict]) -> Table:
    table = Table(
        title="[bold]Payload Test Summary[/bold]",
        title_justify="left",
        header_style="bold",
        box=box.ROUNDED,
        border_style="dim",
        show_header=True,
        padding=(0, 2),
    )

    table.add_column("Target Payload", style="blue")
    table.add_column("Status", justify="center")
    table.add_column("Detections", justify="center")
    table.add_column("Rule Name", style="white")
    table.add_column("MITRE ATT&CK", style="dim")
    table.add_column("Severity")
    table.add_column("Score", justify="right")

    for item in report_data:
        rules = item["rules"]
        if not rules:
            table.add_row(
                item["target"],
                "[bold green]Bypassed[/bold green]",
                "[green]0[/green]",
                "[dim]None[/dim]",
                "[dim]-[/dim]",
                "[dim]-[/dim]",
                "[dim]-[/dim]",
            )
        else:
            for idx, rule in enumerate(rules):
                target_col = item["target"] if idx == 0 else ""
                status_col = "[bold red]Detected[/bold red]" if idx == 0 else ""
                detections_col = str(item["detections"]) if idx == 0 else ""
                severity_styled = _format_severity(rule.get("severity", "Unknown"))
                score = rule.get("score")
                score_str = f"{score:.1f}" if score is not None else "[dim]-[/dim]"

                table.add_row(
                    target_col,
                    status_col,
                    detections_col,
                    rule.get("rule_name", "Unknown"),
                    rule.get("mitre_attack", "[dim]-[/dim]"),
                    severity_styled,
                    score_str,
                )

        table.add_section()
    return table


def generate_summary(report_paths: list[Path]) -> int:
    json_files = _collect_report_files(report_paths)
    report_data = _load_report_data(json_files)
    if not report_data:
        print("No valid report data found.", file=sys.stderr)
        return 1
    console = Console()
    table = _build_summary_table(report_data)

    console.line()

    console.print(table)

    console.line()
    return 0


def _build_comparison_panel(orig_report: dict, mod_report: dict) -> Panel:
    orig_rules = {r["rule_name"]: r for r in orig_report.get("rules", [])}
    mod_rules = {r["rule_name"]: r for r in mod_report.get("rules", [])}

    orig_count = len(orig_rules)
    mod_count = len(mod_rules)

    evaded_rules = set(orig_rules.keys()) - set(mod_rules.keys())
    evaded_count = len(evaded_rules)

    if orig_count > 0:
        evasion_rate = (evaded_count / orig_count) * 100.0
    else:
        evasion_rate = 100.0 if mod_count == 0 else 0.0

    summary_text = (
        f"[bold]Baseline:[/] {orig_report.get('target', 'Unknown')} "
        f"([red]{orig_count} detections[/red])  -->  "
        f"[bold]Modified:[/] {mod_report.get('target', 'Unknown')} "
        f"([yellow]{mod_count} detections[/yellow])\n"
        f"[bold]Evasion Rate:[/] [bold green]{evasion_rate:.1f}%[/bold green] "
        f"([cyan]{evaded_count}/{orig_count}[/cyan] rules evaded)"
    )

    return Panel(
        summary_text,
        title="[bold]Evasion Performance Summary[/bold]",
        title_align="left",
        border_style="cyan",
    )


def _build_comparison_table(orig_report: dict, mod_report: dict) -> Table:
    orig_rules = {r["rule_name"]: r for r in orig_report.get("rules", [])}
    mod_rules = {r["rule_name"]: r for r in mod_report.get("rules", [])}

    all_rule_names = sorted(set(orig_rules.keys()) | set(mod_rules.keys()))

    table = Table(
        title="[bold]Rule-by-Rule Evasion Breakdown[/bold]",
        title_justify="left",
        header_style="bold",
        box=box.ROUNDED,
        border_style="dim",
        padding=(0, 2),
    )

    table.add_column("Triggered Rule", style="white")
    table.add_column("Severity")
    table.add_column("MITRE ATT&CK", style="dim")
    table.add_column("Baseline", justify="center")
    table.add_column("Modified", justify="center")
    table.add_column("Outcome", justify="center")

    if not all_rule_names:
        table.add_row(
            "[dim]None[/dim]",
            "[dim]-[/dim]",
            "[dim]-[/dim]",
            "[bold green]Clean[/bold green]",
            "[bold green]Clean[/bold green]",
            "[bold green]NO ALERTS[/bold green]",
        )
    else:
        for rule_name in all_rule_names:
            rule_meta = orig_rules.get(rule_name, {}) or mod_rules.get(rule_name, {})
            severity_styled = _format_severity(rule_meta.get("severity", "Unknown"))
            mitre = rule_meta.get("mitre_attack", "[dim]-[/dim]")

            in_orig = rule_name in orig_rules
            in_mod = rule_name in mod_rules

            if in_orig and not in_mod:
                orig_status = "[bold red]Detected[/bold red]"
                mod_status = "[bold green]Bypassed[/bold green]"
                outcome = "[bold green]EVADED[/bold green]"
            elif in_orig and in_mod:
                orig_status = "[bold red]Detected[/bold red]"
                mod_status = "[bold red]Detected[/bold red]"
                outcome = "[bold red]PERSISTS[/bold red]"
            else:
                orig_status = "[dim]Clean[/dim]"
                mod_status = "[bold red]Detected[/bold red]"
                outcome = "[bold yellow]NEW ALERT[/bold yellow]"

            table.add_row(
                rule_name, severity_styled, mitre, orig_status, mod_status, outcome
            )

    table.add_section()
    return table


def generate_comparison(original_path: Path, modified_path: Path) -> int:
    orig_files = _collect_report_files([original_path])
    mod_files = _collect_report_files([modified_path])

    orig_data = _load_report_data(orig_files)
    mod_data = _load_report_data(mod_files)

    if not orig_data or not mod_data:
        print(
            "Error: Could not load both valid report files for comparison.",
            file=sys.stderr,
        )
        return 1

    orig_report = orig_data[0]
    mod_report = mod_data[0]

    console = Console()
    panel = _build_comparison_panel(orig_report, mod_report)
    table = _build_comparison_table(orig_report, mod_report)

    console.line()
    console.print(panel)
    console.line()
    console.print(table)
    console.line()

    return 0

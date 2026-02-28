import argparse
import json
from pathlib import Path
from typing import Dict, List, Set


ALERT_TO_SN: Dict[str, List[str]] = {
    "Cross Site Scripting (Reflected)": ["02"],
    "Server Side Template Injection": ["02"],
    "External Redirect": ["05"],
    "Off-site Redirect": ["05"],
    "Path Traversal": ["15"],
    "Remote OS Command Injection": ["25"],
    "SQL Injection": ["01", "19"],
    "SQL Injection - SQLite": ["01", "19"],
    "Server Side Request Forgery": ["22"],
    "Missing Anti-clickjacking Header": ["09"],
    "GET for POST": ["07"],
    "Information Disclosure - Sensitive Information in URL": ["07", "10", "21"],
    "Application Error Disclosure": ["03"],
    "Source Code Disclosure - File Inclusion": ["15"],
    "Source Code Disclosure - SQL": ["01", "19"],
}


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in file: {path}\n{exc}") from exc


def ensure_input_files_exist(paths: List[Path]) -> None:
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        raise FileNotFoundError(
            "Missing required input file(s):\n- " + "\n- ".join(missing)
        )


def read_sn_set(group_json: dict) -> Set[str]:
    return {item["sn"] for item in group_json.get("items", [])}


def extract_alert_names_from_zap(zap: dict) -> Set[str]:
    sites = zap.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    alert_names: Set[str] = set()
    for site in sites:
        for alert in site.get("alerts", []):
            name = alert.get("name")
            if name:
                alert_names.add(name)

    return alert_names


def map_detected_sns(alert_names: Set[str]) -> Set[str]:
    detected: Set[str] = set()
    for alert_name in alert_names:
        detected.update(ALERT_TO_SN.get(alert_name, []))
    return detected


def find_unmapped_alert_names(alert_names: Set[str]) -> List[str]:
    return sorted([alert_name for alert_name in alert_names if alert_name not in ALERT_TO_SN])


def pct(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round((numerator / denominator) * 100, 2)


def compute_group_stats(group_sn_set: Set[str], detected_sn_set: Set[str]) -> dict:
    covered = sorted(group_sn_set & detected_sn_set)
    not_covered = sorted(group_sn_set - detected_sn_set)
    return {
        "covered_count": len(covered),
        "total": len(group_sn_set),
        "percentage": pct(len(covered), len(group_sn_set)),
        "covered_sn": covered,
        "not_covered_sn": not_covered,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute DAST coverage against dast-only and sast-and-dast groups from ZAP full-scan report."
    )
    parser.add_argument(
        "--zap-report",
        default="artifacts/full-scan-report.json",
        help="Path to ZAP full scan report JSON",
    )
    parser.add_argument(
        "--dast-only",
        default="tools/data/dast-only.json",
        help="Path to dast-only group JSON",
    )
    parser.add_argument(
        "--sast-and-dast",
        default="tools/data/sast-and-dast.json",
        help="Path to sast-and-dast group JSON",
    )
    parser.add_argument(
        "--json-out",
        default="tools/results/dast_stats_summary.json",
        help="Output JSON summary path",
    )
    args = parser.parse_args()

    zap_report_path = Path(args.zap_report)
    dast_only_path = Path(args.dast_only)
    sast_and_dast_path = Path(args.sast_and_dast)
    json_out_path = Path(args.json_out)

    ensure_input_files_exist([zap_report_path, dast_only_path, sast_and_dast_path])

    zap_data = load_json(zap_report_path)
    dast_only_data = load_json(dast_only_path)
    sast_and_dast_data = load_json(sast_and_dast_path)

    dast_only_sn = read_sn_set(dast_only_data)
    sast_and_dast_sn = read_sn_set(sast_and_dast_data)

    alert_names = extract_alert_names_from_zap(zap_data)
    detected_sn = map_detected_sns(alert_names)
    unmapped_alert_names = find_unmapped_alert_names(alert_names)

    dast_only_stats = compute_group_stats(dast_only_sn, detected_sn)
    sast_and_dast_stats = compute_group_stats(sast_and_dast_sn, detected_sn)

    summary = {
        "inputs": {
            "zap_report": str(zap_report_path),
            "dast_only": str(dast_only_path),
            "sast_and_dast": str(sast_and_dast_path),
        },
        "mapping_rule": "ZAP alert name -> SN mapping defined in ALERT_TO_SN",
        "detected_alert_names": sorted(alert_names),
        "unmapped_detected_alert_names": unmapped_alert_names,
        "detected_sn_total": sorted(detected_sn),
        "groups": {
            "dast_only": dast_only_stats,
            "sast_and_dast": sast_and_dast_stats,
        },
    }

    json_out_path.parent.mkdir(parents=True, exist_ok=True)
    json_out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("DAST Coverage Summary")
    print("=====================")
    print(
        f"DAST-only detected: {dast_only_stats['covered_count']}/{dast_only_stats['total']} "
        f"({dast_only_stats['percentage']}%)"
    )
    print(
        f"SAST-and-DAST detected by DAST: {sast_and_dast_stats['covered_count']}/{sast_and_dast_stats['total']} "
        f"({sast_and_dast_stats['percentage']}%)"
    )
    print()
    print("DAST-only covered SN:", ", ".join(dast_only_stats["covered_sn"]) or "None")
    print("DAST-only not covered SN:", ", ".join(dast_only_stats["not_covered_sn"]) or "None")
    print("SAST-and-DAST covered SN:", ", ".join(sast_and_dast_stats["covered_sn"]) or "None")
    print("SAST-and-DAST not covered SN:", ", ".join(sast_and_dast_stats["not_covered_sn"]) or "None")
    if unmapped_alert_names:
        print("Unmapped detected alert names:", ", ".join(unmapped_alert_names))
    print()
    print(f"JSON summary written to: {json_out_path}")


if __name__ == "__main__":
    main()

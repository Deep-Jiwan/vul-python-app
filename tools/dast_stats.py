import argparse
import json
from pathlib import Path
from typing import Dict, List, Set, Any


MAPPING_RULES: List[Dict[str, Any]] = [
    # Global/header-level signals
    {"sn": "08", "alert_name": "HTTP Only Site"},
    {"sn": "11", "alert_name": "Storable and Cacheable Content"},
    # SQL injection split by endpoint
    {"sn": "01", "alert_name": "SQL Injection", "uri_contains": ["/login"]},
    {"sn": "01", "alert_name": "SQL Injection - SQLite", "uri_contains": ["/login"]},
    {"sn": "01", "alert_name": "Source Code Disclosure - SQL", "uri_contains": ["/login"]},
    {"sn": "19", "alert_name": "SQL Injection", "uri_contains": ["/search"]},
    {"sn": "19", "alert_name": "SQL Injection - SQLite", "uri_contains": ["/search"]},
    {"sn": "19", "alert_name": "Source Code Disclosure - SQL", "uri_contains": ["/search"]},
    # XSS/SSTI (conservative: profile only for SN02)
    {"sn": "02", "alert_name": "Cross Site Scripting (Reflected)", "uri_contains": ["/profile"]},
    {"sn": "02", "alert_name": "Server Side Template Injection", "uri_contains": ["/profile"]},
    # Frame injection (/frame_content) evidenced via multiple alert types on vulnerable endpoint
    {"sn": "04", "alert_name": "Cross Site Scripting (Reflected)", "uri_contains": ["/frame_content"]},
    {"sn": "04", "alert_name": "Server Side Template Injection", "uri_contains": ["/frame_content"]},
    {"sn": "04", "alert_name": "Source Code Disclosure - File Inclusion", "uri_contains": ["/frame_content"]},
    # Info leakage
    {"sn": "03", "alert_name": "Application Error Disclosure", "uri_contains": ["/login"]},
    # Open redirect
    {"sn": "05", "alert_name": "External Redirect", "uri_contains": ["/redirect"]},
    {"sn": "05", "alert_name": "Off-site Redirect", "uri_contains": ["/redirect"]},
    # GET vs POST misuse
    {"sn": "07", "alert_name": "GET for POST", "uri_contains": ["/login"]},
    # Clickjacking
    {"sn": "09", "alert_name": "Missing Anti-clickjacking Header"},
    # Path traversal
    {"sn": "15", "alert_name": "Path Traversal", "uri_contains": ["/download"]},
    {"sn": "15", "alert_name": "Source Code Disclosure - File Inclusion", "uri_contains": ["/download"]},
    # SSRF
    {"sn": "22", "alert_name": "Server Side Request Forgery", "uri_contains": ["/fetch_url"]},
    # Command injection
    {"sn": "25", "alert_name": "Remote OS Command Injection", "uri_contains": ["/ping"]},
]


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


def extract_alert_instances(zap: dict) -> List[Dict[str, str]]:
    sites = zap.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    records: List[Dict[str, str]] = []
    for site in sites:
        for alert in site.get("alerts", []):
            name = alert.get("name", "")
            instances = alert.get("instances", [])
            if instances:
                for inst in instances:
                    records.append({"name": name, "uri": inst.get("uri", "")})
            else:
                records.append({"name": name, "uri": ""})
    return records


def rule_matches_instance(rule: Dict[str, Any], instance: Dict[str, str]) -> bool:
    if instance.get("name") != rule.get("alert_name"):
        return False

    uri_filters = rule.get("uri_contains")
    if not uri_filters:
        return True

    uri = instance.get("uri", "")
    return any(token in uri for token in uri_filters)


def map_detected_sns(instances: List[Dict[str, str]]) -> (Set[str], List[Dict[str, str]]):
    detected: Set[str] = set()
    evidence: List[Dict[str, str]] = []

    for rule in MAPPING_RULES:
        for inst in instances:
            if rule_matches_instance(rule, inst):
                detected.add(rule["sn"])
                evidence.append(
                    {
                        "sn": rule["sn"],
                        "alert_name": rule["alert_name"],
                        "uri": inst.get("uri", ""),
                    }
                )
                break

    return detected, evidence


def find_unmapped_alert_names(alert_names: Set[str]) -> List[str]:
    mapped_alert_names = {rule["alert_name"] for rule in MAPPING_RULES}
    return sorted([alert_name for alert_name in alert_names if alert_name not in mapped_alert_names])


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
    alert_instances = extract_alert_instances(zap_data)
    detected_sn, match_evidence = map_detected_sns(alert_instances)
    unmapped_alert_names = find_unmapped_alert_names(alert_names)

    dast_only_stats = compute_group_stats(dast_only_sn, detected_sn)
    sast_and_dast_stats = compute_group_stats(sast_and_dast_sn, detected_sn)

    summary = {
        "inputs": {
            "zap_report": str(zap_report_path),
            "dast_only": str(dast_only_path),
            "sast_and_dast": str(sast_and_dast_path),
        },
        "mapping_rule": "Conservative mapping by alert name + endpoint URI defined in MAPPING_RULES",
        "detected_alert_names": sorted(alert_names),
        "unmapped_detected_alert_names": unmapped_alert_names,
        "detected_sn_total": sorted(detected_sn),
        "match_evidence": match_evidence,
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

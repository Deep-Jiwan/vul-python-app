import argparse
import json
from pathlib import Path
from typing import Dict, List, Set


RULE_TO_SN: Dict[str, List[str]] = {
    "py/sql-injection": ["01", "19"],
    "py/reflective-xss": ["02"],
    "py/template-injection": ["02"],
    "py/url-redirection": ["05"],
    "py/weak-cryptographic-algorithm": ["12", "17"],
    "py/http-response-splitting": ["13"],
    "py/path-injection": ["15"],
    "py/full-ssrf": ["22"],
    "py/unsafe-deserialization": ["24"],
    "py/command-line-injection": ["25"],
    "py/xxe": ["26"],
    "py/xml-bomb": ["26"],
    "py/stack-trace-exposure": ["03"],
    "py/cookie-injection": ["08"],
    "py/csrf-protection-disabled": ["21"],
    "py/client-exposed-cookie": ["08"],
    "py/insecure-cookie": ["08"],
    "py/samesite-none-cookie": ["08"],
    "py/clear-text-storage-sensitive-data": ["18"],
    "py/clear-text-logging-sensitive-data": ["03"],
    "py/weak-sensitive-data-hashing": ["17"],
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


def extract_rule_ids_from_sarif(sarif: dict) -> Set[str]:
    runs = sarif.get("runs", [])
    rule_ids: Set[str] = set()
    for run in runs:
        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            if rule_id:
                rule_ids.add(rule_id)
    return rule_ids


def map_detected_sns(rule_ids: Set[str]) -> Set[str]:
    detected: Set[str] = set()
    for rule_id in rule_ids:
        detected.update(RULE_TO_SN.get(rule_id, []))
    return detected


def find_unmapped_rule_ids(rule_ids: Set[str]) -> List[str]:
    return sorted([rule_id for rule_id in rule_ids if rule_id not in RULE_TO_SN])


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
        description="Compute SAST coverage against sast-only and sast-and-dast groups from SARIF."
    )
    parser.add_argument(
        "--sarif",
        default="artifacts/python-results.sarif",
        help="Path to CodeQL SARIF file",
    )
    parser.add_argument(
        "--sast-only",
        default="tools/data/sast-only.json",
        help="Path to sast-only group JSON",
    )
    parser.add_argument(
        "--sast-and-dast",
        default="tools/data/sast-and-dast.json",
        help="Path to sast-and-dast group JSON",
    )
    parser.add_argument(
        "--json-out",
        default="tools/results/sast_stats_summary.json",
        help="Output JSON summary path",
    )
    args = parser.parse_args()

    sarif_path = Path(args.sarif)
    sast_only_path = Path(args.sast_only)
    sast_and_dast_path = Path(args.sast_and_dast)
    json_out_path = Path(args.json_out)

    ensure_input_files_exist([sarif_path, sast_only_path, sast_and_dast_path])

    sarif_data = load_json(sarif_path)
    sast_only_data = load_json(sast_only_path)
    sast_and_dast_data = load_json(sast_and_dast_path)

    sast_only_sn = read_sn_set(sast_only_data)
    sast_and_dast_sn = read_sn_set(sast_and_dast_data)

    rule_ids = extract_rule_ids_from_sarif(sarif_data)
    detected_sn = map_detected_sns(rule_ids)
    unmapped_rule_ids = find_unmapped_rule_ids(rule_ids)

    sast_only_stats = compute_group_stats(sast_only_sn, detected_sn)
    sast_and_dast_stats = compute_group_stats(sast_and_dast_sn, detected_sn)

    summary = {
        "inputs": {
            "sarif": str(sarif_path),
            "sast_only": str(sast_only_path),
            "sast_and_dast": str(sast_and_dast_path),
        },
        "mapping_rule": "CodeQL ruleId -> SN mapping defined in RULE_TO_SN",
        "mapping_note": "SN26 uses py/xxe as primary mapping; py/xml-bomb is also mapped for XML parser misuse coverage.",
        "detected_rule_ids": sorted(rule_ids),
        "unmapped_detected_rule_ids": unmapped_rule_ids,
        "detected_sn_total": sorted(detected_sn),
        "groups": {
            "sast_only": sast_only_stats,
            "sast_and_dast": sast_and_dast_stats,
        },
    }

    # Ensure the output directory exists (write to tools/results by default)
    json_out_path.parent.mkdir(parents=True, exist_ok=True)
    json_out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("SAST Coverage Summary")
    print("=====================")
    print(
        f"SAST-only detected: {sast_only_stats['covered_count']}/{sast_only_stats['total']} "
        f"({sast_only_stats['percentage']}%)"
    )
    print(
        f"SAST-and-DAST detected by SAST: {sast_and_dast_stats['covered_count']}/{sast_and_dast_stats['total']} "
        f"({sast_and_dast_stats['percentage']}%)"
    )
    print()
    print("SAST-only covered SN:", ", ".join(sast_only_stats["covered_sn"]) or "None")
    print("SAST-only not covered SN:", ", ".join(sast_only_stats["not_covered_sn"]) or "None")
    print("SAST-and-DAST covered SN:", ", ".join(sast_and_dast_stats["covered_sn"]) or "None")
    print("SAST-and-DAST not covered SN:", ", ".join(sast_and_dast_stats["not_covered_sn"]) or "None")
    if unmapped_rule_ids:
        print("Unmapped detected rule IDs:", ", ".join(unmapped_rule_ids))
    print()
    print(f"JSON summary written to: {json_out_path}")


if __name__ == "__main__":
    main()

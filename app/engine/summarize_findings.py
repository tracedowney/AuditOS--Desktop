from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List


def summarize_findings(report: Dict[str, Any]) -> Dict[str, Any]:
    all_findings: List[Dict[str, Any]] = []
    component_errors: List[str] = []

    for key, value in report.items():
        if key in {"summary", "meta"}:
            continue

        if isinstance(value, dict):
            if isinstance(value.get("findings"), list):
                all_findings.extend(value["findings"])

            if value.get("status") == "error":
                component_errors.append(key)

    all_findings.sort(key=lambda x: x.get("score", 0), reverse=True)

    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in all_findings:
        sev = finding.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1

    overall = "low"
    if counts["high"] >= 2:
        overall = "high"
    elif counts["high"] == 1 or counts["medium"] >= 8:
        overall = "medium"

    if component_errors and overall == "low":
        overall = "medium"

    recommendations: List[str] = []

    if any(f.get("category") == "proxy" for f in all_findings):
        recommendations.append("Review proxy and PAC settings in Windows and the browser.")
    if any(f.get("category") in {"browser_extension", "permission", "host_access"} for f in all_findings):
        recommendations.append("Review browser extensions with broad access, sensitive permissions, or non-standard update behavior.")
    if any(f.get("category") in {"startup_items", "scheduled_tasks"} for f in all_findings):
        recommendations.append("Review persistence items that launch from AppData, Temp, Downloads, or script hosts.")
    if any(f.get("category") == "certificates" for f in all_findings):
        recommendations.append("Review user and machine root certificates for anything you do not recognize.")
    if any(f.get("category") in {"active_connections", "listening_ports"} for f in all_findings):
        recommendations.append("Review processes with unusual public connections or listening ports, especially from user-writeable paths.")
    if component_errors:
        recommendations.append("One or more audit components failed. Review the component error details and traceback fields in the report.")

    return {
        "component": "summary",
        "overall_risk": overall,
        "counts": counts,
        "total_findings": len(all_findings),
        "component_errors": component_errors,
        "top_findings": all_findings[:25],
        "recommendations": recommendations,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("report_json")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()

    with open(args.report_json, "r", encoding="utf-8") as f:
        report = json.load(f)

    print(json.dumps(summarize_findings(report), indent=2 if args.pretty else None))
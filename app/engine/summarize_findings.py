from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List


def summarize_findings(report: Dict[str, Any]) -> Dict[str, Any]:
    all_findings: List[Dict[str, Any]] = []

    for _, value in report.items():
        if isinstance(value, dict) and isinstance(value.get("findings"), list):
            all_findings.extend(value["findings"])

    all_findings.sort(key=lambda x: x.get("score", 0), reverse=True)

    counts = {"high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        counts[f.get("severity", "low")] = counts.get(f.get("severity", "low"), 0) + 1

    # Less alarmist overall scoring
    overall = "low"
    if counts["high"] >= 2:
        overall = "high"
    elif counts["high"] == 1 or counts["medium"] >= 8:
        overall = "medium"

    recs = []
    if any(f["category"] == "proxy" for f in all_findings):
        recs.append("Review proxy and PAC settings in Windows and the browser.")
    if any(f["category"] == "browser_extension" for f in all_findings):
        recs.append("Review browser extensions with broad host access, cookies, webRequest, or nativeMessaging.")
    if any(f["category"] in {"startup_items", "scheduled_tasks"} for f in all_findings):
        recs.append("Review persistence items that launch from AppData, Temp, Downloads, or script hosts.")
    if any(f["category"] == "certificates" for f in all_findings):
        recs.append("Review user root certificates for anything you do not recognize.")
    if any(f["category"] in {"active_connections", "listening_ports"} for f in all_findings):
        recs.append("Review processes with unusual public connections or listening ports, especially from user-writeable paths.")

    return {
        "component": "summary",
        "overall_risk": overall,
        "counts": counts,
        "total_findings": len(all_findings),
        "top_findings": all_findings[:25],
        "recommendations": recs,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("report_json")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()

    with open(args.report_json, "r", encoding="utf-8") as f:
        report = json.load(f)

    print(json.dumps(summarize_findings(report), indent=2 if args.pretty else None))

from __future__ import annotations

from typing import Any, Dict, List


def summarize_findings(report: Dict[str, Any]) -> Dict[str, Any]:
    all_findings: List[Dict[str, Any]] = []
    limitations: List[str] = []

    for _, value in report.items():
        if isinstance(value, dict) and isinstance(value.get("findings"), list):
            all_findings.extend(value["findings"])
            for finding in value["findings"]:
                detail = str(finding.get("detail", ""))
                if detail.startswith("Limited visibility:") and detail not in limitations:
                    limitations.append(detail)

    all_findings.sort(key=lambda x: x.get("score", 0), reverse=True)

    counts = {"high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        counts[f.get("severity", "low")] = counts.get(f.get("severity", "low"), 0) + 1

    overall = "low"
    if counts["high"] >= 2:
        overall = "high"
    elif counts["high"] == 1 or counts["medium"] >= 8:
        overall = "medium"

    host_os = str(report.get("host_os", "")).lower()
    is_macos = "darwin" in host_os or "mac" in host_os
    is_windows = "windows" in host_os
    is_linux = "linux" in host_os

    recs = []
    plain_summary = []

    if any(f["category"] == "proxy" for f in all_findings):
        if is_macos:
            recs.append("Review proxy and PAC settings in macOS Network settings.")
        elif is_windows:
            recs.append("Review proxy and PAC settings in Windows and the browser.")
        elif is_linux:
            recs.append("Review proxy settings in your desktop/network configuration.")
        else:
            recs.append("Review proxy and PAC settings on this system.")

    if any(f["category"] == "browser_extension" for f in all_findings):
        recs.append("Review browser extensions with broad host access or sensitive permissions.")

    if any(f["category"] in {"startup_items", "scheduled_tasks"} for f in all_findings):
        if is_macos:
            recs.append("Review LaunchAgents, LaunchDaemons, and launchctl jobs you do not recognize.")
        elif is_windows:
            recs.append("Review persistence items that launch from AppData, Temp, Downloads, or script hosts.")
        else:
            recs.append("Review startup and scheduled items that launch unexpectedly or from unusual paths.")

    if any(f["category"] == "certificates" for f in all_findings):
        if is_macos:
            recs.append("Review trusted certificates in Keychain Access if you suspect unexpected trust changes.")
        else:
            recs.append("Review root certificates for anything you do not recognize.")

    if any(f["category"] in {"active_connections", "listening_ports"} for f in all_findings):
        recs.append("Review processes with unusual public connections or listening ports, especially from user-writeable paths.")

    if limitations and is_macos:
        recs.append("If Deep Audit shows limited visibility on macOS, review system privacy permissions and rerun the scan.")

    if not all_findings:
        plain_summary.append("AuditOS did not see any findings that it considers notable in this scan.")
    else:
        if counts["high"]:
            plain_summary.append(f"AuditOS found {counts['high']} high-priority item(s) that deserve attention first.")
        elif counts["medium"]:
            plain_summary.append(f"AuditOS found {counts['medium']} medium-priority item(s) worth reviewing.")
        else:
            plain_summary.append("AuditOS only found low-priority items in this scan.")

        if any(f["category"] == "browser_extension" for f in all_findings):
            plain_summary.append("At least one browser extension has permissions or site access that may be broader than expected.")

        if any(f["category"] in {"startup_items", "scheduled_tasks"} for f in all_findings):
            plain_summary.append("AuditOS found apps or jobs that can start automatically with the system.")

        if any(f["category"] in {"active_connections", "listening_ports"} for f in all_findings):
            plain_summary.append("Deep Audit saw live network activity or open ports that you may want to recognize and verify.")

    if limitations:
        plain_summary.append("Some parts of the scan had reduced visibility because the operating system limited access.")

    return {
        "component": "summary",
        "overall_risk": overall,
        "counts": counts,
        "total_findings": len(all_findings),
        "top_findings": all_findings[:25],
        "recommendations": recs,
        "limitations": limitations,
        "plain_summary": plain_summary,
    }

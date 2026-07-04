from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List


def _finding_key(finding: Dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(finding.get("category", "")).strip().lower(),
        str(finding.get("detail", "")).strip(),
        str(finding.get("severity", "low")).strip().lower(),
    )


def _collect_findings(value: Any) -> List[Dict[str, Any]]:
    collected: List[Dict[str, Any]] = []

    if isinstance(value, dict):
        findings = value.get("findings")
        if isinstance(findings, list):
            collected.extend(finding for finding in findings if isinstance(finding, dict))

        for nested in value.values():
            if nested is findings:
                continue
            collected.extend(_collect_findings(nested))

    elif isinstance(value, list):
        for item in value:
            collected.extend(_collect_findings(item))

    return collected


def summarize_findings(report: Dict[str, Any]) -> Dict[str, Any]:
    all_findings: List[Dict[str, Any]] = []
    limitations: List[str] = []
    seen_findings: set[tuple[str, str, str]] = set()

    for value in report.values():
        for finding in _collect_findings(value):
            detail = str(finding.get("detail", ""))
            if detail.startswith("Limited visibility:") and detail not in limitations:
                limitations.append(detail)
                continue
            key = _finding_key(finding)
            if key not in seen_findings:
                all_findings.append(finding)
                seen_findings.add(key)

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

    browser_extension_items = report.get("browser_extensions", {}).get("items", [])
    has_browser_extension_findings = any(f["category"] == "browser_extension" for f in all_findings) or any(
        isinstance(item, dict) and isinstance(item.get("findings"), list) and item.get("findings")
        for item in browser_extension_items
    )
    medium_or_high_findings = [f for f in all_findings if str(f.get("severity", "low")) in {"medium", "high"}]
    medium_or_high_categories = Counter(str(f.get("category", "")).strip().lower() for f in medium_or_high_findings)
    low_categories = Counter(
        str(f.get("category", "")).strip().lower()
        for f in all_findings
        if str(f.get("severity", "low")) == "low"
    )

    plain_summary = []

    if not all_findings:
        plain_summary.append("AuditOS did not see any findings that it considers notable in this scan.")
    else:
        if counts["high"]:
            plain_summary.append(f"AuditOS found {counts['high']} high-priority item(s) that deserve attention first.")
        elif counts["medium"]:
            plain_summary.append(f"AuditOS found {counts['medium']} medium-priority item(s) worth reviewing.")
        else:
            plain_summary.append("AuditOS only found low-priority items in this scan.")

        if has_browser_extension_findings:
            plain_summary.append("At least one browser extension has permissions or site access that may be broader than expected.")

        if medium_or_high_categories.get("dns"):
            plain_summary.append(
                "Most of the higher-priority items in this scan were DNS server entries repeated across resolvers, so the real question is whether those few DNS servers are expected on this machine."
            )

        if medium_or_high_categories.get("routes"):
            plain_summary.append("AuditOS also noticed a routing configuration detail worth verifying.")

        if any(f["category"] in {"startup_items", "scheduled_tasks"} for f in medium_or_high_findings):
            plain_summary.append("AuditOS found apps or jobs that can start automatically with the system.")
        elif any(low_categories.get(category) for category in ("startup_items", "scheduled_tasks")):
            plain_summary.append("AuditOS also listed low-priority apps or jobs that start automatically with the system, but they did not drive the overall risk score.")

        if any(f["category"] in {"active_connections", "listening_ports"} for f in medium_or_high_findings):
            plain_summary.append("Deep Audit saw live network activity or open ports that you may want to recognize and verify.")
        elif any(low_categories.get(category) for category in ("active_connections", "listening_ports")):
            plain_summary.append("Deep Audit also recorded low-priority live network or open-port items to recognize, but they did not drive the overall risk score.")

        if any(f["category"] == "background_tasks" for f in medium_or_high_findings):
            plain_summary.append("Deep Audit found background tasks worth verifying, especially ones running from unusual locations or acting as command hosts.")
        elif low_categories.get("background_tasks"):
            plain_summary.append("Deep Audit also listed low-priority background-task context, but it did not drive the overall risk score.")

    if limitations:
        plain_summary.append("Some parts of the scan had reduced visibility because the operating system limited access.")

    return {
        "component": "summary",
        "overall_risk": overall,
        "counts": counts,
        "total_findings": len(all_findings),
        "top_findings": all_findings[:25],
        "limitations": limitations,
        "plain_summary": plain_summary,
    }

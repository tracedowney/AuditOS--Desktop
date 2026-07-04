from __future__ import annotations

from app.engine.summarize_findings import summarize_findings


def test_summarize_findings_counts_nested_browser_extension_findings():
    report = {
        "host_os": "Windows-11",
        "browser_extensions": {
            "component": "browser_extensions",
            "findings": [],
            "items": [
                {
                    "name": "Google Docs Offline",
                    "findings": [
                        {
                            "category": "host_access",
                            "detail": "Wildcard host access: https://*/*",
                            "score": 2,
                            "severity": "low",
                        },
                        {
                            "category": "host_access",
                            "detail": "Wildcard host access: http://*/*",
                            "score": 2,
                            "severity": "low",
                        },
                    ],
                }
            ],
        },
        "scheduled_tasks": {
            "component": "scheduled_tasks",
            "findings": [
                {
                    "category": "scheduled_tasks",
                    "detail": "Automatic task can run commands or scripts: \\Microsoft\\Windows\\Hotpatch\\Monitoring",
                    "score": 4,
                    "severity": "medium",
                }
            ],
        },
        "background_tasks": {
            "component": "background_tasks",
            "findings": [
                {
                    "category": "background_tasks",
                    "detail": "Review this background task: PowerShell can run commands or scripts, and its command line looks unusually powerful or remote-driven",
                    "score": 8,
                    "severity": "high",
                }
            ],
        },
        "listening_ports": {
            "component": "listening_ports",
            "findings": [
                {
                    "category": "listening_ports",
                    "detail": "Likely normal Windows background service on port 49665",
                    "score": 1,
                    "severity": "low",
                }
            ],
        },
    }

    summary = summarize_findings(report)

    assert summary["total_findings"] == 5
    assert summary["counts"] == {"high": 1, "medium": 1, "low": 3}
    assert any(
        "browser extension has permissions or site access" in line
        for line in summary["plain_summary"]
    )
    assert any(
        "apps or jobs that can start automatically with the system" in line
        for line in summary["plain_summary"]
    )
    assert any(
        "background tasks worth verifying" in line
        for line in summary["plain_summary"]
    )


def test_summarize_findings_keeps_limitations_out_of_finding_counts():
    report = {
        "host_os": "macOS-15",
        "dns_settings": {
            "component": "dns_settings",
            "findings": [
                {
                    "category": "dns",
                    "detail": "Review custom public DNS server on 2 resolver entries: 151.236.14.64",
                    "score": 4,
                    "severity": "medium",
                }
            ],
        },
        "active_connections": {
            "component": "active_connections",
            "findings": [
                {
                    "category": "active_connections",
                    "detail": "Limited visibility: macOS denied access to 271 process connection list(s)",
                    "score": 1,
                    "severity": "low",
                }
            ],
        },
        "listening_ports": {
            "component": "listening_ports",
            "findings": [
                {
                    "category": "listening_ports",
                    "detail": "Limited visibility: macOS denied access to 271 process socket list(s)",
                    "score": 1,
                    "severity": "low",
                }
            ],
        },
    }

    summary = summarize_findings(report)

    assert summary["counts"] == {"high": 0, "medium": 1, "low": 0}
    assert summary["total_findings"] == 1
    assert len(summary["limitations"]) == 2
    assert any("DNS server entries repeated across resolvers" in line for line in summary["plain_summary"])

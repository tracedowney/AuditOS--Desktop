from __future__ import annotations

from typing import Any, Dict, List

from ..common_utils import make_finding, run_command


def _certutil_store(store_name: str) -> tuple[int, str, str]:
    return run_command(["certutil", "-store", store_name])


def run():
    findings: List[Dict[str, Any]] = []
    suspicious_subjects: List[str] = []

    user_code, user_out, user_err = _certutil_store("Root")
    machine_code, machine_out, machine_err = _certutil_store("AuthRoot")

    if user_code != 0 and machine_code != 0:
        return {
            "component": "certificates",
            "user_root_count": 0,
            "machine_root_count": 0,
            "user_root_certificates": [],
            "machine_root_sample": [],
            "suspicious_subjects": [],
            "findings": [
                make_finding("certificates", "Failed to read Windows certificate stores", 3, {"user_error": user_err, "machine_error": machine_err})
            ],
            "errors": {"windows": "\n".join(x for x in [user_err, machine_err] if x)},
        }

    def extract_subjects(output: str) -> List[str]:
        subjects = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Subject:"):
                subjects.append(line.partition(":")[2].strip())
        return subjects

    user_subjects = extract_subjects(user_out)
    machine_subjects = extract_subjects(machine_out)

    for subject in user_subjects:
        low = subject.lower()
        if any(token in low for token in ("proxy", "inspection", "mitm", "debug", "filter", "avast", "kaspersky", "bitdefender")):
            suspicious_subjects.append(subject)

    if suspicious_subjects:
        findings.append(
            make_finding(
                "certificates",
                f"Review {len(suspicious_subjects)} certificate subject(s) with interception/security-tool indicators",
                4,
                {"subjects": suspicious_subjects[:10]},
            )
        )

    return {
        "component": "certificates",
        "user_root_count": len(user_subjects),
        "machine_root_count": len(machine_subjects),
        "user_root_certificates": user_subjects[:25],
        "machine_root_sample": machine_subjects[:25],
        "suspicious_subjects": suspicious_subjects,
        "findings": findings,
        "errors": {"windows": ""},
    }

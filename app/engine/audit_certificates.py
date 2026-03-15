from __future__ import annotations

import argparse
import json

from .common_utils import make_finding, run_command


def parse_certutil_output(stdout: str):
    certs = []
    current = {}

    for line in stdout.splitlines():
        s = line.strip()
        if s.startswith("===="):
            if current:
                certs.append(current)
                current = {}
            continue
        if "Subject:" in s:
            current["subject"] = s.split("Subject:", 1)[-1].strip()
        elif "Issuer:" in s:
            current["issuer"] = s.split("Issuer:", 1)[-1].strip()
        elif "Serial Number:" in s:
            current["serial_number"] = s.split("Serial Number:", 1)[-1].strip()
        elif "NotAfter:" in s:
            current["not_after"] = s.split("NotAfter:", 1)[-1].strip()

    if current:
        certs.append(current)

    return certs


def audit_certificates():
    findings = []

    user_code, user_out, user_err = run_command(["certutil", "-user", "-store", "Root"])
    mach_code, mach_out, mach_err = run_command(["certutil", "-store", "Root"])

    user_certs = parse_certutil_output(user_out) if user_code == 0 else []
    machine_certs = parse_certutil_output(mach_out) if mach_code == 0 else []

    if len(user_certs) > 0:
        findings.append(make_finding("certificates", f"User root store contains {len(user_certs)} certificate(s); review anything you did not install", 4))

    suspicious_subjects = []
    for cert in user_certs:
        subj = (cert.get("subject") or "").lower()
        if any(x in subj for x in ["proxy", "filter", "inspect", "packet", "debug", "mitm"]):
            suspicious_subjects.append(cert)
            findings.append(make_finding("certificates", f"Potential interception-related root certificate: {cert.get('subject', '')}", 7, cert))

    if user_code != 0:
        findings.append(make_finding("certificates", "Failed to read user root certificate store", 3, {"error": user_err}))
    if mach_code != 0:
        findings.append(make_finding("certificates", "Failed to read machine root certificate store", 3, {"error": mach_err}))

    return {
        "component": "certificates",
        "user_root_count": len(user_certs),
        "machine_root_count": len(machine_certs),
        "user_root_certificates": user_certs,
        "machine_root_sample": machine_certs[:50],
        "suspicious_subjects": suspicious_subjects,
        "findings": findings,
        "errors": {"user": user_err.strip(), "machine": mach_err.strip()},
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()
    print(json.dumps(audit_certificates(), indent=2 if args.pretty else None))
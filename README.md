# AuditOS

AuditOS is a local desktop auditing tool that helps people understand browser, network, and persistence-related settings on their computer without sending audit data off-device.

The project is currently in beta. The focus right now is stability, clearer reporting, and making the app easy to test on macOS and Windows.

## What AuditOS Does

- Runs local audits of browser extensions, proxy settings, DNS settings, startup items, scheduled tasks, certificates, and network-related system state
- Supports a faster `Quick Audit` for common checks
- Supports a broader `Deep Audit` for additional connection, listening-port, and routing visibility
- Lets you save a baseline and compare later scans
- Tracks behavior changes between scans so testers can spot what changed over time

## Core Principles

- All audits run locally on your machine
- Your data does not leave your computer
- AuditOS does not automatically remove, disable, or change system components
- AuditOS is an informational tool, not an automated remediation tool
- Optional scheduled scans only run while AuditOS is open during this beta

## Audit Modes

### Quick Audit

Use `Quick Audit` for a fast snapshot of higher-level browser and system configuration checks. This is the best default option for routine testing.

Quick Audit currently focuses on:

- Browser extensions
- Proxy settings
- DNS settings
- Network interfaces
- Startup items
- Scheduled tasks
- Certificates

### Deep Audit

Use `Deep Audit` when you want additional visibility into live network behavior.

Deep Audit includes everything in Quick Audit, plus:

- Active network connections
- Listening ports
- Routes / default routes

On macOS, parts of Deep Audit may show limited visibility if the OS denies process or socket enumeration. AuditOS should report that limitation instead of crashing.

## Current Beta Scope

AuditOS is still in the stabilization phase. Expect:

- rough edges in cross-platform coverage
- some findings that still need tuning for signal quality
- packaging and release flow updates while the project hardens

## Installation

### macOS

1. Download the current macOS beta zip.
2. Unzip it.
3. Open `AuditOS.app`.
4. If Gatekeeper blocks the app, right click `AuditOS.app`, choose `Open`, then confirm.

### Windows

1. Download the current Windows beta zip.
2. Unzip it fully before launching.
3. Open `AuditOS.exe`.
4. If SmartScreen appears, choose `More info`, then `Run anyway`.

## What Testers Should Watch For

- crashes or hangs during Quick or Deep audit
- sections that appear empty when they should contain data
- findings that seem obviously incorrect or overly noisy
- inconsistencies between repeated scans on the same machine
- baseline or change-detection results that do not match expectations

## Reporting Feedback

When reporting an issue, include:

- operating system and version
- whether you ran Quick Audit or Deep Audit
- what you expected to happen
- what actually happened
- screenshots or exported report JSON if helpful

If the issue is security-sensitive, please use the process in [SECURITY.md](SECURITY.md).

## Development

### Requirements

- Python 3.9+
- `PySide6`
- `psutil`

Install runtime dependencies with:

```bash
python3 -m pip install -r requirements.txt
```

### Run Locally

From the repo root:

```bash
cd app
PYTHONPATH="$(pwd)/.." python3 main.py
```

On Windows PowerShell:

```powershell
cd app
$env:PYTHONPATH = (Resolve-Path "..").Path
python main.py
```

### Build Releases

The repo includes a PyInstaller spec and a PowerShell release script:

- [AuditOS.spec](AuditOS.spec)
- [build_release.ps1](build_release.ps1)

The intended flow is to build from the spec so packaged output stays consistent across local release runs.

## Project Docs

- [CHANGELOG.md](CHANGELOG.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [TERMS_OF_USE.txt](TERMS_OF_USE.txt)
- [PRIVACY.txt](PRIVACY.txt)

## License

Copyright © 2026 AuditOS

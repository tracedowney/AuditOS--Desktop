from __future__ import annotations

import argparse
import json

from .common_utils import component_error
from .platform_utils import get_os


def _runner():
    os_name = get_os()
    if os_name == "windows":
        from .certificates.windows import run
        return run
    if os_name == "macos":
        from .certificates.macos import run
        return run
    if os_name == "linux":
        from .certificates.linux import run
        return run
    raise RuntimeError(f"Unsupported operating system: {os_name}")


def audit_certificates():
    try:
        return _runner()()
    except Exception as exc:
        return component_error("certificates", exc)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()
    print(json.dumps(audit_certificates(), indent=2 if args.pretty else None))

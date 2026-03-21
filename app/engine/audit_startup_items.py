from __future__ import annotations

import argparse
import json

from .common_utils import component_error
from .platform_utils import get_os


def _runner():
    os_name = get_os()
    if os_name == "windows":
        from .startup_items.windows import run
        return run
    if os_name == "macos":
        from .startup_items.macos import run
        return run
    if os_name == "linux":
        from .startup_items.linux import run
        return run
    raise RuntimeError(f"Unsupported operating system: {os_name}")


def audit_startup_items():
    try:
        return _runner()()
    except Exception as exc:
        return component_error("startup_items", exc)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()
    print(json.dumps(audit_startup_items(), indent=2 if args.pretty else None))

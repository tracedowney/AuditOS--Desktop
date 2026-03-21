from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple


COMMON_WEB_PORTS = {80, 443, 8080, 8443}
COMMON_DNS_PORTS = {53, 853}
PRIVATE_PATH_HINTS = [r"\temp\\", r"\appdata\\local\\temp\\", r"\downloads\\"]


def run_command(args: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", f"Command timed out after {timeout}s: {exc}"
    except Exception as exc:
        return 1, "", str(exc)


def safe_read_json(path: Path) -> Dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def expand(path: str | Path) -> Path:
    return Path(path).expanduser().resolve()


def score_to_severity(score: int) -> str:
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def make_finding(
    category: str,
    detail: str,
    score: int,
    evidence: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {
        "category": category,
        "detail": detail,
        "score": int(score),
        "severity": score_to_severity(int(score)),
        "evidence": evidence or {},
    }


def suspicious_path(path: str) -> bool:
    p = (path or "").lower()
    return any(hint in p for hint in PRIVATE_PATH_HINTS)


def normalize_component_result(component: str, result: Dict[str, Any] | None) -> Dict[str, Any]:
    result = result or {}
    if not isinstance(result, dict):
        result = {"raw_result": repr(result)}

    result.setdefault("component", component)
    result.setdefault("items", [])
    result.setdefault("findings", [])
    result.setdefault("status", "ok")
    result.setdefault("error", "")
    return result


def component_error(component: str, exc: Exception, traceback_text: str = "") -> Dict[str, Any]:
    return {
        "component": component,
        "items": [],
        "findings": [
            make_finding(
                component,
                f"{component} component failed to execute",
                2,
                {
                    "exception_type": type(exc).__name__,
                    "message": str(exc),
                },
            )
        ],
        "status": "error",
        "error": str(exc),
        "traceback": traceback_text,
    }
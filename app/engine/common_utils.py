from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple

COMMON_WEB_PORTS = {80, 443, 8080, 8443}
COMMON_DNS_PORTS = {53, 853}
PRIVATE_PATH_HINTS = [r"\temp\\", r"\appdata\\local\\temp\\", r"\downloads\\"]


def run_command(args: List[str]) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        return p.returncode, p.stdout, p.stderr
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
        "score": score,
        "severity": score_to_severity(score),
        "evidence": evidence or {},
    }


def suspicious_path(path: str) -> bool:
    p = path.lower()
    return any(hint in p for hint in PRIVATE_PATH_HINTS)

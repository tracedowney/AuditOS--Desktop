from __future__ import annotations

from typing import Dict


def explain_finding_locally(finding: Dict):
    severity = finding.get("severity", "unknown")
    category = finding.get("category", "")
    detail = finding.get("detail", "")

    return (
        f"This finding is rated {severity} severity.\n\n"
        f"It belongs to the category: {category}.\n\n"
        f"Explanation:\n{detail}\n\n"
        "This does not necessarily mean compromise â€” it simply means it deserves review."
    )

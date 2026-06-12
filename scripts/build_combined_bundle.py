#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import tempfile
import zipfile
from pathlib import Path
from textwrap import dedent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a single cross-platform AuditOS bundle containing macOS and Windows artifacts."
    )
    parser.add_argument("--version", required=True, help="Bundle version label, e.g. v0.4.4-beta")
    parser.add_argument("--mac-zip", required=True, type=Path, help="Path to the macOS release zip")
    parser.add_argument("--windows-zip", required=True, type=Path, help="Path to the Windows release zip")
    parser.add_argument(
        "--report",
        action="append",
        default=[],
        type=Path,
        help="Optional exported report JSON to include. Can be passed multiple times.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output zip path. Defaults to repo root.",
    )
    return parser.parse_args()


def ensure_exists(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"{label} was not found: {resolved}")
    return resolved


def write_bundle_readme(
    path: Path,
    *,
    version: str,
    mac_name: str,
    windows_name: str,
    report_names: list[str],
) -> None:
    report_section = ""
    if report_names:
        lines = "\n".join(f"- reports/{name}" for name in report_names)
        report_section = (
            "\nIncluded sample reports:\n"
            f"{lines}\n"
        )

    contents = dedent(
        f"""\
        AuditOS Cross-Platform Bundle
        =============================

        Version: {version}

        This bundle contains both platform builds for the same AuditOS release.

        Included platform artifacts:
        - macOS/{mac_name}
        - Windows/{windows_name}
        {report_section}
        Notes:
        - This is a convenience bundle, not a self-installing cross-platform launcher.
        - macOS users should use the file inside the macOS folder.
        - Windows users should use the file inside the Windows folder.
        - Reviewers can compare both packages side by side from this single bundle.
        """
    ).strip() + "\n"
    path.write_text(contents, encoding="utf-8")


def zip_directory(source_dir: Path, output_zip: Path) -> None:
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(source_dir.rglob("*")):
            if file_path.is_dir():
                continue
            zf.write(file_path, arcname=file_path.relative_to(source_dir.parent))


def main() -> int:
    args = parse_args()

    project_root = Path(__file__).resolve().parent.parent
    version = args.version
    bundle_name = f"AuditOS_CrossPlatform_Bundle_{version}"
    output_zip = args.output.expanduser().resolve() if args.output else project_root / f"{bundle_name}.zip"

    mac_zip = ensure_exists(args.mac_zip, "macOS artifact")
    windows_zip = ensure_exists(args.windows_zip, "Windows artifact")
    reports = [ensure_exists(report, "Report file") for report in args.report]

    with tempfile.TemporaryDirectory(prefix="auditos_bundle_") as tmp:
        tmp_root = Path(tmp)
        bundle_root = tmp_root / bundle_name
        mac_dir = bundle_root / "macOS"
        windows_dir = bundle_root / "Windows"
        reports_dir = bundle_root / "reports"

        mac_dir.mkdir(parents=True, exist_ok=True)
        windows_dir.mkdir(parents=True, exist_ok=True)
        if reports:
            reports_dir.mkdir(parents=True, exist_ok=True)

        shutil.copy2(mac_zip, mac_dir / mac_zip.name)
        shutil.copy2(windows_zip, windows_dir / windows_zip.name)

        report_names: list[str] = []
        for report in reports:
            report_names.append(report.name)
            shutil.copy2(report, reports_dir / report.name)

        write_bundle_readme(
            bundle_root / "README_FIRST.txt",
            version=version,
            mac_name=mac_zip.name,
            windows_name=windows_zip.name,
            report_names=report_names,
        )

        if output_zip.exists():
            output_zip.unlink()

        zip_directory(bundle_root, output_zip)

    print(f"Created combined bundle: {output_zip}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

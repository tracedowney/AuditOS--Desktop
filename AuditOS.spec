# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import sys

# Managed hardening spec.
# Source-of-truth for packaging is the app package tree discovered at build time.

ROOT = Path(globals().get("__file__", Path.cwd() / "AuditOS.spec")).resolve().parent
APP_DIR = ROOT / "app"


def include_if_exists(path: Path, destination: str = "."):
    if path.exists():
        return [(str(path), destination)]
    return []

hiddenimports = [
    "app",
    "app.engine",
    "app.engine.audit_active_connections",
    "app.engine.audit_browser_extensions",
    "app.engine.audit_certificates",
    "app.engine.audit_dns_settings",
    "app.engine.audit_listening_ports",
    "app.engine.audit_network_interfaces",
    "app.engine.audit_proxy_settings",
    "app.engine.audit_routes",
    "app.engine.audit_scheduled_tasks",
    "app.engine.audit_startup_items",
    "app.engine.browser_extensions.linux",
    "app.engine.browser_extensions.macos",
    "app.engine.browser_extensions.windows",
    "app.engine.certificates.linux",
    "app.engine.certificates.macos",
    "app.engine.certificates.windows",
    "app.engine.common_utils",
    "app.engine.dns_settings.linux",
    "app.engine.dns_settings.macos",
    "app.engine.dns_settings.windows",
    "app.engine.network_interfaces.linux",
    "app.engine.network_interfaces.macos",
    "app.engine.network_interfaces.windows",
    "app.engine.platform_utils",
    "app.engine.routes.linux",
    "app.engine.routes.macos",
    "app.engine.routes.windows",
    "app.engine.run_full_audit",
    "app.engine.scheduled_tasks.linux",
    "app.engine.scheduled_tasks.macos",
    "app.engine.scheduled_tasks.windows",
    "app.engine.startup_items.linux",
    "app.engine.startup_items.macos",
    "app.engine.startup_items.windows",
    "app.engine.summarize_findings",
    "app.engine_adapter",
    "app.main",
    "app.services",
    "app.services.ai_explainer",
    "app.services.baseline_store",
    "app.services.crash_logger",
    "app.services.diff_engine",
    "app.services.first_run_notice",
    "app.services.network_behavior_baseline",
    "app.ui",
    "app.ui.behavior_table",
    "app.ui.changes_table",
    "app.ui.findings_table",
    "app.ui.main_window",
    "app.ui.settings_dialog",
    "app.workers",
]

datas = []
for doc_name in ("LICENSE", "NOTICE", "PRIVACY", "README.md", "CHANGELOG.md"):
    datas.extend(include_if_exists(ROOT / doc_name))

icon_path = APP_DIR / ("AuditOS.icns" if sys.platform == "darwin" else "icon.ico")
icon_arg = str(icon_path) if icon_path.exists() else None

a = Analysis(
    [str(APP_DIR / "main.py")],
    pathex=[str(ROOT), str(APP_DIR)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AuditOS',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    icon=icon_arg,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="AuditOS",
)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="AuditOS.app",
        icon=icon_arg,
        bundle_identifier="com.auditos.desktop",
        info_plist={
            "CFBundleName": "AuditOS",
            "CFBundleDisplayName": "AuditOS",
            "CFBundleShortVersionString": "0.4",
            "CFBundleVersion": "0.4",
            "NSPrincipalClass": "NSApplication",
        },
    )

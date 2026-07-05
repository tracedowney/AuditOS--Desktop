from __future__ import annotations

from app.services.visibility_guidance import build_visibility_guidance, describe_limitation


def test_describe_limitation_translates_process_connection_note():
    note = "Limited visibility: macOS denied access to 272 process connection list(s)"
    described = describe_limitation(note, "macOS-15")

    assert "blocked AuditOS from matching live internet connections to owning processes" in described
    assert "272" in described
    assert "not a list of separate problems" in described
    assert "even after Full Disk Access" in described


def test_build_visibility_guidance_offers_macos_settings_path():
    guidance = build_visibility_guidance(
        [
            "Limited visibility: the operating system denied access to 12 process record(s)",
        ],
        "macOS-15",
    )

    assert guidance["actionable"] is True
    assert guidance["settings_url"]
    assert "Privacy" in str(guidance["primary_button"])
    assert "background-task visibility" in str(guidance["status_note"]).lower()
    assert "does not always show a permission prompt" in str(guidance["dialog_body"])
    assert guidance["instructions"] == [
        "Open System Settings to Privacy & Security.",
        "Open Full Disk Access.",
        "If AuditOS is already listed, turn it on. If it is not listed, click the add button and choose AuditOS.",
        "If macOS asks you to quit and reopen AuditOS, do that.",
        "Run Deep Audit again so AuditOS can check whether visibility improved.",
    ]


def test_build_visibility_guidance_marks_connection_ownership_limits_as_non_actionable():
    guidance = build_visibility_guidance(
        [
            "Limited visibility: macOS blocked process-to-connection ownership lookup for 271 running process(es)",
            "Limited visibility: macOS blocked process-to-socket ownership lookup for 271 running process(es)",
        ],
        "macOS-15",
    )

    assert guidance["actionable"] is False
    assert guidance["settings_url"] is None
    assert guidance["primary_button"] == ""
    assert "Full Disk Access may not remove this specific limit" in str(guidance["banner_text"])
    assert "standard app session" in str(guidance["dialog_body"])

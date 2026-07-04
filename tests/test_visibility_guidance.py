from __future__ import annotations

from app.services.visibility_guidance import build_visibility_guidance, describe_limitation


def test_describe_limitation_translates_process_connection_note():
    note = "Limited visibility: macOS denied access to 272 process connection list(s)"
    described = describe_limitation(note, "macOS-15")

    assert "blocked AuditOS from matching live internet connections to owning processes" in described
    assert "272" in described
    assert "not a list of separate problems" in described


def test_build_visibility_guidance_offers_macos_settings_path():
    guidance = build_visibility_guidance(
        [
            "Limited visibility: macOS denied access to 272 process connection list(s)",
            "Limited visibility: macOS denied access to 272 process socket list(s)",
        ],
        "macOS-15",
    )

    assert guidance["actionable"] is True
    assert guidance["settings_url"]
    assert "Privacy" in str(guidance["primary_button"])
    assert "live network visibility" in str(guidance["status_note"]).lower()

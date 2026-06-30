# AuditOS Beta Release Checklist

Use this checklist when cutting a new beta so the macOS and Windows artifacts stay aligned to the same source state.

## 1. Preflight

- Confirm the intended version in `app/version_info.py`.
- Confirm the worktree only contains the release-ready changes you want to ship.
- Run the test suite:
  - `QT_QPA_PLATFORM=offscreen venv/bin/python -m pytest -q`
- Run a local source smoke test for both audit modes:
  - Quick Audit should complete and summarize findings without crashing.
  - Deep Audit should complete and include the Background Tasks view.

## 2. Build From One Commit

- Build the macOS artifact from the exact commit you plan to release.
- Build the Windows artifact from that same commit or tag.
- Use the release script:
  - `pwsh -File ./scripts/build_release.ps1`
- The script derives the archive version from `app/version_info.py` unless you intentionally override it with `-Version`.

## 3. Smoke Test The Packaged Artifacts

- Unzip the packaged artifact you plan to upload.
- Launch the packaged app, not just the source tree.
- Verify:
  - the app opens without an immediate crash
  - Quick Audit runs successfully
  - Deep Audit runs successfully
  - scheduled scans still clearly say they only run while AuditOS is open
  - the Background Tasks tab appears for Deep Audit and not for Quick Audit
  - findings, behavior, and export/report flows still work

## 4. Release Surface Check

- Make sure `README.md` matches the current beta capabilities and limitations.
- Keep screenshots current if the UI changed materially.
- Confirm release notes explain what changed and what testers should focus on.
- Avoid uploading superseded or mismatched assets from an older version.

## 5. Publish

- Attach both platform artifacts to the same GitHub release.
- Verify the release title, tag, artifact filenames, and version text all agree.
- Keep a note of the commit SHA used to produce the release assets.

## 6. After Publish

- Download the posted artifacts once from GitHub Releases and do one final launch smoke test.
- File follow-up issues for anything discovered during packaging or smoke testing.
- Mark any older beta release as superseded if it could confuse testers.

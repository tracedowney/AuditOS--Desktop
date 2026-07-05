# Changelog

All notable changes to AuditOS should be documented in this file.

## Unreleased

### Added

- Deep Audit now includes a Background Tasks view with plain-language explanations for running processes and clearer review cues for unusual paths or command hosts
- Restored Windows audit module entry points for browser extensions, certificates, DNS settings, network interfaces, routes, scheduled tasks, and startup items
- Added roadmap and release-planning docs for objectives, parked ideas, and beta release verification
- Added a beta release checklist for aligned macOS and Windows packaging and smoke testing
- Added a live-network collector seam so Deep Audit can evolve from standard-user collection toward elevated or helper-backed collection paths without rewriting the audit logic

### Changed

- Scheduled scans now persist next-run state more safely, show clearer status messaging, and recover more gracefully when a scheduled run fails
- Settings now preview automatic scan behavior and make the beta limitation explicit that scheduled scans only run while AuditOS is open
- Compatible beta-to-beta updates now preserve saved baselines, behavior history, and the first-run acknowledgement instead of resetting them on every app version bump
- Background Tasks now recognizes AuditOS-launched helper commands more clearly, shows launcher context when available, and gives the detail view a larger readable layout
- Findings summaries now separate scan-visibility limits from real findings more clearly, and DNS review items are grouped into unique custom servers instead of repeated raw-IP spam per resolver entry
- Findings tooltips now surface more supporting detail, including process explanation, impact hints, paths, and command previews where available
- Deep audit now degrades gracefully on macOS when the OS denies process or socket enumeration
- Deep Audit on macOS now prefers a command-backed network ownership collector, which attributes more live connections and listeners without falling back to a wall of per-process denial counts
- macOS visibility guidance now distinguishes between Full Disk Access gaps and tougher process-to-network ownership limits that require a different collection strategy
- macOS certificate checks no longer create a finding simply because certificates exist
- Release workflow now builds from the checked-in PyInstaller spec, derives archive versions from `app/version_info.py`, and supports tag-aligned dual-platform beta publishing
- README expanded with clearer beta, testing, and audit-mode guidance

### Repo

- Removed tracked generated artifacts from source control
- Tightened ignore rules for generated zip files

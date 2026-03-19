# Changelog

All notable changes to AuditOS should be documented in this file.

## Unreleased

### Added

- Restored Windows audit module entry points for browser extensions, certificates, DNS settings, network interfaces, routes, scheduled tasks, and startup items

### Changed

- Deep audit now degrades gracefully on macOS when the OS denies process or socket enumeration
- macOS certificate checks no longer create a finding simply because certificates exist
- Release workflow now builds from the checked-in PyInstaller spec
- README expanded with clearer beta, testing, and audit-mode guidance

### Repo

- Removed tracked generated artifacts from source control
- Tightened ignore rules for generated zip files

# AuditOS Parking Lot

Ideas and future-facing items that are worth keeping, but are intentionally out of scope for the current beta-hardening and release-alignment work.

## Product Ideas

- Plain-language explanation improvements beyond the current rule-based summaries
  - Goal: make findings easier for non-technical users to understand without turning AuditOS into an automated decision-maker.

- Optional AI explanation of findings
  - Already hinted at in the app and docs as a future capability.
  - Should remain opt-in and privacy-explicit.
  - If pursued, decide later whether it belongs in the free tier, a premium tier, or an optional paid add-on.

- AI-assisted interpretation for common-user language
  - Separate from raw findings collection.
  - Focus would be translation and explanation, not telling users what to remove.

## Deferred Features Already Referenced In The App

- Scheduled audits beyond the current beta limitation
  - Today: scheduled scans only run while AuditOS is open.
  - Later question: should AuditOS ever support more persistent scheduling?

- Change history timeline
  - Already listed in the welcome text as a future version idea.

- Cross-device comparison
  - Already listed in the welcome text as a future version idea.

- AI explanations setting
  - The Settings dialog already includes `Enable AI explanations (coming soon)`.
  - Keep disabled/inactive until the behavior, privacy model, and product tiering are clearly defined.

## Product Positioning Follow-Ups

- Refine the distinction between:
  - informational classification
  - plain-language explanation
  - guidance or remediation

- Keep AuditOS positioned as:
  - visibility
  - organization
  - change tracking
  - user-controlled decision support

- Avoid drifting into promises around:
  - performance fixes
  - automated cleanup
  - definitive safe/unsafe judgments

## Release / Process Follow-Ups

- Keep macOS and Windows beta assets aligned to the same commit/tag.

- Consider a more repeatable dual-platform packaging flow so releases do not drift between:
  - source on `main`
  - macOS beta artifact
  - Windows beta artifact

- Revisit whether GitHub Actions should eventually build release artifacts on both:
  - `macos-latest`
  - `windows-latest`

## Current Scope Rule

These items are intentionally parked until the current track is complete:

- stabilize the beta
- keep packaging aligned across platforms
- validate positioning with real outside feedback

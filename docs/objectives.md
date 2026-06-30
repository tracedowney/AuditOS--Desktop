# AuditOS Objectives

This document is the working roadmap for AuditOS.

It is meant to answer three questions:

- What are we actively trying to accomplish now?
- What should come next once the current track is complete?
- Which ideas are worth keeping, but intentionally not pulling into scope yet?

Use this file as the current roadmap, and use [parking-lot.md](./parking-lot.md) for ideas we want to retain without actively pulling them into scope.

## Product Direction

AuditOS is aiming to be a local desktop auditing tool that helps people see what is starting, running, and changing on their computer in one place.

The product direction we have discussed repeatedly is:

- local-first
- clear enough for non-experts to follow
- useful on both macOS and Windows
- focused on visibility, organization, and change tracking
- supportive of user judgment, not automatic remediation

Guardrails for future roadmap decisions:

- Do not position AuditOS as an antivirus replacement.
- Do not promise automated cleanup or definitive safe/unsafe judgments.
- Keep plain-language explanations separate from prescriptive recommendations.
- Preserve user trust by keeping privacy and on-device processing explicit.

## Current Objectives

These are the active objectives for the current track.

### 1. Stabilize The Beta

Why this matters:
The current beta needs to feel dependable before we widen testing or add more ambitious features.

What this includes:

- finish the scheduler and persistence hardening work already in progress
- keep scheduled scans clearly limited to "runs while the app is open" during beta
- improve empty states, status messaging, and error handling where the app still feels uncertain
- keep tests covering persistence, scheduler state, and cross-platform behavior

Exit criteria:

- scheduler-related local changes are committed cleanly
- the behavior is understandable in the UI
- the current test suite passes after the work is finalized

### 2. Keep macOS And Windows Releases Aligned

Why this matters:
We have already seen how easy it is for source, tags, and shipped assets to drift apart.

What this includes:

- build both platform artifacts from the same commit or tag
- keep the Windows build path healthy, including VM and storage setup
- smoke test the actual downloaded release assets, not just source runs
- write down a repeatable release checklist so beta packaging is less fragile

Exit criteria:

- both packaged builds come from the same source state
- the release page clearly matches the code that produced the assets
- the packaging flow feels repeatable instead of ad hoc

### 3. Make Beta Testing Easy To Understand And Easy To Join

Why this matters:
If the repo and release page are hard to parse, useful testers will fall off before we learn anything.

What this includes:

- keep the README clear, visual, and honest about beta limitations
- publish screenshots and keep them current
- keep download, bug-report, feature-request, and security-report paths obvious
- make release notes and superseded-release messaging straightforward

Exit criteria:

- a new visitor can understand the app quickly
- a tester can find the download and feedback path without hunting
- the public-facing repo reflects the current beta instead of stale assets

### 4. Validate Positioning With Real Outside Feedback

Why this matters:
We need to learn whether AuditOS solves a problem other people actually feel, not just whether the code works.

What this includes:

- use the GitHub repo, Discussions, and release pages as the primary credibility surface
- use the drafts in [community-feedback.md](./community-feedback.md) for GitHub Discussions, Reddit, Show HN, and similar outreach
- collect feedback on trust, noise level, confusion points, and repeat-use value
- learn which message resonates most with early testers

Exit criteria:

- we have feedback from people outside the immediate project context
- we can name the clearest user value proposition in plain English
- we know which parts of the app create trust and which parts create friction

## Next Objectives

These should move into active work after the current objectives are in a healthier state.

### 1. Harden The Release Process

- decide whether GitHub Actions should eventually build beta artifacts for both macOS and Windows
- reduce the number of manual steps required to produce aligned releases
- document a release checklist that covers build, smoke test, upload, and superseded-release handling

### 2. Improve Signal Quality And Reporting Clarity

- keep reducing noisy findings
- sharpen the "what deserves attention" story
- improve plain-language explanations without crossing into overconfident remediation advice
- make repeated scans and change tracking easier to interpret quickly

### 3. Strengthen The Product Story

- keep refining the positioning around visibility, organization, and change tracking
- make the difference between informational reporting and advice more explicit
- tighten the messaging for README, release pages, Discussions, and outreach posts

### 4. Prepare For Broader Distribution Requirements

- review app-store and platform compliance implications before subscription work
- specifically revisit the previously discussed Texas age-assurance and Apple distribution questions before monetization or broader store plans
- keep credentials, GitHub permissions, and release access healthy so process friction does not stall launches

## Longer-Term Product Bets

These are meaningful directions we have discussed that may become roadmap objectives later, but they are not the current focus.

- better behavior and finding explanations for non-technical users
- a clearer "where should I look next?" experience
- stronger change-history storytelling over time
- broader confidence-building around repeated audits and baseline comparisons

## Parked But Important

These remain intentionally out of scope until the current beta-hardening, release-alignment, and feedback-validation work is in a better place.

Direct reference: [parking-lot.md](./parking-lot.md)

Parked items that still make sense to retain:

- optional AI explanations of findings
- AI-assisted interpretation in common-user language
- scheduled audits beyond the current beta limitation
- change history timeline
- cross-device comparison
- future AI explanations settings and product-tiering decisions

## Working Order

When we are deciding what to do next, use this priority order:

1. Stabilize the beta experience.
2. Keep the packaged releases aligned across platforms.
3. Make it easier for testers to understand the app and respond.
4. Learn from outside feedback before pulling parked features into scope.

## Roadmap Checkpoints

When deciding what to work on next, these questions should come first:

1. Which current objective is active right now?
2. Which local or release changes are already in progress?
3. Are macOS and Windows builds aligned to the same source state?
4. Is the next task a beta-hardening task, a release task, or an outside-feedback task?

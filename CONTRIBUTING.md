# Contributing

Thanks for helping improve AuditOS.

## Before You Start

- Open an issue or start a discussion for larger changes
- Keep fixes focused when possible
- Avoid bundling unrelated cleanup into the same change

## Local Setup

```bash
python3 -m pip install -r requirements.txt
python3 app/main.py
```

## Contribution Priorities

- stability and crash fixes
- cross-platform audit accuracy
- clearer reporting and lower-noise findings
- packaging and release reliability
- documentation that helps testers and contributors

## Pull Request Guidelines

- describe the user-facing problem
- explain the approach you took
- note any platform-specific behavior
- include validation steps you ran
- include screenshots when UI changes are involved

## Testing Notes

AuditOS has platform-specific behavior. When possible, note:

- OS and version tested
- whether you ran Quick Audit or Deep Audit
- any permissions required for the result you observed

## Scope

AuditOS is an informational audit tool. Contributions should preserve the principle that the app informs the user rather than silently making system changes.

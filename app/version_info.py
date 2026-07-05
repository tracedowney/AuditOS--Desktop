from __future__ import annotations

# App version is what users download. Persistence and disclosure versions are
# separate so compatible beta-to-beta updates do not feel like fresh installs.
APP_VERSION = "0.5.0-beta"
DISCLOSURE_VERSION = "disclosure-v1"
PERSISTENCE_VERSION = "persistence-v1"

# Recent betas stored app/version identifiers directly in saved payloads.
# Keep them readable so current testers do not lose baselines or history when
# we move to schema-based versioning.
LEGACY_COMPATIBLE_DISCLOSURE_VERSIONS = frozenset({
    "0.4.4-beta",
    "0.4.5-beta",
    "0.4.6-beta",
    "0.5.0-beta",
})
LEGACY_COMPATIBLE_PERSISTENCE_VERSIONS = frozenset({
    "0.4.4-beta",
    "0.4.5-beta",
    "0.4.6-beta",
    "0.5.0-beta",
})


def is_compatible_disclosure_version(value: object) -> bool:
    normalized = str(value).strip()
    return normalized == DISCLOSURE_VERSION or normalized in LEGACY_COMPATIBLE_DISCLOSURE_VERSIONS


def is_compatible_persistence_version(value: object) -> bool:
    normalized = str(value).strip()
    return normalized == PERSISTENCE_VERSION or normalized in LEGACY_COMPATIBLE_PERSISTENCE_VERSIONS

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPOSITORY = "tracedowney/AuditOS--Desktop"
RELEASES_API_URL = f"https://api.github.com/repos/{REPOSITORY}/releases?per_page=20"
RELEASES_PAGE_URL = f"https://github.com/{REPOSITORY}/releases"

_VERSION_RE = re.compile(r"^v?(?P<number>\d+(?:\.\d+)*)(?P<suffix>.*)$")


class UpdateCheckError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReleaseInfo:
    tag_name: str
    name: str
    html_url: str
    prerelease: bool
    draft: bool
    published_at: str

    @property
    def version(self) -> str:
        return self.tag_name.strip().lstrip("v")

    @property
    def is_prerelease(self) -> bool:
        return self.prerelease or _is_prerelease_version(self.version)


@dataclass(frozen=True)
class UpdateCheckResult:
    status: str
    current_version: str
    channel_label: str
    release: ReleaseInfo | None
    message: str


def _stage_rank(version_label: str) -> int:
    suffix = _version_suffix(version_label)
    if not suffix:
        return 3
    if "rc" in suffix:
        return 2
    if "beta" in suffix:
        return 1
    if "alpha" in suffix:
        return 0
    return 1


def _version_suffix(version_label: str) -> str:
    match = _VERSION_RE.match(str(version_label).strip())
    if not match:
        return ""
    return match.group("suffix").strip().lower()


def _version_key(version_label: str) -> tuple[tuple[int, ...], int, str]:
    match = _VERSION_RE.match(str(version_label).strip())
    if not match:
        return ((-1,), -1, str(version_label).strip().lower())

    numbers = tuple(int(part) for part in match.group("number").split("."))
    suffix = match.group("suffix").strip().lower()
    return numbers, _stage_rank(version_label), suffix


def _compare_versions(left: str, right: str) -> int:
    left_key = _version_key(left)
    right_key = _version_key(right)
    if left_key > right_key:
        return 1
    if left_key < right_key:
        return -1
    return 0


def _is_prerelease_version(version_label: str) -> bool:
    return _stage_rank(version_label) < 3


def _release_sort_key(release: ReleaseInfo) -> tuple[tuple[int, ...], int, str, str]:
    numbers, stage_rank, suffix = _version_key(release.version)
    return numbers, stage_rank, suffix, release.published_at


def _latest_release(releases: Iterable[ReleaseInfo]) -> ReleaseInfo | None:
    items = list(releases)
    if not items:
        return None
    return max(items, key=_release_sort_key)


def fetch_releases(
    *,
    timeout: float = 5.0,
    urlopen_func: Callable[..., object] = urlopen,
) -> list[ReleaseInfo]:
    request = Request(
        RELEASES_API_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "AuditOS Update Checker",
        },
    )

    try:
        with urlopen_func(request, timeout=timeout) as response:
            payload = json.load(response)
    except HTTPError as exc:
        raise UpdateCheckError(f"GitHub returned HTTP {exc.code} while checking releases.") from exc
    except URLError as exc:
        raise UpdateCheckError("AuditOS could not reach GitHub Releases.") from exc
    except TimeoutError as exc:
        raise UpdateCheckError("The update check timed out before GitHub responded.") from exc
    except json.JSONDecodeError as exc:
        raise UpdateCheckError("AuditOS received an unreadable response from GitHub Releases.") from exc

    releases: list[ReleaseInfo] = []
    if not isinstance(payload, list):
        raise UpdateCheckError("GitHub Releases returned an unexpected payload.")

    for item in payload:
        if not isinstance(item, dict):
            continue

        tag_name = str(item.get("tag_name", "")).strip()
        if not tag_name:
            continue

        releases.append(
            ReleaseInfo(
                tag_name=tag_name,
                name=str(item.get("name", "")).strip(),
                html_url=str(item.get("html_url", RELEASES_PAGE_URL)).strip() or RELEASES_PAGE_URL,
                prerelease=bool(item.get("prerelease")),
                draft=bool(item.get("draft")),
                published_at=str(item.get("published_at", "")).strip(),
            )
        )

    return releases


def select_target_release(releases: Iterable[ReleaseInfo], current_version: str) -> ReleaseInfo | None:
    published_releases = [release for release in releases if not release.draft]
    if not published_releases:
        return None

    stable_releases = [release for release in published_releases if not release.is_prerelease]
    prerelease_releases = [release for release in published_releases if release.is_prerelease]

    if _is_prerelease_version(current_version):
        newer_prereleases = [
            release
            for release in prerelease_releases
            if _compare_versions(release.version, current_version) > 0
        ]
        if newer_prereleases:
            return _latest_release(newer_prereleases)

        newer_stable_releases = [
            release
            for release in stable_releases
            if _compare_versions(release.version, current_version) > 0
        ]
        if newer_stable_releases:
            return _latest_release(newer_stable_releases)

        return _latest_release(prerelease_releases) or _latest_release(stable_releases)

    newer_stable_releases = [
        release
        for release in stable_releases
        if _compare_versions(release.version, current_version) > 0
    ]
    if newer_stable_releases:
        return _latest_release(newer_stable_releases)

    return _latest_release(stable_releases)


def check_for_updates(
    current_version: str,
    *,
    fetcher: Callable[[], list[ReleaseInfo]] = fetch_releases,
) -> UpdateCheckResult:
    channel_label = "beta" if _is_prerelease_version(current_version) else "stable"
    releases = fetcher()
    target = select_target_release(releases, current_version)

    if target is None:
        return UpdateCheckResult(
            status="no_releases",
            current_version=current_version,
            channel_label=channel_label,
            release=None,
            message=f"AuditOS could not find any published {channel_label} releases yet.",
        )

    if _compare_versions(target.version, current_version) > 0:
        return UpdateCheckResult(
            status="update_available",
            current_version=current_version,
            channel_label=channel_label,
            release=target,
            message=f"AuditOS {target.version} is available on GitHub Releases.",
        )

    if channel_label == "beta":
        message = "You are already on the latest beta build AuditOS could find."
    else:
        message = "You are already on the latest published AuditOS release."

    return UpdateCheckResult(
        status="up_to_date",
        current_version=current_version,
        channel_label=channel_label,
        release=target,
        message=message,
    )

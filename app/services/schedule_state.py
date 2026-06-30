from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict


MAX_QTIMER_INTERVAL_MS = 2_147_483_647


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_schedule_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def format_schedule_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def schedule_interval(frequency: str) -> timedelta:
    return {
        "daily": timedelta(days=1),
        "weekly": timedelta(days=7),
        "monthly": timedelta(days=30),
    }.get(str(frequency).lower(), timedelta(days=7))


def ensure_schedule_next_run(
    settings: Dict[str, Any],
    now: datetime | None = None,
) -> Dict[str, Any]:
    updated = dict(settings)
    if not updated.get("schedule_enabled"):
        updated["schedule_next_run_at"] = None
        return updated

    now = now or utc_now()
    next_run_at = parse_schedule_timestamp(updated.get("schedule_next_run_at"))
    if next_run_at is None:
        next_run_at = now + schedule_interval(str(updated.get("schedule_frequency", "weekly")))
        updated["schedule_next_run_at"] = format_schedule_timestamp(next_run_at)

    return updated


def schedule_remaining_ms(
    settings: Dict[str, Any],
    now: datetime | None = None,
) -> int | None:
    if not settings.get("schedule_enabled"):
        return None

    now = now or utc_now()
    next_run_at = parse_schedule_timestamp(settings.get("schedule_next_run_at"))
    if next_run_at is None:
        return None

    return max(0, int((next_run_at - now).total_seconds() * 1000))


def next_schedule_timer_ms(
    settings: Dict[str, Any],
    now: datetime | None = None,
) -> int | None:
    remaining_ms = schedule_remaining_ms(settings, now=now)
    if remaining_ms is None:
        return None
    return min(remaining_ms, MAX_QTIMER_INTERVAL_MS)


def is_schedule_due(
    settings: Dict[str, Any],
    now: datetime | None = None,
) -> bool:
    remaining_ms = schedule_remaining_ms(settings, now=now)
    if remaining_ms is None:
        return False
    return remaining_ms <= 0


def mark_schedule_completed(
    settings: Dict[str, Any],
    completed_at: datetime | None = None,
) -> Dict[str, Any]:
    updated = dict(settings)
    completed_at = completed_at or utc_now()
    updated["schedule_last_run_at"] = format_schedule_timestamp(completed_at)
    updated["schedule_next_run_at"] = format_schedule_timestamp(
        completed_at + schedule_interval(str(updated.get("schedule_frequency", "weekly")))
    )
    return updated


def delay_schedule_until(
    settings: Dict[str, Any],
    delay_ms: int,
    now: datetime | None = None,
) -> Dict[str, Any]:
    updated = dict(settings)
    now = now or utc_now()
    updated["schedule_next_run_at"] = format_schedule_timestamp(
        now + timedelta(milliseconds=max(0, delay_ms))
    )
    return updated

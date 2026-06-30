from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services.schedule_state import (
    MAX_QTIMER_INTERVAL_MS,
    delay_schedule_until,
    ensure_schedule_next_run,
    format_schedule_timestamp,
    is_schedule_due,
    mark_schedule_completed,
    next_schedule_timer_ms,
)


def test_ensure_schedule_next_run_initializes_missing_timestamp():
    now = datetime(2026, 6, 12, 12, 0, tzinfo=timezone.utc)
    settings = {
        "schedule_enabled": True,
        "schedule_frequency": "weekly",
        "schedule_next_run_at": None,
    }

    updated = ensure_schedule_next_run(settings, now=now)

    assert updated["schedule_next_run_at"] == format_schedule_timestamp(now + timedelta(days=7))


def test_next_schedule_timer_ms_caps_monthly_interval_to_qtimer_limit():
    now = datetime(2026, 6, 12, 12, 0, tzinfo=timezone.utc)
    settings = {
        "schedule_enabled": True,
        "schedule_frequency": "monthly",
        "schedule_next_run_at": format_schedule_timestamp(now + timedelta(days=30)),
    }

    assert next_schedule_timer_ms(settings, now=now) == MAX_QTIMER_INTERVAL_MS


def test_mark_schedule_completed_sets_last_and_next_run():
    completed_at = datetime(2026, 6, 12, 12, 0, tzinfo=timezone.utc)
    settings = {
        "schedule_enabled": True,
        "schedule_frequency": "daily",
    }

    updated = mark_schedule_completed(settings, completed_at=completed_at)

    assert updated["schedule_last_run_at"] == format_schedule_timestamp(completed_at)
    assert updated["schedule_next_run_at"] == format_schedule_timestamp(completed_at + timedelta(days=1))


def test_delay_schedule_until_marks_retry_window():
    now = datetime(2026, 6, 12, 12, 0, tzinfo=timezone.utc)
    settings = {
        "schedule_enabled": True,
        "schedule_frequency": "weekly",
    }

    updated = delay_schedule_until(settings, 15 * 60 * 1000, now=now)

    assert updated["schedule_next_run_at"] == format_schedule_timestamp(now + timedelta(minutes=15))


def test_is_schedule_due_detects_overdue_runs():
    now = datetime(2026, 6, 12, 12, 0, tzinfo=timezone.utc)
    settings = {
        "schedule_enabled": True,
        "schedule_frequency": "weekly",
        "schedule_next_run_at": format_schedule_timestamp(now - timedelta(minutes=1)),
    }

    assert is_schedule_due(settings, now=now) is True

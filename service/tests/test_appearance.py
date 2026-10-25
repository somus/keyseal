from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

from keyseal_service.appearance import signed_on, two_lines


def test_names_split_into_two_even_lines() -> None:
    assert two_lines("Somasundaram Ayyappan") == "Somasundaram\nAyyappan"
    assert two_lines("Chenthil Kumar S") == "Chenthil\nKumar S"
    assert two_lines("PRIYA S RAGHAVAN") == "PRIYA S\nRAGHAVAN"
    assert two_lines("Madonna") == "Madonna"


def test_dates_show_with_their_offset() -> None:
    at = datetime(2026, 10, 20, 4, 35, 25, tzinfo=UTC)
    assert signed_on(at.astimezone(timezone(timedelta(hours=5, minutes=30)))) == (
        "2026.10.20 10:05:25 +05'30'"
    )
    assert signed_on(at) == "2026.10.20 04:35:25 +00'00'"

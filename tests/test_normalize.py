"""Defang/refang round-trip tests."""

from __future__ import annotations

import pytest

from ledgerhound.extract.normalize import defang, refang


@pytest.mark.parametrize(
    "value",
    [
        "http://evil.example.com/login",
        "https://evil.example.com/login?x=1",
        "evil.example.com",
        "sub.evil.example.co.uk",
    ],
)
def test_defang_refang_round_trip(value: str) -> None:
    assert refang(defang(value)) == value


def test_defang_produces_expected_output() -> None:
    assert defang("https://evil.example.com") == "hxxps://evil[.]example[.]com"


@pytest.mark.parametrize(
    "defanged,expected",
    [
        ("hxxp://evil[.]example[.]com", "http://evil.example.com"),
        ("hxxps://evil[.]example[.]com", "https://evil.example.com"),
        ("evil(dot)example(dot)com", "evil.example.com"),
        ("evil[dot]example[dot]com", "evil.example.com"),
        ("user[at]evil.example.com", "user@evil.example.com"),
    ],
)
def test_refang_variants(defanged: str, expected: str) -> None:
    assert refang(defanged) == expected

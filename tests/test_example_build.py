"""The sanitised example rebuilds from fixtures and matches the committed text."""

from __future__ import annotations

from pathlib import Path

from ledgerhound.example_campaign import REPO_ROOT, build_example

COMMITTED = REPO_ROOT / "examples" / "LH-2026-001"
TEXT_FILES = (
    "report.md",
    "stix-bundle.json",
    "misp-event.json",
    "README.md",
    "ioc-feed/LH-2026-001.json",
    "ioc-feed/iocs.json",
    "ioc-feed/feed.json",
)


def test_example_text_artifacts_are_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    build_example(first, screenshot=False)
    build_example(second, screenshot=False)

    for name in TEXT_FILES:
        assert (first / name).read_bytes() == (second / name).read_bytes()
        assert (first / name).read_bytes() == (COMMITTED / name).read_bytes()

    report = (first / "report.md").read_text(encoding="utf-8")
    assert "SANITISED EXAMPLE" in report
    assert "wallet-support.example" in report
    assert "Herman K. (finsecguy)" in report
    bundle = (first / "stix-bundle.json").read_text(encoding="utf-8")
    assert "Herman K. (finsecguy)" in bundle
    assert (first / "report.pdf").read_bytes().startswith(b"%PDF")
    assert (first / "campaign-graph.png").read_bytes().startswith(b"\x89PNG")


def test_example_dashboard_screenshot(tmp_path: Path) -> None:
    out = tmp_path / "shot"
    build_example(out, screenshot=True)
    png = (out / "dashboard.png").read_bytes()
    assert png.startswith(b"\x89PNG")
    assert len(png) > 1000

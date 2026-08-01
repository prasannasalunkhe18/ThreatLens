from rich.console import Console

from threatlens.banner import BANNER, OWL, render_banner

OWL_LINES = [
    '          ,_,',
    '         (O,O)',
    '         (   )',
    '         -"-"--------------------------------',
]


def test_owl_is_exactly_four_lines():
    assert OWL.splitlines() == OWL_LINES


def test_banner_contains_exact_owl_lines():
    for line in OWL_LINES:
        assert line in BANNER.splitlines()


def test_owl_sits_directly_above_title_with_one_blank_line():
    lines = BANNER.splitlines()
    assert lines[:4] == OWL_LINES
    assert lines[4] == ""
    assert lines[5].startswith("████████╗")


def test_banner_has_title_and_tagline():
    assert "THREATLENS • Watching Every Code Path - By Prasanna" in BANNER


def test_render_banner_emits_owl_unmodified():
    console = Console(width=120, record=True, legacy_windows=False)
    render_banner(console)
    out = console.export_text().splitlines()
    for line in OWL_LINES:
        assert line in out

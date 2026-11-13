import pandas as pd

import ui


def test_tile_shows_status_with_symbol_and_word():
    h = ui.tile("Server CPU", 74, "%", "peak", "warn", spark=[1, 5, 3, 8, 2])
    assert "Warning" in h and "▲" in h and "<img" in h
    assert "Critical" in ui.tile("x", 1, level="bad")
    assert "tag" not in ui.tile("x", 1)          # no status, no tag


def test_toplist_scales_bars_and_escapes():
    h = ui.toplist([("<b>a</b>", 10), ("b", 5, "extra")])
    assert "&lt;b&gt;" in h and "--w:100%" in h and "--w:50%" in h
    assert "Nothing to show" in ui.toplist([])


def test_honeycomb_has_one_hover_point_per_slot():
    idx = pd.date_range("2026-10-21", periods=288, freq="5min")
    fig = ui.honeycomb(pd.Series(range(288), index=idx).mod(100).astype(float), 60, 80)
    hover = [t for t in fig.data if t.mode == "markers"][0]
    assert len(hover.x) == 24 * 12
    assert any(t.line.color == ui.CRIT for t in fig.data if t.mode == "lines")   # alert outline present


def test_ts_panels_one_row_per_panel():
    idx = pd.date_range("2026-10-21", periods=20, freq="5min")
    ev = pd.DataFrame({"start": [idx[3]], "title": ["x"], "category": ["c"]})
    fig = ui.ts_panels([dict(title="a", traces=[dict(x=idx, y=list(range(20)), name="a")]),
                        dict(title="b", traces=[dict(x=idx, y=list(range(20)), name="b", kind="bar")])], ev)
    assert len(fig.layout.annotations) == 2 and fig.layout.hovermode == "x unified"

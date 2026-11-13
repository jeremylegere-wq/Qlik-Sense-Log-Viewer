"""Look and feel for the Event Manager: colours, page styling, and the small building blocks the pages use
(stat tiles, top-lists, section bands, the root-cause banner, the CPU honeycomb and stacked time-series panels).

The HTML helpers return strings so they can be tested without Streamlit. Colours follow a validated palette
(categorical blue / orange / aqua ..., fixed status colours, one-hue sequential blue); status is always shown with
a symbol and a word, never colour alone.
"""
from __future__ import annotations

import html
import math
from urllib.parse import quote

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# ---- palette ---------------------------------------------------------------------------------------
BLUE, ORANGE, AQUA, YELLOW, MAGENTA, GREEN, VIOLET, RED_S = (
    "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948")
GOOD, WARN, SERIOUS, CRIT = "#0ca30c", "#fab219", "#ec835a", "#d03b3b"        # status colours (reserved)
INK, INK2, MUTED, GRID, LINE = "#1d1b26", "#52514e", "#898781", "#e8e6ee", "#dcdae3"
RAIL, ACCENT, CANVAS = "#241f33", "#5b2ea6", "#f1f0f4"
SEQ = ["#cde2fb", "#b7d3f6", "#9ec5f4", "#6da7ec", "#3987e5", "#2a78d6", "#1c5cab", "#104281", "#0d366b"]
SEQ_SCALE = [[i / (len(SEQ) - 1), c] for i, c in enumerate(SEQ)]
LEVELS = {  # level -> (colour, symbol, word)
    "good": (GOOD, "✓", "Healthy"), "warn": (WARN, "▲", "Warning"), "bad": (CRIT, "✖", "Critical"),
    "info": (BLUE, "●", "Info"), "none": (MUTED, "–", "No data"),
}
FONT = '"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif'

# ---- page navigation -------------------------------------------------------------------------------
# (page id, material icon, group)
NAV = [
    ("Overview", "dashboard", "Monitor"),
    ("Events", "flag", "Monitor"),
    ("Reported issues", "report", "Monitor"),
    ("Apps", "apps", "Apps and data"),
    ("Storage", "storage", "Apps and data"),
    ("Server CPU", "speed", "Qlik server"),
    ("Reloads", "autorenew", "Qlik server"),
    ("Reload failures", "error", "Qlik server"),
    ("Logins & proxy", "login", "Qlik server"),
    ("Requests", "swap_vert", "Qlik server"),
    ("Engine overview", "insights", "Engine"),
    ("Engine health", "monitor_heart", "Engine"),
    ("Restart history", "restart_alt", "Engine"),
    ("Apps & users", "groups", "Engine"),
    ("System events", "receipt_long", "Engine"),
    ("Trends", "trending_up", "Engine"),
    ("Log setup guide", "tune", "Share"),
    ("Qlik Community search", "travel_explore", "Share"),
    ("Export", "download", "Share"),
]


def css(active: str = "Overview") -> str:
    key = "nav_" + "".join(ch if ch.isalnum() else "_" for ch in active.lower())
    return f"""
<style>
:root{{--ink:{INK};--ink2:{INK2};--muted:{MUTED};--line:{LINE};--canvas:{CANVAS};--accent:{ACCENT};--rail:{RAIL}}}
html,body,.stApp,[data-testid="stAppViewContainer"]{{background:var(--canvas)!important;color:var(--ink);font-family:{FONT}}}
.stApp *{{font-family:inherit}}
.stApp [data-testid="stIconMaterial"],.stApp .material-icons,.stApp [class*="material-symbols"]{{font-family:"Material Symbols Rounded","Material Icons"!important}}
[data-testid="stHeader"],footer,[data-testid="stToolbar"],[data-testid="stSidebarCollapseButton"],
[data-testid="stSidebarCollapsedControl"],[data-testid="stDecoration"]{{display:none!important}}
[data-testid="stMainBlockContainer"],.block-container{{padding:.9rem 1.7rem 3rem!important;max-width:1700px}}
h1,h2,h3{{letter-spacing:0}}
/* ---- rail ---- */
[data-testid="stSidebar"]{{background:var(--rail)!important;min-width:232px!important;max-width:232px!important;width:232px!important;border-right:0}}
[data-testid="stSidebar"]>div{{background:var(--rail)!important}}
[data-testid="stSidebarContent"]{{padding:0 .5rem 1rem}}
[data-testid="stSidebar"] [data-testid="stVerticalBlock"]{{gap:.12rem}}
.rail-brand{{display:flex;align-items:center;gap:10px;padding:16px 10px 14px;color:#fff}}
.rail-brand b{{font-size:1.02rem;font-weight:650;line-height:1.15;display:block}}
.rail-brand span{{font-size:.72rem;color:#a39cbb;display:block}}
.rail-group{{color:#8d86a6;font-size:.68rem;font-weight:700;letter-spacing:.09em;text-transform:uppercase;padding:16px 12px 8px;margin:0 0 6px}}
[data-testid="stSidebar"] .stButton{{margin:0}}
[data-testid="stSidebar"] .stButton button{{width:100%;justify-content:flex-start;background:transparent;border:0;border-radius:7px;
  color:#d6d1e6;padding:.38rem .7rem;min-height:2.1rem;font-size:.9rem;font-weight:500;box-shadow:none}}
[data-testid="stSidebar"] .stButton button p{{font-size:.9rem;font-weight:500;color:inherit;text-align:left}}
[data-testid="stSidebar"] .stButton button>div,[data-testid="stSidebar"] .stButton button>div>span{{display:flex!important;justify-content:flex-start!important;width:100%;text-align:left}}
[data-testid="stSidebar"] .stButton button>div>span{{gap:.55rem;align-items:center}}
[data-testid="stSidebar"] .stButton button:hover{{background:rgba(255,255,255,.07);color:#fff}}
[data-testid="stSidebar"] .stButton button:focus{{box-shadow:none;outline:none}}
.st-key-{key} button{{background:rgba(155,127,224,.22)!important;color:#fff!important;box-shadow:inset 3px 0 0 #b79bf0!important}}
.rail-foot{{color:#8d86a6;font-size:.72rem;padding:14px 12px 4px;line-height:1.5}}
/* ---- top bar ---- */
.crumb{{color:var(--muted);font-size:.78rem;margin:0 0 1px}}
.ptitle{{font-size:1.55rem;font-weight:650;line-height:1.15;margin:0;color:var(--ink)}}
.pill{{display:inline-flex;align-items:center;gap:6px;font-size:.78rem;font-weight:650;padding:3px 11px;border-radius:999px;
  border:1px solid var(--c);color:var(--ink);background:color-mix(in srgb,var(--c) 12%,#fff);white-space:nowrap}}
.pill i{{font-style:normal;color:var(--c);font-weight:800}}
.stApp a[data-testid="stLinkButton"],.stApp [data-testid="stBaseLinkButton-secondary"],[data-testid="stPopover"] button{{border-radius:8px}}
/* ---- cards (widgets) ---- */
[class*="st-key-card"]{{background:#fff;border:1px solid var(--line)!important;border-radius:10px;box-shadow:0 1px 2px rgba(29,27,38,.05);padding:4px 10px 6px}}
.ct{{font-weight:650;color:var(--ink);font-size:.95rem;margin:2px 0 0}}
.cs{{color:var(--muted);font-size:.8rem;margin:1px 0 6px;line-height:1.35}}
.sec{{background:#e4e2ec;color:var(--ink);font-weight:650;font-size:1rem;text-align:center;padding:9px 0;border-radius:6px;margin:18px 0 10px;
  letter-spacing:.01em}}
.sec small{{font-weight:500;color:var(--ink2);font-size:.8rem;margin-left:8px}}
/* ---- stat tiles ---- */
.tile{{background:#fff;border:1px solid var(--line);border-radius:10px;padding:11px 14px 10px;box-shadow:0 1px 2px rgba(29,27,38,.05);
  margin-bottom:8px;position:relative;min-height:112px;overflow:hidden}}
.tile:before{{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--c)}}
.tile .tl{{font-size:.74rem;color:var(--ink2);font-weight:650;text-transform:uppercase;letter-spacing:.04em;display:flex;justify-content:space-between;gap:6px;white-space:nowrap}}
.tile .tv{{font-size:2.15rem;font-weight:650;line-height:1.15;color:var(--ink);margin-top:2px}}
.tile .tv small{{font-size:1rem;font-weight:600;color:var(--ink2);margin-left:2px}}
.tile .ts{{font-size:.78rem;color:var(--muted);margin-top:1px}}
.tile .tag{{font-size:.68rem;font-weight:700;color:var(--ink);text-transform:none;letter-spacing:0;flex-shrink:0}}
.tile .tag b{{font-weight:700}}
.tile .tl span:first-child{{overflow:hidden;text-overflow:ellipsis;min-width:0}}
.tile{{container-type:inline-size}}
@container (max-width:250px){{.tile .tag b{{display:none}}}}
.tile .tag i{{font-style:normal;color:var(--c);margin-right:3px}}
.tile img.spark{{position:absolute;right:10px;top:30px;width:40%;height:28px;opacity:.95}}
/* ---- top lists ---- */
.tlist{{display:flex;flex-direction:column;gap:5px;margin:4px 0 2px}}
.tr{{display:flex;align-items:center;gap:8px;font-size:.82rem}}
.tr .v{{width:3.6rem;text-align:right;font-weight:650;color:var(--ink);flex:none;font-variant-numeric:tabular-nums}}
.tr .b{{flex:1;position:relative;height:24px;border-radius:4px;background:#f3f2f7;overflow:hidden;min-width:0}}
.tr .b i{{position:absolute;left:0;top:0;bottom:0;width:var(--w);background:var(--c);opacity:.38;border-radius:4px}}
.tr .b span{{position:relative;display:block;line-height:24px;padding:0 8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--ink)}}
.tr .b em{{font-style:normal;color:var(--muted);margin-left:6px}}
/* ---- findings / chips ---- */
.fi{{border-left:4px solid var(--c);background:#f7f6fa;border-radius:8px;padding:8px 12px;margin:8px 0}}
.fi summary{{cursor:pointer;font-weight:650;color:var(--ink);font-size:.9rem}}
.fi .fd{{color:var(--ink2);font-size:.83rem;margin:6px 0 2px;line-height:1.4}}
.chip{{font-size:.68rem;font-weight:700;padding:1px 8px;border-radius:10px;color:#fff;background:var(--tone);letter-spacing:.02em}}
.chip.light{{color:var(--ink)}}
.evrow{{display:flex;align-items:center;gap:8px;padding:6px 2px;border-bottom:1px solid #eeedf3;font-size:.86rem}}
.evrow:last-child{{border-bottom:0}}
.evrow .t{{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.evrow .w{{color:var(--muted);font-size:.76rem;white-space:nowrap}}
/* ---- banners ---- */
.banner{{background:#fff;border:1px solid var(--line);border-left:5px solid var(--c);border-radius:10px;padding:12px 16px;margin:2px 0 10px}}
.banner b{{font-size:1.02rem}}
.banner .bd{{color:var(--ink2);font-size:.86rem;margin-top:2px}}
.rca{{display:grid;grid-template-columns:1fr 28px 1fr 28px 1fr;align-items:stretch;margin:4px 0 10px}}
.rca .box{{border-radius:8px;padding:10px 14px;border:1px solid var(--line);border-top:4px solid var(--c);background:#fff}}
.rca .k{{font-size:.7rem;font-weight:750;letter-spacing:.07em;text-transform:uppercase;color:var(--c)}}
.rca .h{{font-weight:650;font-size:.95rem;margin:3px 0 2px;line-height:1.3;color:var(--ink)}}
.rca .d{{font-size:.8rem;color:var(--ink2);line-height:1.35}}
.rca .ar{{display:flex;align-items:center;justify-content:center;color:{MUTED};font-size:1.5rem}}
@media (max-width:1100px){{.rca{{grid-template-columns:1fr}} .rca .ar{{transform:rotate(90deg);height:22px}}}}
.ah{{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 12px;margin:0 0 4px}}
.ah .an{{font-size:1.35rem;font-weight:700;color:var(--ink);letter-spacing:-.01em}}
.ah .chips{{display:flex;gap:6px;flex-wrap:wrap}}
.am{{color:var(--ink2);font-size:.83rem;line-height:1.5}}
.am code{{font-size:.76rem;background:#f1eff6;padding:1px 5px;border-radius:5px}}
.kv{{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;font-size:.84rem;color:var(--ink2)}}
.kv b{{color:var(--ink);font-weight:600}}
.steps{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:6px 0 14px}}
.step{{background:#fff;border:1px solid var(--line);border-radius:10px;padding:16px 18px}}
.step .n{{display:inline-block;width:26px;height:26px;border-radius:50%;background:var(--accent);color:#fff;font-weight:700;text-align:center;line-height:26px}}
.step h4{{margin:8px 0 4px;color:var(--ink);font-size:1.02rem}}
.step p{{margin:0;color:var(--ink2);font-size:.86rem;line-height:1.4}}
.note{{color:var(--ink2);font-size:.82rem}}
</style>"""


# ---- small HTML helpers ----------------------------------------------------------------------------
def esc(x) -> str:
    return html.escape(str(x))


def pill(level: str, text: str = "") -> str:
    c, sym, word = LEVELS.get(level, LEVELS["info"])
    return f'<span class="pill" style="--c:{c}"><i>{sym}</i>{esc(text or word)}</span>'


def chip(text, colour: str, dark_text: bool = False) -> str:
    return f'<span class="chip{" light" if dark_text else ""}" style="--tone:{colour}">{esc(text)}</span>'


def sparkline(values, colour: str = BLUE) -> str:
    """A tiny trend line as an <img> with an inline SVG data URI (no axes; the tile's number carries the value)."""
    v = [float(x) for x in values if x is not None and not (isinstance(x, float) and math.isnan(x))]
    if len(v) < 3:
        return ""
    if len(v) > 80:                       # thin out long series so the markup stays small
        step = len(v) / 80
        v = [v[int(i * step)] for i in range(80)]
    lo, hi = min(v), max(v)
    span = (hi - lo) or 1.0
    pts = " ".join(f"{i * 100 / (len(v) - 1):.1f},{30 - (x - lo) / span * 26 - 2:.1f}" for i, x in enumerate(v))
    svg = (f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 30' preserveAspectRatio='none'>"
           f"<polyline points='{pts}' fill='none' stroke='{colour}' stroke-width='1.8' stroke-linejoin='round' "
           f"vector-effect='non-scaling-stroke'/></svg>")
    return f'<img class="spark" alt="" src="data:image/svg+xml;utf8,{quote(svg)}">'


def tile(label: str, value, unit: str = "", sub: str = "", level: str = "", spark=None) -> str:
    c, sym, word = LEVELS.get(level or "none", LEVELS["none"])
    colour = c if level else "#c9c6d6"
    tag = f'<span class="tag" title="{word}"><i>{sym}</i><b>{word}</b></span>' if level in ("good", "warn", "bad") else ""
    u = f"<small>{esc(unit)}</small>" if unit else ""
    sp = sparkline(spark, c if level else BLUE) if spark is not None else ""
    return (f'<div class="tile" style="--c:{colour}"><div class="tl"><span title="{esc(label)}">{esc(label)}</span>{tag}</div>'
            f'<div class="tv">{esc(value)}{u}</div><div class="ts">{esc(sub)}&nbsp;</div>{sp}</div>')


def toplist(rows, colour: str = BLUE, fmt: str = "{:,.0f}", vmax: float | None = None) -> str:
    """rows: [(label, value[, extra text])] biggest first. Value on the left, a bar behind the label."""
    rows = list(rows)
    if not rows:
        return '<div class="note">Nothing to show for this window.</div>'
    top = vmax or max((r[1] for r in rows), default=1) or 1
    out = []
    for r in rows:
        label, val = r[0], r[1]
        extra = f"<em>{esc(r[2])}</em>" if len(r) > 2 and r[2] else ""
        w = max(2.0, min(100.0, float(val) / top * 100))
        out.append(f'<div class="tr"><div class="v">{fmt.format(val)}</div><div class="b" style="--w:{w:.0f}%;--c:{colour}">'
                   f'<i></i><span title="{esc(label)}">{esc(label)}{extra}</span></div></div>')
    return '<div class="tlist">' + "".join(out) + "</div>"


def section(title: str, sub: str = "") -> str:
    return f'<div class="sec">{esc(title)}{f"<small>{esc(sub)}</small>" if sub else ""}</div>'


def banner(level: str, headline: str, detail: str = "") -> str:
    c = LEVELS.get(level, LEVELS["info"])[0]
    return (f'<div class="banner" style="--c:{c}"><b>{esc(headline)}</b>'
            + (f'<div class="bd">{esc(detail)}</div>' if detail else "") + "</div>")


def rca_banner(root: dict, failure: dict, impact: dict) -> str:
    """Root cause -> critical failure -> impact. Each dict: head, text (and optional colour)."""
    def box(k, d, c):
        return (f'<div class="box" style="--c:{d.get("colour", c)}"><div class="k">{k}</div>'
                f'<div class="h">{esc(d.get("head", ""))}</div><div class="d">{esc(d.get("text", ""))}</div></div>')
    return ('<div class="rca">' + box("Likely root cause", root, ACCENT) + '<div class="ar">➜</div>'
            + box("Failure", failure, CRIT) + '<div class="ar">➜</div>' + box("Impact", impact, SERIOUS) + "</div>")


# ---- Plotly look -----------------------------------------------------------------------------------
def style(fig: go.Figure, height: int | None = None, legend_below: bool = False, crosshair: bool = False) -> go.Figure:
    if height:
        fig.update_layout(height=height)
    fig.update_layout(
        template="plotly_white", font=dict(family=FONT, color=INK2, size=12), paper_bgcolor="#fff", plot_bgcolor="#fff",
        colorway=[BLUE, ORANGE, AQUA, VIOLET, YELLOW, MAGENTA, GREEN, RED_S], margin=dict(l=10, r=12, t=30, b=10),
        legend=dict(orientation="h", yanchor="bottom", y=1.0, xanchor="left", x=0, font=dict(size=11)),
        hoverlabel=dict(font=dict(family=FONT, size=12), bgcolor="#1d1b26", font_color="#fff", bordercolor="#1d1b26"),
    )
    if not fig.layout.title.text:
        fig.update_layout(title_text="")  # older Streamlit/plotly.js print "undefined" for a title without text
    else:
        fig.update_layout(title_font=dict(size=13, color=INK))
    fig.update_xaxes(gridcolor=GRID, zeroline=False, linecolor=LINE, tickfont=dict(size=11, color=MUTED), ticks="outside",
                     tickcolor=LINE)
    fig.update_yaxes(gridcolor=GRID, zeroline=False, linecolor="rgba(0,0,0,0)", tickfont=dict(size=11, color=MUTED))
    if legend_below:
        try:   # legend in the figure's bottom margin, clear of the axis labels
            fig.update_layout(legend=dict(orientation="h", yref="container", yanchor="bottom", y=0.0, xanchor="left", x=0),
                              margin=dict(l=10, r=12, t=14, b=58))
        except ValueError:   # older plotly without legend.yref
            fig.update_layout(legend=dict(orientation="h", yanchor="top", y=-0.18, xanchor="left", x=0),
                              margin=dict(l=10, r=12, t=14, b=10))
    if crosshair:
        fig.update_layout(hovermode="x unified")
        fig.update_xaxes(showspikes=True, spikemode="across", spikesnap="cursor", spikedash="solid", spikethickness=1,
                         spikecolor=INK)
    return fig


def ts_panels(panels: list[dict], events: pd.DataFrame | None = None, x_range=None, row_px: int = 190) -> go.Figure:
    """Stacked time-series panels on one shared time axis (one measure per panel, one y-scale each).

    panel = {title, unit, ymax (optional), height (relative weight), traces:[{x, y, name, colour, kind:line|step|bar|area,
    dash}], hlines:[(y, colour, label)]}.  `events` (start, title, category, severity) draws dotted vertical lines."""
    n = len(panels)
    weights = [p.get("height", 1.0) for p in panels]
    fig = make_subplots(rows=n, cols=1, shared_xaxes=True, vertical_spacing=0.07 if n > 2 else 0.1,
                        row_heights=[w / sum(weights) for w in weights],
                        subplot_titles=[p["title"] for p in panels])
    for i, p in enumerate(panels, 1):
        for t in p["traces"]:
            kind, col = t.get("kind", "line"), t.get("colour", BLUE)
            if kind == "bar":
                fig.add_bar(x=t["x"], y=t["y"], name=t["name"], marker_color=col, marker_line_width=0, row=i, col=1,
                            hovertemplate="%{y:,.0f}")
            else:
                fig.add_scatter(x=t["x"], y=t["y"], name=t["name"], mode="lines", row=i, col=1,
                                line=dict(color=col, width=t.get("width", 2), dash=t.get("dash", "solid"),
                                          shape="hv" if kind == "step" else "linear"),
                                fill="tozeroy" if kind in ("area", "step") else None,
                                fillcolor=_alpha(col, .12), hovertemplate="%{y:,.1f}" if p.get("dec") else "%{y:,.0f}")
        for y, colr, label in p.get("hlines", []):
            fig.add_hline(y=y, line_dash="dot", line_color=colr, line_width=1.2, row=i, col=1,
                          annotation_text=label, annotation_position="top right",
                          annotation_font=dict(size=10, color=colr if colr != WARN else "#a87400"))
        top = p.get("ymax")
        fig.update_yaxes(range=[0, top] if top else None, rangemode="tozero", ticksuffix=p.get("unit", ""), row=i, col=1)
    if events is not None and len(events):
        fig.add_scatter(x=events["start"], y=[panels[0].get("ymax") or 100] * len(events), mode="markers", name="Events",
                        marker=dict(symbol="square", size=9, color=ACCENT, line=dict(color="#fff", width=1)),
                        customdata=events[["title", "category"]],
                        hovertemplate="<b>%{customdata[0]}</b> · %{customdata[1]}", row=1, col=1)
        for s in events["start"]:
            fig.add_shape(type="line", x0=s, x1=s, y0=0, y1=1, xref="x", yref="paper", line=dict(color=ACCENT, width=1, dash="dot"),
                          opacity=.55, layer="below")
    style(fig, height=row_px * n + 40, crosshair=True)
    fig.update_layout(showlegend=False, margin=dict(l=10, r=12, t=26, b=10))
    for a in fig.layout.annotations:           # panel titles: left-aligned, small, bold
        if a.text in [p["title"] for p in panels]:
            a.update(x=0, xanchor="left", font=dict(size=12, color=INK, family=FONT))
    if x_range is not None:
        fig.update_xaxes(range=list(x_range))
    return fig


def _alpha(hex_colour: str, a: float) -> str:
    h = hex_colour.lstrip("#")
    return f"rgba({int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)},{a})"


# ---- CPU honeycomb ---------------------------------------------------------------------------------
def hex_poly(cx: float, cy: float, r: float = 0.94):
    return [(cx + r * math.cos(math.radians(a)), cy + r * math.sin(math.radians(a))) for a in range(0, 361, 60)]


def honeycomb(s: pd.Series, thr_warn: float, thr_crit: float, title: str = "", slot_min: int = 5) -> go.Figure:
    """One day of samples as hexagons: a column per hour, a row per 5-minute slot. A scheduled cycle shows up as
    bands across the rows. s: values indexed by timestamp (one day). Red outline = at or above the alert line."""
    s = s.dropna()
    slots = 60 // slot_min
    day = s.index.min().normalize() if len(s) else pd.Timestamp.today().normalize()
    sq3 = math.sqrt(3)
    vals = {}
    for ts, v in s.items():
        vals[(ts.hour, ts.minute // slot_min)] = max(v, vals.get((ts.hour, ts.minute // slot_min), -1))
    bins = [[] for _ in SEQ]
    empty, hot, hx, hy, htxt = [], [], [], [], []
    for h in range(24):
        for m in range(slots):
            cx, cy = h * 1.5, m * sq3 + (h % 2) * sq3 / 2
            ts = day + pd.Timedelta(hours=h, minutes=m * slot_min)
            poly = hex_poly(cx, cy)
            if (h, m) not in vals:
                empty.append(poly)
                hx.append(cx); hy.append(cy); htxt.append(f"{ts:%a %d %b %H:%M}<br>no sample")
                continue
            v = vals[(h, m)]
            bins[min(len(SEQ) - 1, int(max(v, 0) / 100 * len(SEQ)))].append(poly)
            if v >= thr_crit:
                hot.append(poly)
            hx.append(cx); hy.append(cy); htxt.append(f"{ts:%a %d %b %H:%M}<br><b>{v:.0f}%</b>")

    def trace(polys, **kw):
        xs, ys = [], []
        for p in polys:
            xs += [q[0] for q in p] + [None]
            ys += [q[1] for q in p] + [None]
        return go.Scatter(x=xs, y=ys, hoverinfo="skip", showlegend=False, **kw)

    fig = go.Figure()
    if empty:
        fig.add_trace(trace(empty, mode="lines", fill="toself", fillcolor="#f1f0f4", line=dict(color="#e4e2ec", width=.5)))
    for i, polys in enumerate(bins):
        if polys:
            fig.add_trace(trace(polys, mode="lines", fill="toself", fillcolor=SEQ[i], line=dict(color="#fff", width=.6)))
    if hot:
        fig.add_trace(trace(hot, mode="lines", line=dict(color=CRIT, width=2.2)))
    fig.add_trace(go.Scatter(x=hx, y=hy, mode="markers", marker=dict(size=14, color="rgba(0,0,0,0)"), showlegend=False,
                             text=htxt, hovertemplate="%{text}<extra></extra>"))
    ymax = (slots - 1) * sq3 + sq3 / 2 + 1
    style(fig, height=330)
    fig.update_xaxes(range=[-1.2, 23 * 1.5 + 1.2], tickvals=[h * 1.5 for h in range(0, 24, 2)],
                     ticktext=[f"{h:02d}" for h in range(0, 24, 2)], showgrid=False, constrain="domain", ticks="",
                     side="top", title=None)
    fig.update_yaxes(range=[ymax, -1], tickvals=[m * sq3 for m in range(0, slots, 3)],
                     ticktext=[f":{m * slot_min:02d}" for m in range(0, slots, 3)], showgrid=False, scaleanchor="x",
                     scaleratio=1, ticks="")
    fig.update_layout(margin=dict(l=4, r=4, t=26, b=4), title_text=title or "", hovermode="closest")
    if title:
        fig.update_layout(title_font=dict(size=13, color=INK), title_x=0, title_y=.99)
    return fig

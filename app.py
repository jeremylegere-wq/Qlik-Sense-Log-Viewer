"""Qlik Server Event Manager.

Run:  streamlit run app.py
Reads the Qlik Sense logs from the ArchivedLogs share (engine, repository, proxy, scheduler) plus the audit-count
PowerShell outputs, turns them into events you can triage (status, owner, notes), and shows what was happening on the
server at the time. Qlik Community search builds a web search from what was seen. Reading the logs is read-only.
"""
from __future__ import annotations

import hashlib
import html
import inspect
import io
import os
import pathlib
import re
from contextlib import contextmanager
from datetime import timedelta

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from plotly.subplots import make_subplots

import qlik_catalog as qc
import incident_rules as R
import qlik_events as qe
import qlik_incident as qi
import qlik_logs as q
import qlik_proxy as qp
import qlik_reloads as qr
import qlik_search as qsr
import site_config
import qlik_reports as qrp
import qlik_restart as qrs
import qlik_share as qs
import ui
from version import APP_NAME, __version__

st.set_page_config(page_title=APP_NAME, page_icon="📈", layout="wide", initial_sidebar_state="expanded")

# Series colours (validated palette in ui.py). Old names kept so the chart code reads the same.
NAVY, BLUE, MID_BLUE, GREEN, DEEP_GREEN, RED, AMBER = ui.INK, ui.BLUE, "#6da7ec", ui.AQUA, ui.GREEN, ui.CRIT, ui.WARN
INK, MUTED = ui.INK, ui.MUTED
HEAT = ui.SEQ_SCALE
SEV_C = {"High": ui.CRIT, "Medium": ui.SERIOUS, "Low": ui.BLUE}
STATUS_C = {"New": ui.CRIT, "Investigating": ui.SERIOUS, "Monitoring": ui.BLUE, "Resolved": ui.GOOD, "Ignored": "#9a98a6"}
SEV_COLOUR = {"high": ui.CRIT, "medium": ui.SERIOUS, "info": ui.BLUE}

ss = st.session_state
for _k, _v in ss.pop("_pending", {}).items():
    ss[_k] = _v
ss.setdefault("page", "Overview")
if ss["page"] not in [p for p, _, _ in ui.NAV]:
    ss["page"] = "Overview"
PAGE = ss["page"]


def columns_v(spec, **kw):
    """st.columns with vertical centring where the installed Streamlit supports it."""
    try:
        return st.columns(spec, vertical_alignment="center", **kw)
    except TypeError:
        return st.columns(spec, **kw)


def go_to(page: str, **state):
    """Switch page; widget state is applied at the top of the next run (before any widget exists)."""
    ss["page"] = page
    ss["_pending"] = state
    st.rerun()


# ----------------------------------------------------------------------------------------------
# Left rail
# ----------------------------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        '<div class="rail-brand"><svg width="30" height="30" viewBox="0 0 30 30" aria-hidden="true">'
        '<path d="M15 2.5 26 8.8v12.4L15 27.5 4 21.2V8.8z" fill="#b79bf0"/>'
        '<path d="M9 17l4-4 3 3 5-6" fill="none" stroke="#241f33" stroke-width="2.2" stroke-linecap="round" '
        'stroke-linejoin="round"/></svg>'
        f'<div><b>Event Manager</b><span>Qlik Sense · v{__version__}</span></div></div>', unsafe_allow_html=True)
    _last = None
    for _pid, _icon, _grp in ui.NAV:
        if _grp != _last:
            st.markdown(f'<div class="rail-group">{_grp}</div>', unsafe_allow_html=True)
            _last = _grp
        _key = "nav_" + "".join(ch if ch.isalnum() else "_" for ch in _pid.lower())
        try:
            _clicked = st.button(_pid, key=_key, icon=f":material/{_icon}:", use_container_width=True)
        except TypeError:  # older Streamlit without button icons
            _clicked = st.button(_pid, key=_key, use_container_width=True)
        if _clicked and _pid != PAGE:
            go_to(_pid)
    st.markdown('<div class="rail-foot">Read-only. Nothing here changes Qlik, the logs or any database.</div>',
                unsafe_allow_html=True)
st.markdown(ui.css(PAGE), unsafe_allow_html=True)

_n = [0]


@contextmanager
def safe(page: str):
    """Keep a problem on one page from stopping the rest of the app from drawing."""
    try:
        yield
    except Exception as exc:  # noqa: BLE001
        if type(exc).__name__ in ("StopException", "RerunException"):  # Streamlit control flow, not errors
            raise
        st.error(f"Something on the {page} page couldn't be drawn with this data: {type(exc).__name__}: {exc}"[:600])
        with st.expander("Technical details (send this to whoever maintains the app)"):
            st.exception(exc)


@contextmanager
def card(title: str = "", sub: str = "", height: int | None = None):
    """A white widget with a title and a one-line 'how to read this'."""
    _n[0] += 1
    kw = dict(border=True)
    if height:
        kw["height"] = height
    try:
        c = st.container(key=f"card{_n[0]}", **kw)
    except TypeError:
        c = st.container(**kw)
    with c:
        if title:
            st.markdown(f'<div class="ct">{title}</div>' + (f'<div class="cs">{sub}</div>' if sub else ""),
                        unsafe_allow_html=True)
        yield


def kpi(label, value, sub="", tone="info", chip=""):
    """A stat tile. tone: good / warn / bad (shown with a symbol and word) or info (no status)."""
    level = tone if tone in ("good", "warn", "bad") else ""
    st.markdown(ui.tile(label, value, "", sub, level), unsafe_allow_html=True)


def tiles(items, per_row=None):
    """A row of stat tiles. items: dicts with label, value, unit, sub, level, spark."""
    cols = st.columns(per_row or len(items))
    for c, it in zip(cols, items):
        with c:
            st.markdown(ui.tile(it["label"], it["value"], it.get("unit", ""), it.get("sub", ""), it.get("level", ""),
                                it.get("spark")), unsafe_allow_html=True)


def section(title, sub=""):
    st.markdown(ui.section(title, sub), unsafe_allow_html=True)


def _full_width(fn) -> dict:
    """Newer Streamlit takes width="stretch"; older versions use use_container_width=True."""
    try:
        p = inspect.signature(fn).parameters.get("width")
        if p is not None and isinstance(p.default, str):
            return {"width": "stretch"}
    except (TypeError, ValueError):
        pass
    return {"use_container_width": True}


FULL_PLOT, FULL_DF, FULL_ED = _full_width(st.plotly_chart), _full_width(st.dataframe), _full_width(st.data_editor)
FULL_W = _full_width(st.link_button)


def show(fig, height=None, legend_below=False, crosshair=False):
    ui.style(fig, height, legend_below, crosshair)
    st.plotly_chart(fig, config={"displaylogo": False, "modeBarButtonsToRemove": ["lasso2d", "select2d"]}, **FULL_PLOT)


def table(df, **kw):
    st.dataframe(df, hide_index=True, **FULL_DF, **kw)


# ----------------------------------------------------------------------------------------------
# Top bar + server settings
# ----------------------------------------------------------------------------------------------
try:
    _top = st.container(key="topbar")
except TypeError:
    _top = st.container()
with _top:
    tb1, tb2, tb5, tb3, tb4 = columns_v([3.9, 1.3, 1.45, 1.3, 1.3])
    title_ph = tb1.empty()
    status_ph = tb2.empty()
    with tb3:
        with st.popover("⚙  Server settings"):
            st.caption("Match these to your server. They set the memory limit lines and the capacity calculations.")
            cores = st.number_input("CPU cores", 1, 512, int(site_config.SERVER_CORES))
            ram = st.number_input("RAM (GB)", 8, 4096, int(site_config.SERVER_RAM_GB))
            low_pct = st.number_input("Qlik working set LOW limit %", 10, 100, 70)
            high_pct = st.number_input("Qlik working set HIGH limit %", 10, 100, 90)
            cpu_warn, cpu_thr = st.slider("CPU warning / alert thresholds %", 10, 100, (60, 80),
                                          help="Amber warning line and red alert line on the CPU charts. The alert level also "
                                               "raises CPU events; the warning level decides which spikes are listed on Server CPU.")
            storm_thr = st.number_input("Request storm: requests a minute from one session", 60, 100000, 600, step=60,
                                        help="600 a minute = 10 a second, far above normal browsing.")
            conc_thr = st.number_input("Reload pile-up: reloads running at once", 2, 100, 10)
    with tb5:
        _kw = dict(key="top_report", type="primary", use_container_width=True,
                   help="Someone has told you about a problem: note when, which app or dashboard and what happened. It's "
                        "saved to the register and investigated against the logs straight away.")
        try:
            _rep = st.button("Report an issue", icon=":material/campaign:", **_kw)
        except TypeError:
            _rep = st.button("Report an issue", **_kw)
        if _rep:
            go_to("Reported issues", iss_view="Investigate", iss_pick="__new", iss_adhoc=None)
    with tb4:
        if qe.FAULT_URL:
            st.link_button("↗  Log a fault", qe.FAULT_URL, use_container_width=True,
                           help=f"Opens the {site_config.FAULT_FORM_NAME} in a new tab. Pick an event on the Events "
                                "page for a summary you can paste into it.")
_CRUMB = {p: g for p, _, g in ui.NAV}


def set_title(extra_pill: str = ""):
    title_ph.markdown(f'<div class="crumb">{APP_NAME} / {_CRUMB.get(PAGE, "")}</div><div class="ptitle">{PAGE}</div>',
                      unsafe_allow_html=True)
    status_ph.markdown(extra_pill, unsafe_allow_html=True)


set_title()


# ----------------------------------------------------------------------------------------------
# Loading
# ----------------------------------------------------------------------------------------------
@st.cache_data(show_spinner="Reading log...")
def parse_upload(name: str, raw: bytes):
    return q.parse_log(name, raw)


@st.cache_data(show_spinner="Reading log...")
def parse_path(path: str, mtime: float, size: int):
    return q.parse_log(pathlib.Path(path).name, pathlib.Path(path).read_bytes())


@st.cache_data(ttl=600, show_spinner="Scanning the ArchivedLogs folder (directory listing only)...")
def scan_archive(root: str):
    return qe.scan_archive(root)


@st.cache_data(show_spinner=False)
def daily_sample(root: str, listing_rows: int, days: int, _files):
    bar = st.progress(0.0, "Sampling one engine audit file per day...")
    out = qe.audit_daily_sample(_files, days, progress=lambda f, t: bar.progress(f, f"Sampling {t}..."))
    bar.empty()
    return out


ss = st.session_state
env_folder = os.environ.get("QLIK_LOG_FOLDER", "")
ss.setdefault("arch_root", os.environ.get("QLIK_ARCHIVE_ROOT", qe.DEFAULT_ARCHIVE_ROOT))

SRC_SHARE, SRC_LOCAL, SRC_UPLOAD = "Qlik server share", "Local folder", "Upload files"
ss.setdefault("log_source", SRC_SHARE if ss["arch_root"] else (SRC_LOCAL if env_folder else SRC_UPLOAD))

with st.expander("📁  Load logs" if not ss.get("had_data") else "📁  Logs loaded - change folder, days or files",
                 expanded=not ss.get("had_data")):
    st.markdown('<div class="ct">Where are your logs coming from?</div>', unsafe_allow_html=True)
    src = st.radio("Log source", [SRC_SHARE, SRC_LOCAL, SRC_UPLOAD], key="log_source", horizontal=True,
                   label_visibility="collapsed",
                   help="Share: read the ArchivedLogs folder on the Qlik server straight from the network. "
                        "Local folder: logs you copied to this PC (for example with the fetch script). "
                        "Upload: pick or drop individual files.")
    st.caption({SRC_SHARE: "Reads the newest files of each log type straight from the Qlik share. Needs network access to it.",
                SRC_LOCAL: "Reads every .txt, .log and .csv file directly in one folder on this PC.",
                SRC_UPLOAD: "Reads the files you drop here. Nothing else is read."}[src])
    root, listing, picked, uploads, folder = "", pd.DataFrame(), pd.DataFrame(), [], ""
    if src == SRC_SHARE:
        st.markdown('<div class="ct">Archived logs folder</div><div class="cs">Reads the newest file(s) of each log type from '
                    'every subfolder (Engine, Repository, Proxy, Scheduler...). Only the directory listing is read until a file '
                    'is picked.</div>', unsafe_allow_html=True)
        a1, a2, a3, a4 = st.columns([4.2, 1, 1.1, .9])
        with a1:
            root = st.text_input("ArchivedLogs folder", key="arch_root", label_visibility="collapsed",
                                 placeholder=qe.DEFAULT_ARCHIVE_ROOT or r"\\server\QlikShare$\ArchivedLogs\server", help="Clear it to stop reading from the share.")
        with a2:
            days = st.number_input("Days back", 0.5, 60.0, 2.0, step=0.5, key="arch_days",
                                   help="Files archived in this many days before the newest one are loaded.")
        with a3:
            mb = st.number_input("Max MB per log type", 8, 4000, 64, step=8, key="arch_mb",
                                 help="Caps very busy logs (engine audit files are 8 MB each and can fill in minutes). "
                                      "Newest files are kept first.")
        with a4:
            st.write("")
            if st.button("↻ Rescan", help="Look for newly archived files"):
                scan_archive.clear()
        listing = pd.DataFrame()
        if root:
            if os.path.isdir(root):
                listing = scan_archive(root)
                if listing.empty:
                    st.warning("No Qlik log files found under that folder.")
            else:
                st.warning("Can't reach that folder from this PC. Check you're on the network and have access to the share, "
                           "or run 'Fetch latest Qlik logs.bat' and use the local folder below.")
        picked = qe.pick_latest(listing, days, mb) if len(listing) else listing
        if len(picked):
            summ = picked.groupby("type").agg(files=("name", "size"), newest=("mtime", "max"), oldest=("mtime", "min"),
                                              MB=("size_mb", "sum")).reindex([t for t in qe.USED_TYPES if t in set(picked["type"])])
            missing = [t for t in qe.USED_TYPES if t not in summ.index]
            st.caption(f"Found {len(listing):,} log files. Loading {len(picked)} files ({picked['size_mb'].sum():,.0f} MB) "
                       f"across {len(summ)} log types." + (f" Not found recently: {', '.join(missing)}." if missing else ""))
            with st.popover("What's being loaded"):
                table(summ.assign(MB=summ["MB"].round(1), newest=summ["newest"].dt.strftime("%a %d %b %H:%M"))[["files", "newest", "MB"]].reset_index().rename(columns={"type": "log type"}))
            s1, s2 = st.columns([1.4, 3])
            with s1:
                want_sample = st.toggle("Daily audit sample (last 90 days)", key="want_sample",
                                        help="Opens one engine audit file per day to see which app and user filled it. "
                                             "Reads about 8 MB a day over the network, so it takes a minute or two the first time.")
    if src == SRC_UPLOAD:
        uploads = st.file_uploader("Drop log files here", accept_multiple_files=True,
                                   type=["txt", "log", "csv", "tsv"], key="logs_up")
    if src == SRC_LOCAL:
        folder = st.text_input("Folder of log files on this PC", value=env_folder, key="logs_folder",
                               placeholder=r"C:\Users\you\QlikLogs\latest", help="e.g. the folder the fetch script copies to.")
        st.caption("Reads only the files directly in this folder, not subfolders.")
    st.caption("Not sure how to set up logging so you can pull history? See **Log setup guide** in the menu.")

loaded, notes = [], []
if len(picked):
    bar = st.progress(0.0, "Reading logs...") if len(picked) > 3 else None
    for i, r in enumerate(picked.itertuples()):
        kind, df, msg = parse_path(r.path, r.mtime.timestamp(), r.size_mb)
        (loaded if kind else notes).append((r.name, kind, df) if kind else (r.name, msg))
        if bar:
            bar.progress((i + 1) / len(picked), f"Reading {r.type}...")
    if bar:
        bar.empty()
    ac = qe.audit_counts_from_listing(listing)
    if len(ac):
        loaded.append(("Engine audit files per hour (folder listing)", "audit_counts", ac))
    if ss.get("want_sample"):
        smp = daily_sample(root, len(listing), 90, listing)
        if len(smp):
            loaded.append(("Engine audit daily sample", "audit_sample", smp))
for f in uploads or []:
    kind, df, msg = parse_upload(f.name, f.getvalue())
    (loaded if kind else notes).append((f.name, kind, df) if kind else (f.name, msg))
if folder and pathlib.Path(folder).is_dir():
    for p in sorted(pathlib.Path(folder).glob("*")):
        if p.suffix.lower() in (".txt", ".log", ".csv", ".tsv") and p.is_file():
            st_ = p.stat()
            kind, df, msg = parse_path(str(p), st_.st_mtime, st_.st_size)
            (loaded if kind else notes).append((p.name, kind, df) if kind else (p.name, msg))
elif folder:
    st.error("That folder wasn't found.")

NO_LOG_PAGES = ("Apps", "Storage", "Qlik Community search", "Log setup guide")
if not loaded and PAGE not in NO_LOG_PAGES:
    ss["had_data"] = False
    st.markdown(
        '<div class="steps">'
        '<div class="step"><span class="n">1</span><h4>Point it at the logs</h4><p>The ArchivedLogs folder on the share is '
        'filled in for you. If this PC can\'t reach it, run <b>Fetch latest Qlik logs.bat</b> and use the local folder, '
        'or drop files in.</p></div>'
        '<div class="step"><span class="n">2</span><h4>Choose how far back</h4><p>Days back and a size cap per log type '
        'keep it quick. The engine-request history for the whole archive comes from the folder listing for free.</p></div>'
        '<div class="step"><span class="n">3</span><h4>Work the events</h4><p>The <b>Events</b> page lists everything worth a '
        'look. Set a status, owner and notes; they are kept for next time.</p></div></div>', unsafe_allow_html=True)
    for n, msg in notes:
        st.warning(f"{n}: {msg}")
    st.caption("Apps and Storage work without the logs: pick them in the left rail.")
    st.stop()
if not loaded:
    st.caption("No Qlik logs loaded, so log-based figures (reloads, users, events) are left out on this page.")
elif not ss.get("had_data"):
    ss["had_data"] = True
    st.rerun()  # redraw once so the Load logs panel folds away now that data is loaded

data = q.combine([(k, d_) for _, k, d_ in loaded]) if loaded else {}

# ---- time window + server filter ------------------------------------------------------------
short = {k: v for k, v in data.items() if k not in qe.LONG_KINDS}
all_ts = pd.concat([x["ts"] for x in (short or data).values()]) if data else pd.Series([pd.Timestamp.now()])
hosts = sorted(set().union(*[set(x["Hostname"].unique()) for x in data.values() if "Hostname" in x])) if data else []
# ignore a handful of very old rows (e.g. a 2018 service log) so they don't stretch the slider
lo_ts = all_ts.quantile(0.001) if len(all_ts) > 5000 else all_ts.min()
lo, hi = lo_ts.floor("min").to_pydatetime(), all_ts.max().ceil("min").to_pydatetime()
if not data:
    lo = (pd.Timestamp(hi) - pd.Timedelta(days=1)).to_pydatetime()
PRESETS = {"All loaded": None, "Last 1 day": timedelta(days=1), "Last 4 hours": timedelta(hours=4), "Custom": "custom"}
sel_hosts = hosts
win = (lo, hi)
if data:
    with card():
        tc1, tc2, tc3 = columns_v([1.5, 3.4, 1.2] if len(hosts) > 1 else [1.5, 4.6, 0.01])
        with tc1:
            st.markdown(f"**{', '.join(hosts)}**<br><span style='color:#898781;font-size:.8rem'>{len(loaded)} files · times are server local time</span>",
                        unsafe_allow_html=True)
        with tc2:
            preset = st.radio("Time range", list(PRESETS), horizontal=True, key="range_preset", label_visibility="collapsed")
            win = (lo, hi)
            if preset == "Custom" and hi > lo:
                win = st.slider("Time window", min_value=lo, max_value=hi, value=(lo, hi), step=timedelta(minutes=5),
                                format="ddd DD MMM HH:mm", label_visibility="collapsed")
            elif isinstance(PRESETS[preset], timedelta):
                win = (max(lo, hi - PRESETS[preset]), hi)
        with tc3:
            sel_hosts = st.multiselect("Server", hosts, default=hosts, label_visibility="collapsed") if len(hosts) > 1 else hosts

d = {}
for k, df in data.items():
    if k in qe.LONG_KINDS:
        d[k] = df
        continue
    m = (df["ts"] >= win[0]) & (df["ts"] <= win[1])
    if "Hostname" in df and sel_hosts:
        m &= df["Hostname"].isin(sel_hosts)
    d[k] = df[m]
P, S, Y = d.get("performance"), d.get("session"), d.get("system")

span_days = (win[1] - win[0]).total_seconds() / 86400
default_bucket = "30 min" if span_days <= 1.5 else ("Hour" if span_days <= 10 else "Day")
if notes:
    with st.expander(f"ℹ️  {len(notes)} file(s) skipped (types this tool doesn't use)"):
        for n, msg in notes:
            st.caption(f"**{n}** — {msg}")



# ==============================================================================================
# Apps, storage and reload logs (not tied to the time window)
# ==============================================================================================
@st.cache_resource(show_spinner=False)
def _catalogue(path: str, mtime: float):
    return qc.load(pathlib.Path(path))


def catalogue() -> pd.DataFrame:
    p_ = qc.path()
    return _catalogue(str(p_), p_.stat().st_mtime if p_.exists() else 0.0)


@st.cache_resource(show_spinner="Reading the share listing...")
def _snapshot(path: str, mtime: float):
    df, meta = qs.load_snapshot(pathlib.Path(path))
    return qs.classify(df), meta


def snapshot(i: int = 0):
    """The i-th newest share listing (classified) and its details, or (empty, {})."""
    snaps = qs.snapshots()
    if len(snaps) <= i:
        return qs.classify(pd.DataFrame(columns=qs.COLS)), {}
    return _snapshot(str(snaps[i]), snaps[i].stat().st_mtime)


@st.cache_data(show_spinner=False)
def _script_summary(path: str, mtime: float) -> dict:
    return qr.read_script(path)


def script_runs(files: pd.DataFrame) -> pd.DataFrame:
    if files is None or files.empty:
        return qr.script_runs(files.iloc[0:0] if files is not None else pd.DataFrame(columns=["path"]))
    key = (len(files), str(files["path"].iloc[-1]))
    bar = st.progress(0.0, "Reading reload logs (first and last lines only)...") if ss.get("scripts_read") != key and len(files) > 15 else None
    infos = {}
    for i, f in enumerate(files.itertuples()):
        infos[f.path] = _script_summary(f.path, f.mtime.timestamp())
        if bar and i % 10 == 0:
            bar.progress((i + 1) / len(files), f"Reading reload logs... {i + 1} of {len(files)}")
    if bar:
        bar.empty()
    ss["scripts_read"] = key
    return qr.script_runs(files, reader=infos.__getitem__)


SHARE_ROOT = qs.share_root_from(ss.get("arch_root", ""))
if SHARE_ROOT and qs.get_setting("auto_scan", True) and not qs.JOB.running and not ss.get("scan_checked"):
    ss["scan_checked"] = True
    if qs.due(24) and os.path.isdir(SHARE_ROOT):
        qs.JOB.start(SHARE_ROOT)        # background; the Storage page shows progress

CAT = catalogue()
LISTING, LISTING_META = snapshot(0)
APPFILES = qs.app_files(LISTING)
LOG_NAMES = qe.app_names(data) if data else {}
NAMES = {**{str(k).lower(): v for k, v in LOG_NAMES.items()},
         **{r.id: r.name for r in CAT.itertuples() if r.id and r.name}}
MASTER = qc.apps(CAT, APPFILES, LOG_NAMES)
ss.setdefault("script_days", 14)
_local_scripts = qe.scan_archive(folder) if folder and pathlib.Path(folder, "Script").is_dir() else pd.DataFrame()
_all_listing = pd.concat([x for x in (listing, _local_scripts) if len(x)], ignore_index=True) if (len(listing) or len(_local_scripts)) else listing
SCRIPT_FILES = qr.script_files(_all_listing, ss["script_days"]) if len(_all_listing) else qr.script_files(None)
SCRIPTS = script_runs(SCRIPT_FILES) if len(SCRIPT_FILES) else qr.script_runs(SCRIPT_FILES)
SCHED = d.get("svc_system")
SCHED = SCHED[SCHED["service"].eq("Scheduler")] if SCHED is not None and len(SCHED) and "service" in SCHED else None


def app_name(aid: str) -> str:
    aid = str(aid or "").lower()
    return NAMES.get(aid) or (aid[:8] + "…" if aid else "")

def with_gaps(df):
    """Insert a blank row wherever samples are missing so chart lines break instead of drawing across the gap."""
    df = df.sort_values("ts")
    step = df["ts"].diff().median()
    if pd.isna(step):
        return df
    big = df.index[df["ts"].diff() > step * 3]
    if not len(big):
        return df
    return pd.concat([df, pd.DataFrame({"ts": df.loc[big, "ts"] - step / 2})]).sort_values("ts")


def tone_cpu(v):
    return "bad" if v >= cpu_thr else "warn" if v >= cpu_warn else "good"


# ==============================================================================================
# Events (event management)
# ==============================================================================================


@st.cache_data(show_spinner="Finding events...")
def get_events(sig, cpu_thr_, storm_, conc_, _data):
    return qe.detect_all(_data, cpu_thr_, storm_, conc_)


@st.cache_data(show_spinner=False)
def restart_sigs(sig, _P):
    """Every engine restart signature in the loaded performance data, weak ones included."""
    return qrs.find(_P)


@st.cache_data(show_spinner=False, max_entries=4)
def archive_restarts(root, n_files, newest, days, _files):
    """Engine performance samples from the archive's Performance_Engine files of the last `days` days, and the
    restart signatures in them."""
    bar = st.progress(0.0, "Reading engine performance logs from the archive...")
    P_ = qrs.read_archive_performance(_files, days, lambda p_: pathlib.Path(p_).read_bytes(),
                                      lambda f_, t_: bar.progress(min(1.0, f_), t_[:90]))
    bar.empty()
    return P_, qrs.find(P_)


@st.cache_data(show_spinner=False)
def get_more_events(sig, script_key, _data, _scripts, _names):
    """Reload failure patterns and login / proxy problems."""
    ev = []
    for fn in (lambda: qr.detect(_data.get("task_exec"), _scripts, _names), lambda: qp.detect(_data)):
        try:
            ev += fn()
        except Exception:  # noqa: BLE001
            pass
    return pd.DataFrame(ev)


def chip(text, colour):
    return f'<span class="chip" style="--tone:{colour}">{html.escape(str(text))}</span>'


def event_detail(F, E):
    """One event: likely root cause -> failure -> impact, what was seen, the context chart, fault summary."""
    with card("Event detail", "What was seen, the most likely cause among what else was happening, and what to check next."):
        labels = {r["id"]: f"{r['severity']} · {r['start']:%d %b %y %H:%M} · {r['title']}" for _, r in F.iterrows()}
        if ss.get("ev_select") not in labels:
            ss.pop("ev_select", None)
        pick = st.selectbox("Event", list(labels), format_func=labels.get, label_visibility="collapsed", key="ev_select")
        ev = F.set_index("id").loc[pick].copy()
        ev["id"] = pick
        dg = qe.diagnose(ev, E, data)
        st.markdown(ui.rca_banner(dg["root"], dg["failure"], dg["impact"]), unsafe_allow_html=True)
        st.caption("A lead to follow, not proof: it is the most likely cause among the events that overlap in time.")
        st.markdown(
            f'<div class="fi" style="--c:{SEV_C[ev["severity"]]}"><div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:4px">'
            f'{chip(ev["severity"], SEV_C[ev["severity"]])}{chip(ev["status"], STATUS_C[ev["status"]])}'
            f'{chip(ev["category"], ui.RAIL)}</div><b>{html.escape(ev["title"])}</b>'
            f'<div class="fd">{ev["start"]:%a %d %b %Y %H:%M} → {ev["end"]:%a %d %b %H:%M}'
            + (f' · app <b>{html.escape(ev["app"])}</b>' if ev["app"] else "")
            + (f' · user <b>{html.escape(ev["user"])}</b>' if ev["user"] else "")
            + f' · source: {html.escape(ev["source"])}</div><div class="fd">{html.escape(ev["detail"])}</div>'
            + (f'<div class="fd"><b>Notes:</b> {html.escape(ev["notes"])}</div>' if ev["notes"] else "")
            + "</div>", unsafe_allow_html=True)
        b1, b2, b3 = st.columns([1.1, 1.5, 3])
        with b1:
            if qe.FAULT_URL:
                st.link_button("↗  Log a fault", qe.FAULT_URL, help=f"Opens the {site_config.FAULT_SYSTEM} form. The summary below is ready to paste.")
        aid = app_id_for(ev["app"]) if ev["app"] else ""
        with b2:
            if aid and st.button("Open this app", key=f"open_app_{pick}", help="The app's page: its reloads and failures, and who uses it."):
                open_app(aid)
        context_chart(ev)
        community_search(qsr.for_event(ev), f"ev_{pick}")
        with st.expander(f"↗  Raise this as a {site_config.FAULT_SYSTEM} fault" + (f" (ticket {ev['ticket']})" if ev["ticket"] else "")):
            ov_ = qe.overlapping(E, ev["start"], ev["end"], 30, exclude_id=pick)
            st.caption("Copy this summary (copy icon, top right), open the form, and paste it into the description. "
                       "Then put the incident number in the Ticket column of the register.")
            code_kw = {"wrap_lines": True} if "wrap_lines" in inspect.signature(st.code).parameters else {}
            st.code(qe.fault_summary(ev, ov_, __version__), language=None, **code_kw)
            if qe.FAULT_URL:
                st.link_button(f"Open the {site_config.FAULT_FORM_NAME}", qe.FAULT_URL)
        ov = qe.overlapping(E, ev["start"], ev["end"], 30, exclude_id=pick)
        st.markdown(f'<div class="ct" style="font-size:.92rem;margin-top:4px">At the same time (±30 min): '
                    f'{len(ov)} other event(s)</div>', unsafe_allow_html=True)
        if len(ov):
            table(ov[["severity", "category", "title", "start", "end", "app", "user", "status"]])
        if ev["category"] == "Reported issue":
            if st.button("Open in Reported issues (investigate)", key=f"iss_{pick}"):
                go_to("Reported issues", iss_view="Investigate", iss_pick=pick)
            if st.button("🗑 Remove this reported issue", key=f"rm_{pick}"):
                qrp.save(qrp.remove(reports(), pick))
                store.pop(pick, None)
                qe.save_store(store)
                ss["ev_ver"] = ss.get("ev_ver", 0) + 1
                st.rerun()


def page_events():
    events = EVENTS_ALL
    if st.button("➕  Report an issue", key="ev_report", help="Note a problem someone reported (when, app, what happened). "
                 "It's saved to the reported-issues register, shown on this timeline, and investigated against the logs."):
        go_to("Reported issues", iss_view="Investigate", iss_pick="__new", iss_adhoc=None)

    if events.empty:
        st.info("No events found in the loaded logs. Load more log types (see the Load logs panel) to widen what is checked.")
        return
    E = with_status(events)
    with card():
        f1, f2, f3, f4, f5 = st.columns([1.2, 2.2, 1.6, 1.6, 1])
        with f1:
            sev_f = st.multiselect("Severity", ["High", "Medium", "Low"], default=["High", "Medium", "Low"])
        with f2:
            cats = sorted(E["category"].unique())
            cat_f = st.multiselect("Category", cats, default=cats)
        with f3:
            stat_f = st.multiselect("Status", qe.STATUSES, default=qe.OPEN_STATUSES)
        with f4:
            txt = st.text_input("Search", placeholder="app, user, task...")
        with f5:
            in_win = st.toggle("Time window only", value=False,
                               help="Only show events that overlap the time range chosen above. Off shows the full history.")
    F = E[E["severity"].isin(sev_f) & E["category"].isin(cat_f) & E["status"].isin(stat_f)]
    if txt:
        blob = (F["title"] + " " + F["app"] + " " + F["user"] + " " + F["detail"] + " " + F["notes"]).str.lower()
        F = F[blob.str.contains(txt.lower(), regex=False)]
    if in_win:
        F = F[(F["end"] >= win[0]) & (F["start"] <= win[1])]

    open_ = E[E["status"].isin(qe.OPEN_STATUSES)]
    nh = int((open_["severity"] == "High").sum())
    tiles([dict(label="Open events", value=f"{len(open_)}", sub=f"of {len(E)} detected", level="warn" if len(open_) else "good"),
           dict(label="Open · high", value=f"{nh}", sub="need a look first", level="bad" if nh else "good"),
           dict(label="New", value=f"{(E['status'] == 'New').sum()}", sub="not yet triaged"),
           dict(label="Investigating", value=f"{(E['status'] == 'Investigating').sum()}", sub=f"{(E['status'] == 'Monitoring').sum()} monitoring"),
           dict(label="Resolved", value=f"{(E['status'] == 'Resolved').sum()}", sub=f"{(E['status'] == 'Ignored').sum()} ignored", level="good")])

    focus = bool(ss.pop("ev_focus", False)) and len(F) > 0
    if focus:
        event_detail(F, E)

    if len(F):
        with card("Event timeline", "Each bar is one event, coloured by severity. Hover for details; zoom by dragging."):
            G = F.copy()
            rng = (G["end"].max() - G["start"].min()) if len(G) > 1 else pd.Timedelta(hours=1)
            minw = max(min(rng, pd.Timedelta(days=30)) * 0.004, pd.Timedelta(minutes=10))
            G["end2"] = G[["end", "start"]].apply(lambda r: max(r["end"], r["start"] + minw), axis=1)
            fig = go.Figure()
            for sev in ["Low", "Medium", "High"]:
                g = G[G["severity"] == sev]
                if len(g):
                    fig.add_bar(base=g["start"], x=(g["end2"] - g["start"]).dt.total_seconds() * 1000, y=g["category"],
                                orientation="h", name=sev, marker_color=SEV_C[sev], customdata=g[["title", "status"]],
                                hovertemplate="%{customdata[0]}<br>%{base|%d %b %H:%M}<br>%{customdata[1]}<extra></extra>")
            fig.update_xaxes(type="date", rangeselector=dict(buttons=[
                dict(count=2, label="2 days", step="day", stepmode="backward"),
                dict(count=7, label="week", step="day", stepmode="backward"),
                dict(count=1, label="month", step="month", stepmode="backward"),
                dict(count=6, label="6 months", step="month", stepmode="backward"),
                dict(step="all", label="all")]))
            last = G["end2"].max()
            if last - G["start"].min() > pd.Timedelta(days=45):  # long history: open on the recent month
                fig.update_xaxes(range=[last - pd.Timedelta(days=30), last + pd.Timedelta(hours=12)])
            fig.update_layout(barmode="overlay", bargap=0.35, legend=dict(y=1.12))
            show(fig, max(260, 34 * G["category"].nunique() + 130))

    with card("Event register", "Set Status, Owner and Notes straight in the table. Changes save automatically to "
              f"{qe.default_store_path()} and stay with the event the next time you load the same logs."):
        view = F[["id", "status", "severity", "category", "title", "start", "end", "app", "user", "metric", "owner", "ticket", "notes"]]
        ver = ss.setdefault("ev_ver", 0)
        key = f"ev_ed_{ver}_{abs(hash(tuple(view['id'])))}"
        cfg = dict(
            id=None,
            status=st.column_config.SelectboxColumn("Status", options=qe.STATUSES, required=True, width="small"),
            severity=st.column_config.TextColumn("Sev", width="small"),
            category=st.column_config.TextColumn("Category", width="small"),
            title=st.column_config.TextColumn("Event", width="large"),
            start=st.column_config.DatetimeColumn("Start", format="DD MMM YY HH:mm"),
            end=st.column_config.DatetimeColumn("End", format="DD MMM YY HH:mm"),
            app=st.column_config.TextColumn("App"), user=st.column_config.TextColumn("User"),
            metric=st.column_config.TextColumn("Measure", width="small"),
            owner=st.column_config.TextColumn("Owner", width="small"),
            ticket=st.column_config.TextColumn("Ticket", width="small", help=f"Ticket reference, e.g. {site_config.TICKET_HINT}"),
            notes=st.column_config.TextColumn("Notes", width="medium"),
        )
        kw = dict(key=key, hide_index=True, column_config=cfg, height=min(560, 38 + 35 * max(len(view), 3)),
                  disabled=["severity", "category", "title", "start", "end", "app", "user", "metric"])
        edited = st.data_editor(view, **FULL_ED, **kw)
        chg = edited.merge(view[["id", "status", "owner", "ticket", "notes"]], on="id", suffixes=("", "_old"))
        chg = chg[(chg["status"] != chg["status_old"]) | (chg["owner"] != chg["owner_old"]) | (chg["notes"] != chg["notes_old"])
                  | (chg["ticket"] != chg["ticket_old"])]
        if len(chg):
            now = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M")
            for _, r in chg.iterrows():
                store[r["id"]] = {"status": r["status"], "owner": r["owner"] or "", "notes": r["notes"] or "",
                                  "ticket": r["ticket"] or "", "title": r["title"], "updated": now}
            try:
                qe.save_store(store)
                ss["ev_ver"] = ver + 1
                st.toast(f"Saved {len(chg)} change(s)")
                st.rerun()
            except OSError as exc:
                st.error(f"Couldn't save to {qe.default_store_path()}: {exc}")
        st.download_button("⬇ Events (CSV)", F.to_csv(index=False).encode(), "qlik_events.csv", "text/csv")

    if len(F) and not focus:
        event_detail(F, E)


def page_server_cpu():
    RP, PX, TE = d.get("repo_perf"), d.get("proxy_perf"), d.get("task_exec")
    if (RP is None or RP.empty) and (P is None or P.empty):
        st.info("Load a Performance_Repository log (Repository\\Trace) for whole-server CPU, or a Performance_Engine log "
                "for engine CPU. Add Performance_Proxy for users and TaskExecution_Scheduler for reloads.")
    else:
        conc = qe.reload_concurrency(TE) if TE is not None and len(TE) else pd.Series(dtype=float)
        EVA = EVENTS_ALL
        EVW = EVA[(EVA["start"] >= win[0]) & (EVA["start"] <= win[1])
                  & ((EVA["end"] - EVA["start"]) <= pd.Timedelta(days=1))] if len(EVA) else EVA
        its = []
        if RP is not None and len(RP):
            pk = RP.loc[RP["machine_cpu"].idxmax()]
            its.append(dict(label="Server CPU peak", value=f"{pk['machine_cpu']:.0f}", unit="%", sub=f"at {pk['ts']:%a %H:%M}",
                            level=tone_cpu(pk["machine_cpu"]), spark=RP["machine_cpu"].values))
            its.append(dict(label="Server CPU average", value=f"{RP['machine_cpu'].mean():.0f}", unit="%",
                            sub=f"p95 {RP['machine_cpu'].quantile(.95):.0f}%", level=tone_cpu(RP["machine_cpu"].mean())))
        if P is not None and len(P):
            its.append(dict(label="Engine CPU average", value=f"{P['CPULoad'].mean():.0f}", unit="%", sub=f"peak {P['CPULoad'].max():.0f}%",
                            level=tone_cpu(P["CPULoad"].mean()), spark=P["CPULoad"].values))
        if PX is not None and len(PX):
            its.append(dict(label="Users connected", value=f"{int(PX['ActiveSessions'].max())}", sub=f"peak · avg {PX['ActiveSessions'].mean():.0f}",
                            spark=PX["ActiveSessions"].values))
        if len(conc):
            its.append(dict(label="Reloads running", value=f"{conc.mean():.1f}", sub=f"on average · peak {int(conc.max())}",
                            level="warn" if conc.mean() >= 2 else ""))
        if its:
            tiles(its)
        show_ev = st.toggle(f"Show events on the CPU chart ({len(EVW)} in this window)", value=True,
                            help="Purple squares and dotted lines at each event's start. Hover for the event; full detail is on the Events page.")

        with card("Server CPU, engine CPU, users and reloads", "One measure per panel, all on the same time axis. Hover to read every "
                  "panel at the same moment."):
            tr = []
            if RP is not None and len(RP):
                g = with_gaps(RP)
                tr.append(dict(x=g["ts"], y=g["machine_cpu"], name="Server CPU %", colour=ui.BLUE, width=2.4))
            if P is not None and len(P):
                g = with_gaps(P)
                tr.append(dict(x=g["ts"], y=g["CPULoad"], name="Engine CPU %", colour=ui.AQUA))
            panels = [dict(title="CPU % (blue = whole server, green = Qlik engine)", unit="%", ymax=100, traces=tr, height=1.9,
                           hlines=[(cpu_warn, ui.WARN, f"warning {cpu_warn}%"), (cpu_thr, ui.CRIT, f"alert {cpu_thr}%")])]
            if PX is not None and len(PX):
                g = with_gaps(PX)
                panels.append(dict(title="Users connected", traces=[dict(x=g["ts"], y=g["ActiveSessions"], name="Users",
                                                                         colour=ui.VIOLET, kind="area")], height=.9))
            if len(conc):
                cc = conc.resample("5min").max()
                cc = cc[(cc.index >= win[0]) & (cc.index <= win[1])]
                panels.append(dict(title="Reloads running at once", traces=[dict(x=cc.index, y=cc.values, name="Reloads",
                                                                                  colour=ui.ORANGE, kind="step")], height=.9,
                                   hlines=[(conc_thr, ui.CRIT, f"pile-up {conc_thr}")]))
            show(ui.ts_panels(panels, EVW if show_ev else None, x_range=(win[0], win[1])))

        with card("CPU spikes and what was happening", f"Every stretch at or above the {cpu_warn}% warning line (or the "
                  "highest samples if none), with the events, reloads and users at the same time (±10 min). Sorted by peak."):
            sp = qe.cpu_spikes(d, cpu_warn, EVA, pad_min=10)
            if sp.empty:
                st.caption("No CPU samples in this window.")
            else:
                if (sp["peak_cpu"] < cpu_warn).all():
                    st.caption(f"Nothing reached {cpu_warn}% in this window; showing the highest samples instead.")
                cols_ = [c_ for c_ in ["source", "peak_at", "peak_cpu", "samples", "events", "event_titles",
                                       "reloads_running", "busiest_reloads", "users"] if c_ in sp]
                st.dataframe(sp[cols_], hide_index=True, **FULL_DF, column_config={
                    "source": st.column_config.TextColumn("CPU", help="Server = whole machine (Repository log); "
                                                                       "Engine = Qlik engine (Performance_Engine log)"),
                    "peak_at": st.column_config.DatetimeColumn("Peak at", format="ddd DD MMM HH:mm"),
                    "peak_cpu": st.column_config.ProgressColumn("Peak CPU", min_value=0, max_value=100, format="%d%%"),
                    "samples": st.column_config.NumberColumn("5-min samples", help="How many samples in a row were at or above the warning line"),
                    "events": st.column_config.NumberColumn("Events"), "event_titles": st.column_config.TextColumn("Events at the time", width="large"),
                    "reloads_running": st.column_config.NumberColumn("Reloads (max)"),
                    "busiest_reloads": st.column_config.TextColumn("Busiest reloads", width="medium"),
                    "users": st.column_config.NumberColumn("Users")})
                st.caption("CPU is sampled about every 5 minutes, so spikes shorter than that can fall between samples.")

        l, r = st.columns(2, gap="medium")
        with l:
            src = RP if RP is not None and len(RP) else P
            col = "machine_cpu" if src is RP else "CPULoad"
            with card("CPU by minute of the hour", "If a few bars stand well above the rest, something scheduled runs at "
                      "those minutes every hour (reload triggers usually)."):
                m = src.groupby(src["ts"].dt.minute)[col].mean()
                fig = go.Figure(go.Bar(x=[f":{i:02d}" for i in m.index], y=m.values,
                                       marker_color=[RED if v >= m.mean() * 1.25 else MID_BLUE for v in m.values],
                                       hovertemplate="%{x}: %{y:.0f}%<extra></extra>"))
                fig.update_yaxes(title="average CPU %")
                show(fig, 300)
        with r:
            if RP is not None and len(RP) and P is not None and len(P):
                mm = pd.merge_asof(RP[["ts", "machine_cpu"]].sort_values("ts"), P[["ts", "CPULoad"]].sort_values("ts"),
                                   on="ts", direction="nearest", tolerance=pd.Timedelta("3min")).dropna()
            else:
                mm = pd.DataFrame()
            if len(mm) >= 6:
                gap = (mm["machine_cpu"] - mm["CPULoad"]).mean()
                with card("Is it Qlik, or something else?", "Server CPU against engine CPU at the same moments. Points on the "
                          "diagonal = the engine is the CPU. Points well above it = another process (security software, "
                          "agents, other Qlik services)."):
                    fig = go.Figure(go.Scatter(x=mm["CPULoad"], y=mm["machine_cpu"], mode="markers",
                                               marker=dict(color=MID_BLUE, size=7, opacity=.7)))
                    fig.add_scatter(x=[0, 100], y=[0, 100], mode="lines", line=dict(color=MUTED, dash="dot"), showlegend=False)
                    fig.update_xaxes(title="Engine CPU %", range=[0, 100]); fig.update_yaxes(title="Server CPU %", range=[0, 100])
                    show(fig, 300)
                    st.markdown(f"On average the server runs **{gap:.0f} points** above the engine "
                                f"({len(mm)} matched samples).")
            else:
                with card("What moves with server CPU", "Correlation of server CPU with users and with each busy reload "
                          "task, sample by sample. Near 1 = rises and falls together; near 0 = unrelated."):
                    dr = qe.cpu_drivers(d)
                    if dr.empty:
                        st.caption("Needs a Performance_Repository log plus Performance_Proxy and/or TaskExecution_Scheduler.")
                    else:
                        dr = dr.sort_values("correlation")
                        fig = go.Figure(go.Bar(x=dr["correlation"], y=[s[:60] for s in dr["Driver"]], orientation="h",
                                               marker_color=[GREEN if v >= .5 else MID_BLUE for v in dr["correlation"]]))
                        fig.update_xaxes(range=[-.2, 1])
                        show(fig, max(260, 30 * len(dr) + 80))
                        st.caption("Correlation shows what tends to move together, not proof of cause. "
                                   "Add a Performance_Engine log for the same hours to compare server vs engine CPU directly.")


# ==============================================================================================
# Reloads
# ==============================================================================================
def page_reloads():
    TE = d.get("task_exec")
    if TE is None or TE.empty:
        st.info("Load a TaskExecution_Scheduler log (Scheduler\\Trace) to see reload activity.")
    else:
        tt = qe.task_table(TE)
        conc = qe.reload_concurrency(TE)
        span_h = max((TE["stop"].max() - TE["start"].min()).total_seconds() / 3600, 1 / 60)
        c = st.columns(5)
        with c[0]: kpi("Reloads run", f"{int(tt['runs'].sum()):,}", f"{tt['runs'].sum() / span_h:.0f} an hour")
        with c[1]: kpi("Failed", f"{int(tt['failed'].sum())}", "error / aborted / failed", "bad" if tt["failed"].sum() else "good")
        with c[2]: kpi("Skipped", f"{int(tt['skipped'].sum()):,}", "trigger fired, task didn't run",
                       "warn" if tt["skipped"].sum() else "good")
        with c[3]: kpi("Running at once", f"{conc.mean():.1f}", f"average · peak {int(conc.max()) if len(conc) else 0}",
                       "warn" if len(conc) and conc.mean() >= 2 else "info")
        with c[4]: kpi("Reload busy time", f"{tt['busy_h'].sum():.0f} h", f"in {span_h:.0f} h of log")

        with card("Reloads running at the same time", "Each reload loads, recalculates and saves an app. Tall spikes are "
                  "pile-ups; a floor that never reaches zero means reloads run around the clock."):
            cc = conc.resample("5min").max()
            fig = go.Figure(go.Scatter(x=cc.index, y=cc.values, mode="lines", line=dict(color=BLUE, width=1.6, shape="hv"),
                                       fill="tozeroy", fillcolor="rgba(4,74,144,.12)", name="running"))
            fig.add_hline(y=conc_thr, line_dash="dot", line_color=RED)
            show(fig, 280)

        with card("Reload tasks", "Sorted by how much time each task spends running. 'Busy %' is the share of the period "
                  "that task was running."):
            show_cols = ["TaskName", "app", "runs", "runs_per_h", "median_s", "max_s", "busy_pct", "failed", "skipped"]
            try:
                st.dataframe(tt[show_cols], hide_index=True, **FULL_DF, height=380, column_config={
                    "TaskName": "Task", "app": "App", "runs_per_h": st.column_config.NumberColumn("Runs/h", format="%.1f"),
                    "median_s": st.column_config.NumberColumn("Median s", format="%.0f"),
                    "max_s": st.column_config.NumberColumn("Longest s", format="%.0f"),
                    "busy_pct": st.column_config.ProgressColumn("Busy %", min_value=0, max_value=100, format="%.0f%%")})
            except TypeError:
                table(tt[show_cols])

        apps_ = TE.dropna(subset=["AppId"])[["AppName", "AppId"]].drop_duplicates().sort_values("AppName") if "AppId" in TE else pd.DataFrame()
        if len(apps_):
            with card("Open an app", "Its reload runs and failures with the error text, and who uses it."):
                t1, t2 = columns_v([3, 1])
                lab = {str(r.AppId).lower(): f"{r.AppName}" for r in apps_.itertuples()}
                with t1:
                    pick_app = st.selectbox("App", list(lab), format_func=lab.get, label_visibility="collapsed", key="rl_app")
                with t2:
                    if st.button("Open", key="rl_open", type="primary"):
                        open_app(pick_app, "Reloads")

        with card("Reload timeline (busiest 12 tasks)", "Each bar is one run. Red = failed. Zoom in to see individual runs."):
            top = tt.head(12)["TaskName"].tolist()
            g = TE[TE["TaskName"].isin(top) & (TE["Status"] != "Skipped")].copy()
            g["ms"] = ((g["stop"] - g["start"]).dt.total_seconds().clip(lower=20)) * 1000
            fig = go.Figure()
            for bad, colr, nm in [(False, MID_BLUE, "ok"), (True, RED, "failed")]:
                gg = g[g["Status"].isin(["Error", "Aborted", "FinishedFail"]) == bad]
                if len(gg):
                    fig.add_bar(base=gg["start"], x=gg["ms"], y=gg["TaskName"].str[:55], orientation="h", name=nm,
                                marker_color=colr, customdata=gg[["dur_s", "Status"]],
                                hovertemplate="%{base|%d %b %H:%M:%S} · %{customdata[0]:.0f}s · %{customdata[1]}<extra></extra>")
            fig.update_xaxes(type="date"); fig.update_layout(barmode="overlay")
            show(fig, 40 * len(top) + 120)

        SV, SY = d.get("service"), d.get("svc_system")
        msgs = []
        if SV is not None and len(SV):
            s = SV[SV["Service"].eq("Scheduler")]
            msgs.append(s.assign(kind=s["Message"]).groupby("kind").size())
        if SY is not None and len(SY):
            s = SY[SY["service"].eq("Scheduler") & SY["Level"].ne("INFO")]
            msgs.append(s.assign(kind=s["Level"] + " " + s["Message"].map(lambda m: q.categorise("", m))).groupby("kind").size())
        msgs = [m for m in msgs if len(m)]
        if msgs:
            with card("Scheduler warnings and errors", "From the Scheduler service and trace logs."):
                table(pd.concat(msgs).groupby(level=0).sum().sort_values(ascending=False).rename("count").reset_index()
                      .rename(columns={"kind": "message"}).head(25))


# ==============================================================================================
# Requests (engine request volume, storms)
# ==============================================================================================
def page_requests():
    AC, AS = data.get("audit_counts"), data.get("audit_sample")
    R = qe.engine_requests(d)
    if (AC is None or AC.empty) and (AS is None or AS.empty) and R.empty:
        st.info("Load AuditActivity_Engine / Service_Engine logs (Engine\\Audit, Engine\\System), or the PowerShell outputs "
                "for audit files per hour and the daily sample. See the README for the commands.")
    if AC is not None and len(AC):
        daily = qe.audit_daily(AC)
        with card("Engine request volume by day (full history)", "Audit log files written per day (each about 8 MB of "
                  "logged engine requests). Green = weekdays, blue = weekends; the line is the usual level for that kind "
                  "of day. Weekend bars climbing means something runs with nobody at work."):
            fig = go.Figure()
            fig.add_bar(x=daily.index[~daily["weekend"]], y=daily.loc[~daily["weekend"], "files"], name="Weekday", marker_color=GREEN)
            fig.add_bar(x=daily.index[daily["weekend"]], y=daily.loc[daily["weekend"], "files"], name="Weekend", marker_color=MID_BLUE)
            fig.add_scatter(x=daily.index[~daily["weekend"]], y=daily.loc[~daily["weekend"], "baseline"], name="Usual weekday",
                            mode="lines", line=dict(color=NAVY, width=1.5, dash="dot"))
            fig.update_layout(bargap=0.05)
            if daily.index.max() - daily.index.min() > pd.Timedelta(days=200):
                fig.update_xaxes(range=[daily.index.max() - pd.Timedelta(days=183), daily.index.max() + pd.Timedelta(days=1)])
            fig.update_xaxes(rangeselector=dict(buttons=[dict(count=2, label="2m", step="month", stepmode="backward"),
                                                         dict(count=6, label="6m", step="month", stepmode="backward"),
                                                         dict(step="all", label="all")]))
            show(fig, 340)
        if bool(AC["hourly"].iloc[0]):
            with card("Hour by hour, last 60 days", "Darker = more engine requests. Overnight and weekend rows that stay "
                      "dark point to sessions left open on a misbehaving sheet."):
                h = AC[AC["ts"] >= AC["ts"].max() - pd.Timedelta(days=60)]
                pv = h.assign(day=h["ts"].dt.normalize(), hr=h["ts"].dt.hour).pivot_table(index="day", columns="hr",
                                                                                         values="files", aggfunc="sum")
                pv = pv.reindex(columns=range(24)).fillna(0)
                pv = pv.reindex(pd.date_range(pv.index.min(), pv.index.max(), freq="D")).fillna(0)
                fig = go.Figure(go.Heatmap(z=pv.values, x=[f"{i:02d}:00" for i in pv.columns],
                                           y=[i.strftime("%a %d %b") for i in pv.index], colorscale=HEAT,
                                           hovertemplate="%{y} %{x}: %{z} files<extra></extra>"))
                fig.update_yaxes(autorange="reversed")
                show(fig, max(360, 13 * len(pv) + 80))
    if AS is not None and len(AS):
        with card("Who filled the engine log each day (daily sample)", "One file per day sampled. A share of 70%+ from one "
                  "user means a single open session was making most of the engine's requests."):
            v = AS.sort_values("day", ascending=False)[["day", "files", "sampled", "app", "user", "share_pct"]]
            try:
                st.dataframe(v, hide_index=True, **FULL_DF, height=380, column_config={
                    "day": st.column_config.DateColumn("Day", format="ddd DD MMM YY"), "files": "Files that day",
                    "sampled": "Sampled at", "app": "Top app", "user": "Top user",
                    "share_pct": st.column_config.ProgressColumn("Share of requests", min_value=0, max_value=100, format="%d%%")})
            except TypeError:
                table(v)
    if not R.empty:
        R = R.assign(key=R["sess"].astype(str) + "|" + R["app"].astype(str))
        sessions = R.groupby(["key", "UserId", "app"]).agg(requests=("ts", "size"), first=("ts", "min"), last=("ts", "max"),
                                                           objects=("obj", "nunique"), failed=("failed", "mean")).reset_index()
        secs = (sessions["last"] - sessions["first"]).dt.total_seconds().clip(lower=1)
        sessions["per_s"] = sessions["requests"] / secs
        sessions["failed"] = sessions["failed"] * 100
        sessions = sessions.sort_values("requests", ascending=False)
        c = st.columns(4)
        with c[0]: kpi("Engine requests logged", f"{len(R):,}", f"{R['ts'].min():%d %b %H:%M} → {R['ts'].max():%H:%M}")
        with c[1]: kpi("Sessions", f"{len(sessions):,}", f"{R['UserId'].nunique()} users")
        top = sessions.iloc[0]
        with c[2]: kpi("Busiest session", f"{top['requests'] / len(R) * 100:.0f}%", f"{top['UserId']} · {top['app']}",
                       "bad" if top["requests"] / len(R) > .5 else "info")
        with c[3]: kpi("Its rate", f"{top['per_s']:.0f}/s", f"{int(top['objects']):,} different objects",
                       "bad" if top["per_s"] >= storm_thr / 60 else "info")
        with card("Engine requests per minute, by session", "From AuditActivity_Engine and Service_Engine. These files fill "
                  "up in minutes during a storm, so each one covers only a short stretch."):
            topk = sessions.head(6)["key"].tolist()
            rr = R[R["key"].isin(topk)]
            pm = rr.groupby([rr["ts"].dt.floor("min"), "key"]).size().unstack(fill_value=0)
            full = pd.date_range(pm.index.min(), pm.index.max(), freq="min")
            pm = pm.reindex(full)  # minutes with no logged requests stay blank so lines break between log files
            lab = {r.key: f"{r.UserId} · {r.app}" for r in sessions.itertuples()}
            fig = go.Figure()
            for s_ in pm.columns:
                fig.add_scatter(x=pm.index, y=pm[s_], name=str(lab.get(s_, s_))[:40], mode="lines+markers")
            fig.add_hline(y=storm_thr, line_dash="dot", line_color=RED, annotation_text="storm threshold")
            show(fig, 320)
        with card("Sessions by request count", "A normal session makes a burst of requests when a sheet opens, then a "
                  "few per selection. Thousands of different objects in minutes is not normal."):
            v = sessions[["UserId", "app", "requests", "per_s", "objects", "failed", "first", "last"]]
            try:
                st.dataframe(v.head(50), hide_index=True, **FULL_DF, column_config={
                    "UserId": "User", "app": "App", "per_s": st.column_config.NumberColumn("Per second", format="%.1f"),
                    "failed": st.column_config.NumberColumn("Failed %", format="%.0f"),
                    "first": st.column_config.DatetimeColumn("First", format="DD MMM HH:mm:ss"),
                    "last": st.column_config.DatetimeColumn("Last", format="DD MMM HH:mm:ss")})
            except TypeError:
                table(v.head(50))
    A = d.get("activity")
    if A is not None and len(A):
        o = A[A["Service"].eq("Repository") & A["Command"].eq("Open app")]
        if len(o):
            with card("App opens (Repository audit)", "Apps re-opened hundreds of times by the same people, including "
                      "overnight, are usually wallboards reconnecting after every reload."):
                t = o.groupby(["app", "UserId"]).size().rename("opens").reset_index().sort_values("opens", ascending=False)
                table(t.head(30))


# ==============================================================================================
# Overview
# ==============================================================================================
def page_engine_overview():
    found = q.findings(d, cores, ram, low_pct, high_pct, cpu_thr)
    left, right = st.columns([2.05, 1], gap="medium")
    with left:
        if P is not None and not P.empty:
            pk = P.loc[P["CPULoad"].idxmax()]
            hot = (P["CPULoad"] >= cpu_thr).mean() * 100
            vm_peak = P["VM_GB"].max()
            vm_tone = "bad" if vm_peak > ram * high_pct / 100 else "warn" if vm_peak > ram * low_pct / 100 else "good"
            cols = st.columns(5)
            with cols[0]: kpi("Peak CPU", f"{pk['CPULoad']:.0f}%", f"at {pk['ts']:%a %H:%M}", tone_cpu(pk["CPULoad"]),
                              "HIGH" if pk["CPULoad"] >= cpu_thr else "OK")
            with cols[1]: kpi("Average CPU", f"{P['CPULoad'].mean():.0f}%", f"p95 {P['CPULoad'].quantile(.95):.0f}%",
                              tone_cpu(P["CPULoad"].mean()))
            with cols[2]: kpi(f"Time ≥ {cpu_thr}% CPU", f"{hot:.0f}%", f"of {len(P)} samples",
                              "bad" if hot > 25 else "warn" if hot > 5 else "good")
            with cols[3]: kpi("Peak users", f"{int(P['ActiveUsers'].max())}", f"{int(P['ActiveDocSessions'].max())} doc sessions")
            with cols[4]: kpi("Peak memory", f"{vm_peak:.0f} GB", f"{vm_peak / ram * 100:.0f}% of {ram} GB", vm_tone,
                              {"bad": "OVER", "warn": "HIGH", "good": "OK"}[vm_tone])

            with card("CPU and users over time", "Blue = engine CPU, green = active users. Red shading marks stretches above your "
                      "alert threshold; red triangles mark memory warnings from the System log."):
                fig = go.Figure()
                Pg = with_gaps(P)
                fig.add_scatter(x=Pg["ts"], y=Pg["CPULoad"], name="CPU %", mode="lines", line=dict(color=MID_BLUE, width=2.5),
                                fill="tozeroy" if len(Pg) == len(P) else None, fillcolor="rgba(18,125,176,.13)",
                                hovertemplate="%{y:.0f}%")
                fig.add_scatter(x=Pg["ts"], y=Pg["ActiveUsers"], name="Active users", yaxis="y2", mode="lines",
                                line=dict(color=GREEN, width=2), hovertemplate="%{y}")
                fig.add_hline(y=cpu_thr, line_dash="dot", line_color=RED, annotation_text=f"{cpu_thr}%",
                              annotation_position="top left")
                fig.add_hline(y=cpu_warn, line_dash="dot", line_color=AMBER, annotation_text=f"{cpu_warn}%",
                              annotation_position="top left")
                for _, r in q.breach_runs(P, cpu_thr).iterrows():
                    fig.add_vrect(x0=r["start"], x1=r["end"], fillcolor="rgba(229,72,59,.10)", line_width=0)
                if Y is not None and not Y.empty:
                    w = Y[Y["cat"].str.contains("virtual memory|Low on RAM", regex=True)]
                    if len(w):
                        wc = w.groupby(w["ts"].dt.floor("5min")).size()
                        fig.add_scatter(x=wc.index, y=[4] * len(wc), mode="markers", name="Memory warnings", customdata=wc.values,
                                        marker=dict(symbol="triangle-up", size=11, color=RED),
                                        hovertemplate="%{customdata} memory warnings<extra></extra>")
                utop = max(5, -(-int(P["ActiveUsers"].max()) // 5) * 5)
                fig.update_layout(hovermode="x unified", yaxis=dict(range=[0, 100], title="CPU %", dtick=20),
                                  yaxis2=dict(overlaying="y", side="right", title="Users", showgrid=False, range=[0, utop],
                                              dtick=utop / 5, tickformat="d"))
                show(fig, 400)
        else:
            st.info("Add a Performance_Engine log to see CPU, users and memory over time.")

        c1, c2 = st.columns(2, gap="medium")
        with c1:
            with card("Is Qlik itself using the CPU?", f"Engine CPU vs the CPU the session log can account for, as a share "
                      f"of {cores} cores. A big gap means the CPU is going elsewhere."):
                a = q.attribution(P, S, cores) if P is not None and S is not None else pd.DataFrame()
                if len(a):
                    fig = go.Figure()
                    fig.add_bar(x=a["Hour"], y=a["engine_cpu_pct"], name="Engine CPU load %", marker_color=BLUE)
                    fig.add_bar(x=a["Hour"], y=a["session_cpu_pct_of_capacity"], name="Session CPU, % of capacity", marker_color=GREEN)
                    fig.update_layout(barmode="group", yaxis_title="% of server CPU")
                    show(fig, 300)
                else:
                    st.info("Needs both a Performance and a Session log covering the same hours.")
        with c2:
            with card("Top apps by CPU", "Where the session log says the CPU went. Dark = users, green = reload scheduler."):
                if S is not None and not S.empty:
                    g = S.groupby(["app", "is_scheduler"])["cpu_s"].sum().unstack(fill_value=0)
                    g.columns = ["Users" if not c else "Reloads" for c in g.columns]
                    g["t"] = g.sum(axis=1)
                    g = g.sort_values("t").tail(8).drop(columns="t")
                    fig = go.Figure()
                    for c, colr in zip(g.columns, [BLUE, GREEN]):
                        fig.add_bar(y=g.index, x=g[c], name=c, orientation="h", marker_color=colr)
                    fig.update_layout(barmode="stack", xaxis_title="CPU seconds")
                    show(fig, 300)
                else:
                    st.info("Add a Session_Engine log.")

    with right:
        with card("What stands out", "Leads to follow up, most serious first. Patterns in the logs, not confirmed causes. "
                  "Click one to read more.", height=760):
            if not found:
                st.info("Nothing notable in this window.")
            for f in found:
                detail = f'<div class="fd">{html.escape(f["detail"])}</div>' if f["detail"] else ""
                st.markdown(f'<details class="fi" style="--c:{SEV_COLOUR[f["severity"]]}"><summary>{html.escape(f["finding"])}'
                            f'</summary>{detail}</details>', unsafe_allow_html=True)

# ==============================================================================================
# Engine health
# ==============================================================================================
def page_engine_health():
    if P is None or P.empty:
        st.info("Load a Performance_Engine log to see this tab.")
    else:
        cols = st.columns(6)
        with cols[0]: kpi("Mean CPU", f"{P['CPULoad'].mean():.0f}%", f"p95 {P['CPULoad'].quantile(.95):.0f}%", tone_cpu(P["CPULoad"].mean()))
        with cols[1]: kpi("Peak CPU", f"{P['CPULoad'].max():.0f}%", f"{P.loc[P['CPULoad'].idxmax(), 'ts']:%d %b %H:%M}", tone_cpu(P["CPULoad"].max()))
        with cols[2]: kpi(f"Samples ≥ {cpu_thr}%", f"{(P['CPULoad'] >= cpu_thr).mean() * 100:.0f}%", f"{len(P)} samples")
        with cols[3]: kpi("Peak users", f"{int(P['ActiveUsers'].max())}", f"{int(P['ActiveDocSessions'].max())} doc sessions")
        with cols[4]: kpi("Peak memory", f"{P['VM_GB'].max():.0f} GB", f"{P['VM_GB'].max() / ram * 100:.0f}% of {ram} GB")
        with cols[5]: kpi("Mean cache hit", f"{P['cache_hit_pct'].mean():.0f}%", "higher is better")

        with card("CPU utilisation", "Each column is a time bucket. Colour shows how many 5-minute samples landed at that CPU level; "
                  "the lines are the median and the 95th percentile."):
            bucket = st.radio("Bucket", list(q.BUCKETS), index=list(q.BUCKETS).index(default_bucket), horizontal=True,
                              key="dens", label_visibility="collapsed")
            freq = q.BUCKETS[bucket]
            d_ = P.assign(b=P["ts"].dt.floor(freq), bin=(P["CPULoad"] // 5 * 5).clip(0, 95).astype(int))
            pv = d_.pivot_table(index="bin", columns="b", values="CPULoad", aggfunc="size", fill_value=0)
            full = pd.date_range(d_["b"].min(), d_["b"].max(), freq=freq)
            pv = pv.reindex(index=range(0, 100, 5), columns=full, fill_value=0)
            st_ = d_.groupby("b")["CPULoad"].agg(p50="median", p95=lambda x: x.quantile(.95)).reindex(full)
            fig = go.Figure(go.Heatmap(
                z=pv.values, x=pv.columns, y=pv.index + 2.5, zmin=0,
                colorscale=[[0, "rgba(4,74,144,.05)"], [.15, "#a9d3ee"], [.5, "#127db0"], [1, "#062b51"]],
                colorbar=dict(title="samples"), hovertemplate="%{x}<br>CPU ≈ %{y:.0f}%<br>%{z} samples<extra></extra>"))
            fig.add_scatter(x=st_.index, y=st_["p95"], name="p95", line=dict(color=AMBER, width=2))
            fig.add_scatter(x=st_.index, y=st_["p50"], name="median", line=dict(color=GREEN, width=2))
            fig.add_hline(y=cpu_thr, line_dash="dot", line_color=RED, annotation_text=f"{cpu_thr}%")
            fig.update_layout(yaxis=dict(range=[0, 100], title="CPU %"))
            show(fig, 380)

        with card("Everything over time", "CPU, users, memory against Qlik's limits, and cache hit rate, on one shared time axis."):
            fig = make_subplots(rows=4, cols=1, shared_xaxes=True, vertical_spacing=.05,
                                subplot_titles=("Engine CPU load %", "Users and document sessions",
                                                "Engine virtual memory (GB)", "Cache hit rate %"))
            Pg = with_gaps(P)
            fig.add_scatter(x=Pg["ts"], y=Pg["CPULoad"], name="CPU %", line=dict(color=BLUE), row=1, col=1)
            fig.add_hline(y=cpu_thr, line_dash="dot", line_color=RED, row=1, col=1)
            fig.add_scatter(x=Pg["ts"], y=Pg["ActiveUsers"], name="Active users", line=dict(color=GREEN), row=2, col=1)
            fig.add_scatter(x=Pg["ts"], y=Pg["ActiveDocSessions"], name="Doc sessions", line=dict(color=MID_BLUE), row=2, col=1)
            fig.add_scatter(x=Pg["ts"], y=Pg["VM_GB"], name="VM committed GB", line=dict(color=DEEP_GREEN), row=3, col=1)
            fig.add_hline(y=ram * low_pct / 100, line_dash="dot", line_color=AMBER, row=3, col=1, annotation_text="low limit")
            fig.add_hline(y=ram * high_pct / 100, line_dash="dot", line_color=RED, row=3, col=1, annotation_text="high limit")
            fig.add_scatter(x=Pg["ts"], y=Pg["cache_hit_pct"], name="Cache hit %", line=dict(color="#5fb3e0"), row=4, col=1)
            for _, r in qrs.restarts(RESTARTS).iterrows():
                fig.add_vrect(x0=r["start"], x1=max(r["end"], r["start"] + pd.Timedelta(seconds=40)), fillcolor="rgba(200,40,40,.3)",
                              line_width=0, layer="below")
            fig.update_layout(showlegend=False, hovermode="x unified")
            show(fig, 760)

        with card("What moves with CPU?", "Bars to the right rise and fall together with CPU. This shows association, not cause."):
            cc = ["ActiveUsers", "ActiveDocSessions", "Calls", "Selections", "VM_GB", "cache_hit_pct", "CacheObjectAdded", "LoadedDocs"]
            corr = P[["CPULoad"] + [c for c in cc if c in P]].corr()["CPULoad"].drop("CPULoad").sort_values()
            fig = go.Figure(go.Bar(x=corr.values, y=corr.index, orientation="h",
                                   marker_color=[BLUE if v > 0 else GREEN for v in corr.values]))
            fig.update_layout(xaxis=dict(title="correlation with CPU (-1 to 1)", range=[-1, 1]))
            show(fig, 300)

# ==============================================================================================
# Apps & users
# ==============================================================================================
def page_apps_users():
    if S is None or S.empty:
        st.info("Load a Session_Engine log to see this tab.")
    else:
        tot = S["cpu_s"].sum()
        cols = st.columns(4)
        with cols[0]: kpi("Sessions", f"{len(S):,}", f"{S['app'].nunique()} apps")
        with cols[1]: kpi("Session CPU", f"{tot:,.0f} s", f"{tot / ((win[1] - win[0]).total_seconds() * cores + 1) * 100:.1f}% of capacity")
        with cols[2]: kpi("Reload scheduler share", f"{S.loc[S['is_scheduler'], 'cpu_s'].sum() / max(tot, 1) * 100:.0f}%", "sa_scheduler")
        with cols[3]: kpi("Distinct users", f"{S.loc[~S['is_scheduler'], 'user'].nunique()}", "excluding scheduler")

        with card("Show me", "Pick what to measure and how finely to slice time. The heat maps below follow these."):
            o1, o2, o3 = st.columns([1.3, 1.3, 1])
            with o1: metric = st.radio("Measure", ["CPU seconds", "Sessions", "Calls"], horizontal=True)
            with o2: bucket = st.radio("Time bucket", list(q.BUCKETS), index=list(q.BUCKETS).index(default_bucket), horizontal=True, key="sb")
            with o3: n_apps = st.slider("Apps shown", 5, 40, 20)
        col, agg = {"CPU seconds": ("cpu_s", "sum"), "Sessions": (None, "sum"), "Calls": ("Calls", "sum")}[metric]

        with card("CPU by app", "Dark = user sessions, green = reload scheduler."):
            g = S.groupby(["app", "is_scheduler"])["cpu_s"].sum().unstack(fill_value=0)
            g.columns = ["Users" if not c else "Scheduler (reloads)" for c in g.columns]
            g["t"] = g.sum(axis=1)
            g = g.sort_values("t").tail(15).drop(columns="t")
            fig = go.Figure()
            for c, colr in zip(g.columns, [BLUE, GREEN]):
                fig.add_bar(y=g.index, x=g[c], name=c, orientation="h", marker_color=colr)
            fig.update_layout(barmode="stack", xaxis_title="CPU seconds")
            show(fig, 440)

        for label, rowcol, nn in [("App", "app", n_apps), ("User", "user", 15)]:
            sub = S if rowcol == "app" else S[~S["is_scheduler"]]
            pv = q.bucket_pivot(sub, "ts", rowcol, col, agg, q.BUCKETS[bucket], nn)
            if pv.empty:
                continue
            with card(f"{metric} by {label.lower()} over time", "Darker/redder = more. Look for apps that light up at the same time CPU was high."
                      + (" Scheduler excluded." if rowcol == "user" else "")):
                fig = go.Figure(go.Heatmap(z=pv.values, x=pv.columns, y=pv.index, colorscale=HEAT,
                                           colorbar=dict(title=metric), hoverongaps=False))
                fig.update_yaxes(autorange="reversed")
                show(fig, max(320, 22 * len(pv) + 120))

        with card("Heaviest single sessions", "The 25 sessions that used the most CPU."):
            top = S.sort_values("cpu_s", ascending=False).head(25)[["ts", "app", "user", "cpu_s", "dur_min", "Calls", "Exit Reason"]]
            top.columns = ["Closed", "App", "User", "CPU s", "Minutes", "Calls", "Exit reason"]
            table(top.round({"CPU s": 1, "Minutes": 1}))

# ==============================================================================================
# System events
# ==============================================================================================
def page_system_events():
    if Y is None or Y.empty:
        st.info("Load a System_Engine log to see this tab.")
    else:
        span_min = max((Y["ts"].max() - Y["ts"].min()).total_seconds() / 60, 1)
        opts = {"1 min": "1min", "2 min": "2min", "5 min": "5min", "15 min": "15min", "Hour": "60min"}
        default = "2 min" if span_min <= 60 else "5 min" if span_min <= 360 else "Hour"
        with card("Messages by type and time", "Each row is a kind of engine message. Each column is a slice of time. Hot = busy."):
            o1, o2, o3 = st.columns([1.6, 1, 1])
            with o1: sb = st.radio("Time bucket", list(opts), index=list(opts).index(default), horizontal=True, key="sysb")
            with o2: n = st.slider("Message types", 5, 40, 18, key="sysn")
            with o3:
                norm = st.checkbox("Colour each row on its own scale", True, help="Shows when each message type peaked, even rare ones.")
                warn_only = st.checkbox("Warnings only")
            sub = Y[Y["Level"] != "INFO"] if warn_only else Y
            pv = q.bucket_pivot(sub, "ts", "cat", None, "sum", opts[sb], n)
            if not pv.empty:
                z = pv.div(pv.max(axis=1).replace(0, 1), axis=0) if norm else pv
                fig = go.Figure(go.Heatmap(z=z.values, x=pv.columns, y=[c[:70] for c in pv.index], customdata=pv.values,
                                           colorscale=HEAT, showscale=False, hoverongaps=False,
                                           hovertemplate="%{y}<br>%{x}<br>%{customdata} messages<extra></extra>"))
                fig.update_yaxes(autorange="reversed")
                show(fig, max(360, 24 * len(pv) + 120))

        w = Y[Y["Level"] != "INFO"]
        if len(w):
            with card("Warnings", "Each dot is one warning. Tight clusters mean something got worse at that moment."):
                fig = go.Figure(go.Scatter(x=w["ts"], y=w["cat"].str[:60], mode="markers",
                                           marker=dict(size=9, color=RED, opacity=.7)))
                show(fig, max(260, 40 * w["cat"].nunique() + 100))
                table(w.groupby("cat").agg(count=("ts", "size"), first=("ts", "min"), last=("ts", "max"))
                      .sort_values("count", ascending=False).reset_index().rename(columns={"cat": "Warning"}))

        sus = q.suspends_by_app(Y, S)
        if len(sus):
            with card("Apps suspended most", "An app is suspended each time it changes (e.g. a real-time reload saves it) "
                      "and every open session on it refreshes."):
                table(sus.head(15))

# ==============================================================================================
# Trends
# ==============================================================================================
def page_trends():
    if P is None or P.empty:
        st.info("Load Performance_Engine logs from several days to build trends.")
    else:
        if P["ts"].dt.date.nunique() < 2:
            st.info("Only one day is loaded. Add more days (e.g. from the Archived Logs folder) to unlock day-to-day and "
                    "before/after comparisons. The grids below still show hour-of-day patterns.")
        ds = q.daily_summary(P)
        dx = ds["Date"].astype(str)
        cols = st.columns(4)
        with cols[0]: kpi("Days loaded", f"{len(ds)}", f"{ds['Date'].min()} to {ds['Date'].max()}")
        with cols[1]: kpi("Worst day (peak CPU)", f"{ds['cpu_max'].max():.0f}%", f"{ds.loc[ds['cpu_max'].idxmax(), 'Date']}", tone_cpu(ds["cpu_max"].max()))
        with cols[2]: kpi("Busiest day (mean CPU)", f"{ds['cpu_mean'].max():.0f}%", f"{ds.loc[ds['cpu_mean'].idxmax(), 'Date']}", tone_cpu(ds["cpu_mean"].max()))
        with cols[3]: kpi("Highest memory", f"{ds['vm_gb_max'].max():.0f} GB", f"{ds['vm_gb_max'].max() / ram * 100:.0f}% of {ram} GB")

        with card("Daily CPU against capacity", "Light blue = the CPU available. Green = average used. Lines show the busy end of each day."):
            fig = go.Figure()
            fig.add_bar(x=dx, y=[100] * len(ds), name="Capacity", marker_color="#d6e8f5")
            fig.add_bar(x=dx, y=ds["cpu_mean"], name="Mean CPU", marker_color=GREEN)
            fig.add_scatter(x=dx, y=ds["cpu_p95"], name="p95", mode="lines+markers", line=dict(color=MID_BLUE))
            fig.add_scatter(x=dx, y=ds["cpu_max"], name="Peak", mode="lines+markers", line=dict(color=RED, dash="dot"))
            fig.update_layout(barmode="overlay", yaxis_title="CPU %", xaxis_type="category")
            show(fig, 340)

        mlabel = {"CPULoad": "CPU %", "ActiveUsers": "Active users", "VM_GB": "Memory GB", "cache_hit_pct": "Cache hit %"}
        with card("Utilisation grid", "Average by date and hour of day. Spot the hours that are always busy, or the day that was different."):
            mcol = st.radio("Measure", list(mlabel), horizontal=True, format_func=mlabel.get)
            g = P.assign(Date=P["ts"].dt.strftime("%a %d %b"), hour=P["ts"].dt.hour)
            order = P["ts"].dt.normalize().drop_duplicates().dt.strftime("%a %d %b").tolist()
            pv = g.pivot_table(index="Date", columns="hour", values=mcol, aggfunc="mean").reindex(order)
            fig = go.Figure(go.Heatmap(z=pv.values, x=[f"{h:02d}:00" for h in pv.columns], y=pv.index, colorscale=HEAT,
                                       texttemplate="%{z:.0f}", hoverongaps=False, zmin=0,
                                       zmax=100 if mcol in ("CPULoad", "cache_hit_pct") else None))
            fig.update_yaxes(autorange="reversed")
            show(fig, max(260, 30 * len(pv) + 120))

            wd = P.assign(wd=P["ts"].dt.day_name(), hour=P["ts"].dt.hour)
            days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
            pv = wd.pivot_table(index="wd", columns="hour", values=mcol, aggfunc="mean").reindex([x for x in days if x in wd["wd"].unique()])
            fig = go.Figure(go.Heatmap(z=pv.values, x=[f"{h:02d}:00" for h in pv.columns], y=pv.index, colorscale=HEAT,
                                       texttemplate="%{z:.0f}", hoverongaps=False, zmin=0))
            fig.update_yaxes(autorange="reversed")
            fig.update_layout(title="By weekday (more meaningful with a week or more of data)")
            show(fig, 130 + 36 * len(pv))

        dates = sorted(P["ts"].dt.date.unique())
        with card("Compare days", "One line per day, by time of day. Is today different from the others?"):
            pick = st.multiselect("Days to overlay", dates, default=dates[-5:], format_func=lambda x: f"{x:%a %d %b}")
            if pick:
                fig = go.Figure()
                for dd in pick:
                    x = P[P["ts"].dt.date == dd]
                    h = x.groupby(x["ts"].dt.floor("30min").dt.strftime("%H:%M"))[mcol].mean()
                    fig.add_scatter(x=h.index, y=h.values, name=f"{dd:%a %d %b}", mode="lines")
                show(fig, 340)

        with card("Before vs after a change", "Pick the date something changed (a patch, an agent upgrade, a new app) and compare CPU by hour of day."):
            b1, b2 = st.columns([1, 1])
            with b1:
                split = st.date_input("Change date", value=dates[len(dates) // 2] if len(dates) > 1 else dates[0],
                                      min_value=dates[0], max_value=dates[-1])
            with b2:
                wk = st.checkbox("Weekdays only", True)
            B = P if not wk else P[P["ts"].dt.day_of_week < 5]
            before, after = B[B["ts"].dt.date < split], B[B["ts"].dt.date >= split]
            if len(before) and len(after):
                hb = before.groupby(before["ts"].dt.hour)["CPULoad"].mean()
                ha = after.groupby(after["ts"].dt.hour)["CPULoad"].mean()
                fig = go.Figure()
                fig.add_scatter(x=hb.index, y=hb.values, name=f"Before {split:%d %b}", line=dict(color=MID_BLUE))
                fig.add_scatter(x=ha.index, y=ha.values, name=f"From {split:%d %b}", line=dict(color=DEEP_GREEN))
                fig.update_layout(xaxis_title="Hour of day", yaxis_title="Mean CPU %")
                show(fig, 320)
                table(pd.DataFrame({"Period": ["Before", "After"], "Samples": [len(before), len(after)],
                                    "Mean CPU %": [before["CPULoad"].mean(), after["CPULoad"].mean()],
                                    "p95 CPU %": [before["CPULoad"].quantile(.95), after["CPULoad"].quantile(.95)],
                                    "Peak users": [before["ActiveUsers"].max(), after["ActiveUsers"].max()]}).round(1))
            else:
                st.info("Needs data on both sides of the change date.")

        if S is not None and not S.empty and S["ts"].dt.date.nunique() > 1:
            with card("App CPU by day", "Which apps are using more or less CPU from day to day."):
                pv = q.bucket_pivot(S, "ts", "app", "cpu_s", "sum", "1D", 20)
                fig = go.Figure(go.Heatmap(z=pv.values, x=[c.strftime("%a %d %b") for c in pv.columns], y=pv.index,
                                           colorscale=HEAT, hoverongaps=False))
                fig.update_yaxes(autorange="reversed")
                show(fig, max(320, 22 * len(pv) + 120))
        if Y is not None and not Y.empty and Y["ts"].dt.date.nunique() > 1:
            w = Y[Y["Level"] != "INFO"]
            if len(w):
                with card("Warnings by day", "Are warnings becoming more frequent?"):
                    pv = q.bucket_pivot(w, "ts", "cat", None, "sum", "1D", 15)
                    fig = go.Figure(go.Heatmap(z=pv.values, x=[c.strftime("%a %d %b") for c in pv.columns],
                                               y=[c[:70] for c in pv.index], colorscale=HEAT, hoverongaps=False))
                    fig.update_yaxes(autorange="reversed")
                    show(fig, max(280, 28 * len(pv) + 120))

# ==============================================================================================
# Export
# ==============================================================================================
def page_export():
    with card("Take the results with you", "Download the findings as a CSV, or everything as an Excel workbook for a report or ticket."):
        fdf = pd.DataFrame(q.findings(d, cores, ram, low_pct, high_pct, cpu_thr))
        buf = io.BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as xw:
            fdf.to_excel(xw, sheet_name="Findings", index=False)
            try:
                ev_x = get_events(sig, cpu_thr, storm_thr, conc_thr, data)
                if len(ev_x):
                    stx = qe.load_store()
                    ev_x = ev_x.assign(status=ev_x["id"].map(lambda i: stx.get(i, {}).get("status", "New")),
                                       owner=ev_x["id"].map(lambda i: stx.get(i, {}).get("owner", "")),
                                       notes=ev_x["id"].map(lambda i: stx.get(i, {}).get("notes", "")))
                    ev_x.to_excel(xw, sheet_name="Events", index=False)
            except Exception:  # noqa: BLE001
                pass
            if P is not None and len(P):
                q.daily_summary(P).to_excel(xw, sheet_name="Daily CPU", index=False)
                P[["ts", "Hostname", "CPULoad", "ActiveUsers", "ActiveDocSessions", "Calls", "Selections", "VM_GB",
                   "cache_hit_pct"]].to_excel(xw, sheet_name="Performance", index=False)
            if S is not None and len(S):
                S.groupby("app").agg(sessions=("cpu_s", "size"), cpu_s=("cpu_s", "sum")).sort_values("cpu_s", ascending=False) \
                    .reset_index().to_excel(xw, sheet_name="App CPU", index=False)
            if P is not None and S is not None:
                a = q.attribution(P, S, cores)
                if len(a):
                    a.to_excel(xw, sheet_name="CPU attribution", index=False)
            if Y is not None and len(Y):
                Y[Y["Level"] != "INFO"][["ts", "Level", "cat", "Message"]].to_excel(xw, sheet_name="Warnings", index=False)
            extra = {"Reported issues": reports(), "Reload failures": fail_table(window_only=False),
                     "Apps": MASTER.drop(columns=["display"], errors="ignore")}
            for nm, df_ in extra.items():
                if df_ is not None and len(df_):
                    df_.to_excel(xw, sheet_name=nm, index=False)
        st.caption("The workbook also has the reported issues, reload failures and the full app list.")
        e1, e2 = st.columns(2)
        with e1:
            st.download_button("⬇ Findings (CSV)", fdf.to_csv(index=False).encode(), "qlik_findings.csv", "text/csv")
        with e2:
            st.download_button("⬇ Summary workbook (Excel)", buf.getvalue(), "qlik_log_summary.xlsx",
                               "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


# ==============================================================================================
# Shared: events with their status, overall health
# ==============================================================================================
def all_events():
    """Detected events plus issues people reported, most severe first (cached detection)."""
    ev = get_events(sig, cpu_thr, storm_thr, conc_thr, data)
    more = get_more_events(sig, (len(SCRIPTS), str(SCRIPTS["file"].iloc[-1]) if len(SCRIPTS) else ""), data, SCRIPTS, NAMES)
    if len(more):
        ev = pd.concat([ev, more], ignore_index=True).drop_duplicates("id")
        ev = ev.assign(_s=ev["severity"].map({"High": 0, "Medium": 1, "Low": 2})) \
            .sort_values(["_s", "start"], ascending=[True, False]).drop(columns="_s").reset_index(drop=True)
    rep = qrp.as_events(reports())
    if len(rep):
        ev = pd.concat([rep, ev], ignore_index=True)
        ev = ev.assign(_s=ev["severity"].map({"High": 0, "Medium": 1, "Low": 2})) \
            .sort_values(["_s", "start"], ascending=[True, False]).drop(columns="_s").reset_index(drop=True)
    return ev


def with_status(ev):
    if ev is None or ev.empty:
        return ev
    E_ = ev.copy()
    for col, default in (("status", "New"), ("owner", ""), ("notes", ""), ("ticket", "")):
        E_[col] = E_["id"].map(lambda i, c=col, dflt=default: store.get(i, {}).get(c, dflt))
    return E_


def health():
    """One-line state of the server from the loaded logs: latest CPU, recent peak, events still open."""
    cs = qe.cpu_samples(d)
    out = {"level": "none", "short": "No CPU data", "headline": "Load a Performance log to see server health.",
           "detail": "", "now": None, "peak": None, "src": "", "open": 0, "high": 0, "end": win[1]}
    ev = with_status(EVENTS_ALL)
    open_ = ev[ev["status"].isin(qe.OPEN_STATUSES)] if ev is not None and len(ev) else pd.DataFrame(columns=["severity", "end"])
    recent = open_[open_["end"] >= win[1] - pd.Timedelta(hours=24)] if len(open_) else open_
    out["open"], out["high"] = len(open_), int((recent["severity"] == "High").sum()) if len(recent) else 0
    if len(cs):
        src = "Server" if (cs["source"] == "Server").any() else "Engine"
        s = cs[cs["source"] == src]
        last = s.iloc[-1]
        day = s[s["ts"] >= last["ts"] - pd.Timedelta(hours=24)]
        out.update(now=float(last["cpu"]), peak=float(day["cpu"].max()), src=src, end=last["ts"])
        level = "good"
        if last["cpu"] >= cpu_warn or day["cpu"].max() >= cpu_thr or (len(recent) and (recent["severity"] == "Medium").any()):
            level = "warn"
        if last["cpu"] >= cpu_thr or out["high"]:
            level = "bad"
        out["level"] = level
        out["short"] = {"good": "Healthy", "warn": "Needs a look", "bad": "Attention"}[level]
        out["headline"] = (f"{src} CPU is {last['cpu']:.0f}% at the last sample ({last['ts']:%a %d %b %H:%M}); "
                           f"the highest in the 24 hours before that was {day['cpu'].max():.0f}%.")
        bits = [f"{out['open']} open event(s)" + (f", {out['high']} high in the last day" if out["high"] else "")]
        bits.append(f"alert line {cpu_thr}%, warning line {cpu_warn}%")
        age = pd.Timestamp.now() - last["ts"]
        if age > pd.Timedelta(hours=6):
            bits.append(f"these are archived logs: the newest sample is {age.days}d {age.seconds // 3600}h old")
        out["detail"] = " · ".join(bits)
    return out


def app_id_for(name: str) -> str:
    """App ID for an app name (catalogue first, then the logs)."""
    if not name:
        return ""
    low = str(name).lower()
    for aid, nm in NAMES.items():
        if str(nm).lower() == low:
            return aid
    te = d.get("task_exec")
    if te is not None and len(te) and "AppName" in te:
        m = te[te["AppName"] == name]["AppId"]
        if len(m):
            return str(m.iloc[0]).lower()
    return ""


def open_app(app_id: str, section: str = ""):
    """Go to the Apps page on this app (optionally on one section, e.g. its reloads)."""
    state = {"app_id": str(app_id).lower()}
    if section:
        state["app_section"] = section
    go_to("Apps", **state)


def seg(label: str, options: list, key: str, default=None):
    """A row of toggle buttons (segmented control where available, radio otherwise). Always returns an option."""
    if ss.get(key) not in options:
        ss[key] = default if default in options else options[0]
    try:
        v = st.segmented_control(label, options, key=key, label_visibility="collapsed")
    except (AttributeError, TypeError):
        v = st.radio(label, options, key=key, horizontal=True, label_visibility="collapsed")
    return v if v in options else options[0]


def select_table(df: pd.DataFrame, key: str, **kw):
    """A table you can click a row in. Returns the selected row position, or None."""
    try:
        ev = st.dataframe(df, hide_index=True, on_select="rerun", selection_mode="single-row", key=key, **FULL_DF, **kw)
        rows = ev.selection.rows if ev and hasattr(ev, "selection") else []
        return rows[0] if rows else None
    except TypeError:  # older Streamlit: no row selection
        table(df, **kw)
        return None


def rnd(df: pd.DataFrame, n: int = 1) -> pd.DataFrame:
    """Round the number columns only."""
    num = df.select_dtypes("number").columns
    return df.assign(**{c: df[c].round(n) for c in num}) if len(num) else df


def owner_short(o: str) -> str:
    return re.sub(r"\s*\(.*\)\s*$", "", str(o or ""))


def fail_table(window_only: bool = True) -> pd.DataFrame:
    """Failed reloads with the best explanation found (task runs + scheduler trace + reload logs)."""
    te = d.get("task_exec")
    sc = SCRIPTS
    if window_only and len(sc):
        sc = sc[(sc["start"] >= win[0]) & (sc["start"] <= win[1])]
    sched = SCHED
    if sched is not None and len(sched):
        sched = sched[(sched["ts"] >= win[0]) & (sched["ts"] <= win[1])]
    return qr.failures(te, sched, sc, NAMES)


def app_activity() -> pd.DataFrame:
    """Per app ID in the time window: reload runs and failures, engine sessions and users."""
    parts = []
    te = d.get("task_exec")
    if te is not None and len(te) and "AppId" in te:
        x = te[te["Status"] != "Skipped"].assign(aid=te["AppId"].astype(str).str.lower())
        parts.append(x.groupby("aid").agg(reloads=("Status", "size"),
                                          failed=("Status", lambda s: int(s.isin(qr.FAILED).sum()))))
    if S is not None and len(S) and "AppId" in S:
        x = S[~S["is_scheduler"]].assign(aid=S["AppId"].astype(str).str.lower())
        parts.append(x.groupby("aid").agg(users=("user", "nunique"), sessions=("user", "size"), cpu_s=("cpu_s", "sum")))
    if not parts:
        return pd.DataFrame(columns=["reloads", "failed", "users", "sessions", "cpu_s"])
    out = parts[0]
    for p_ in parts[1:]:
        out = out.join(p_, how="outer")
    return out


# ==============================================================================================
# Event context chart (stacked panels on one time axis)
# ==============================================================================================
def context_chart(ev):
    """CPU, engine activity and users around an event, one measure per panel."""
    span = ev["end"] - ev["start"]
    pad = pd.Timedelta(hours=3) if span < pd.Timedelta(hours=12) else pd.Timedelta(days=2) if span < pd.Timedelta(days=10) else span / 3
    a, b = ev["start"] - pad, ev["end"] + pad
    panels = []
    cpu_tr = []
    rp, pf = data.get("repo_perf"), data.get("performance")
    if rp is not None:
        x = rp[(rp["ts"] >= a) & (rp["ts"] <= b)]
        if len(x):
            cpu_tr.append(dict(x=x["ts"], y=x["machine_cpu"], name="Server CPU %", colour=ui.BLUE, width=2.2))
    if pf is not None:
        x = pf[(pf["ts"] >= a) & (pf["ts"] <= b)]
        if len(x):
            cpu_tr.append(dict(x=x["ts"], y=x["CPULoad"], name="Engine CPU %", colour=ui.AQUA))
    if cpu_tr:
        panels.append(dict(title="CPU % (blue = server, green = Qlik engine)", unit="%", ymax=100, traces=cpu_tr, height=1.5,
                           hlines=[(cpu_warn, ui.WARN, f"warning {cpu_warn}%"), (cpu_thr, ui.CRIT, f"alert {cpu_thr}%")]))
    ys = data.get("system")
    sys_drawn = False
    if ys is not None:
        x = ys[(ys["ts"] >= a) & (ys["ts"] <= b)]
        if len(x):
            per = "5min" if (b - a) <= pd.Timedelta(hours=12) else "60min"
            sus = x[x["Message"].str.contains("suspend", case=False, regex=False)].groupby(x["ts"].dt.floor(per)).size()
            qrs = x[x["Message"].str.startswith("QrsSecurityManagement")].groupby(x["ts"].dt.floor(per)).size()
            tr = [dict(x=ser.index, y=ser.values, name=nm, colour=colr, kind="bar")
                  for ser, nm, colr in [(qrs, "Security lookups", ui.ORANGE), (sus, "Suspend messages", ui.VIOLET)] if len(ser)]
            if tr:
                panels.append(dict(title=f"Engine messages per {per.replace('min', ' min')} (orange = security lookups, "
                                         "purple = app suspends)", traces=tr, height=1))
                sys_drawn = True
    ac = data.get("audit_counts")
    if ac is not None and not sys_drawn:
        x = ac[(ac["ts"] >= a) & (ac["ts"] <= b)]
        if len(x):
            panels.append(dict(title="Engine audit files written", traces=[dict(x=x["ts"], y=x["files"], name="files",
                                                                                 colour=ui.BLUE, kind="bar")], height=1))
    px = data.get("proxy_perf")
    if px is not None:
        x = px[(px["ts"] >= a) & (px["ts"] <= b)]
        if len(x):
            panels.append(dict(title="Users connected", traces=[dict(x=x["ts"], y=x["ActiveSessions"], name="users",
                                                                     colour=ui.VIOLET, kind="area")], height=.9))
    if not panels:
        st.caption("No CPU or audit-volume data loaded around this time.")
        return
    fig = ui.ts_panels(panels, x_range=(a, b), row_px=170)
    fig.add_vrect(x0=ev["start"], x1=max(ev["end"], ev["start"] + pd.Timedelta(minutes=2)), fillcolor="rgba(208,59,59,.13)",
                  line_width=0, layer="below", row="all", col=1)
    show(fig)


# ==============================================================================================
# Overview (landing dashboard)
# ==============================================================================================
def page_overview():
    H = HEALTH
    st.markdown(ui.banner(H["level"], H["headline"], H["detail"]), unsafe_allow_html=True)
    cs = qe.cpu_samples(d)
    RP_, PX_, TE_, PF_ = d.get("repo_perf"), d.get("proxy_perf"), d.get("task_exec"), d.get("performance")
    items = []
    src_df, src_col, src_name = (RP_, "machine_cpu", "Server CPU") if RP_ is not None and len(RP_) else (PF_, "CPULoad", "Engine CPU")
    if src_df is not None and len(src_df):
        s_ = src_df.sort_values("ts")
        last_ = s_.iloc[-1][src_col]
        items.append(dict(label=src_name, value=f"{last_:.0f}", unit="%", level=tone_cpu(last_),
                          sub=f"latest · peak {s_[src_col].max():.0f}% · avg {s_[src_col].mean():.0f}%", spark=s_[src_col].tail(96).values))
    if PF_ is not None and len(PF_) and src_df is not PF_:
        items.append(dict(label="Engine CPU", value=f"{PF_['CPULoad'].mean():.0f}", unit="%", level=tone_cpu(PF_["CPULoad"].mean()),
                          sub=f"average · peak {PF_['CPULoad'].max():.0f}%", spark=PF_["CPULoad"].tail(96).values))
    if PX_ is not None and len(PX_):
        items.append(dict(label="Users connected", value=f"{int(PX_['ActiveSessions'].max())}", sub=f"peak · avg {PX_['ActiveSessions'].mean():.0f}",
                          spark=PX_["ActiveSessions"].tail(96).values))
    elif PF_ is not None and len(PF_):
        items.append(dict(label="Active users", value=f"{int(PF_['ActiveUsers'].max())}", sub=f"peak · avg {PF_['ActiveUsers'].mean():.0f}",
                          spark=PF_["ActiveUsers"].tail(96).values))
    if TE_ is not None and len(TE_):
        tt_ = qe.task_table(TE_)
        span_h_ = max((TE_["stop"].max() - TE_["start"].min()).total_seconds() / 3600, 1 / 60)
        fails = int(tt_["failed"].sum())
        items.append(dict(label="Reloads an hour", value=f"{tt_['runs'].sum() / span_h_:.0f}", sub=f"{int(tt_['runs'].sum()):,} runs in {span_h_:.0f} h"))
        items.append(dict(label="Failed reloads", value=f"{fails}", level="bad" if fails else "good", sub=f"{int(tt_['skipped'].sum()):,} skipped"))
    ev_ = with_status(EVENTS_ALL)
    open_ = ev_[ev_["status"].isin(qe.OPEN_STATUSES)] if ev_ is not None and len(ev_) else pd.DataFrame(columns=["severity"])
    nh = int((open_["severity"] == "High").sum()) if len(open_) else 0
    items.append(dict(label="Open events", value=f"{len(open_)}", level="bad" if nh else ("warn" if len(open_) else "good"),
                      sub=f"{nh} high · {int((open_['severity'] == 'Medium').sum()) if len(open_) else 0} medium"))
    if items:
        tiles(items[:6], per_row=min(len(items), 6))

    # ---- needs attention ---------------------------------------------------------------------
    section("What needs attention", "open events, most serious first")
    l, r = st.columns([1.55, 1], gap="medium")
    with l:
        with card("Open events", "The newest, most serious first. Investigate opens the event with its likely cause and what else was happening."):
            if open_ is None or open_.empty:
                st.markdown(ui.banner("good", "No open events in the loaded logs"), unsafe_allow_html=True)
            else:
                top = open_.assign(_s=open_["severity"].map({"High": 0, "Medium": 1, "Low": 2})).sort_values(["_s", "start"], ascending=[True, False]).head(7)
                for _, r_ in top.iterrows():
                    c1, c2 = columns_v([6.2, 1.05])
                    with c1:
                        st.markdown(f'<div class="evrow">{chip(r_["severity"], SEV_C[r_["severity"]])}'
                                    f'<span class="t" title="{html.escape(r_["title"])}">{html.escape(r_["title"])}</span>'
                                    f'<span class="w">{r_["start"]:%a %d %b %H:%M}</span></div>', unsafe_allow_html=True)
                    with c2:
                        if st.button("Investigate", key=f"inv_{r_['id']}"):
                            go_to("Events", ev_select=r_["id"], ev_focus=True)
                if len(open_) > len(top):
                    st.caption(f"{len(open_) - len(top)} more on the Events page.")
    with r:
        with card("What stands out", "Leads from the logs, not confirmed causes.", height=440):
            found = q.findings(d, cores, ram, low_pct, high_pct, cpu_thr)
            if not found:
                st.info("Nothing notable in this window.")
            for f in found[:8]:
                detail = f'<div class="fd">{html.escape(f["detail"])}</div>' if f["detail"] else ""
                st.markdown(f'<details class="fi" style="--c:{SEV_COLOUR[f["severity"]]}"><summary>{html.escape(f["finding"])}'
                            f'</summary>{detail}</details>', unsafe_allow_html=True)

    # ---- server CPU --------------------------------------------------------------------------
    section("Server CPU", "one hexagon per 5-minute sample; red outline = at or above the alert line")
    series = [(nm, df_, col) for nm, df_, col in (("Server CPU", RP_, "machine_cpu"), ("Engine CPU", PF_, "CPULoad"))
              if df_ is not None and len(df_)]
    if not series:
        st.info("Load a Performance_Repository log (server CPU) or a Performance_Engine log (engine CPU).")
    else:
        days_ = sorted({x.date() for _, df_, _ in series for x in df_["ts"]})
        pc1, pc2 = st.columns([1, 4])
        with pc1:
            day_ = st.selectbox("Day", days_, index=len(days_) - 1, format_func=lambda x: f"{x:%a %d %b}", key="hex_day")
        hc = st.columns(len(series), gap="medium")
        for c_, (nm, df_, col) in zip(hc, series):
            with c_:
                with card(f"{nm}, {day_:%a %d %b}", "Columns are hours, rows are minutes past the hour. A band across the rows "
                          "(e.g. :00 :15 :30 :45) is something that runs on a schedule."):
                    sd = df_[df_["ts"].dt.date == day_].set_index("ts")[col]
                    if sd.empty:
                        st.caption("No samples on this day.")
                    else:
                        st.plotly_chart(ui.honeycomb(sd, cpu_warn, cpu_thr), config={"displaylogo": False, "displayModeBar": False}, **FULL_PLOT)
        EV_ = EVENTS_ALL
        EVW_ = EV_[(EV_["start"] >= win[0]) & (EV_["start"] <= win[1]) & ((EV_["end"] - EV_["start"]) <= pd.Timedelta(days=1))] if EV_ is not None and len(EV_) else None
        with card("CPU, users and reloads over the selected time range", "Hover to read all panels at the same moment. "
                  "Purple squares and dotted lines are events; the amber and red lines are your warning and alert thresholds."):
            panels = []
            tr = []
            if RP_ is not None and len(RP_):
                g = with_gaps(RP_)
                tr.append(dict(x=g["ts"], y=g["machine_cpu"], name="Server CPU", colour=ui.BLUE, width=2.2))
            if PF_ is not None and len(PF_):
                g = with_gaps(PF_)
                tr.append(dict(x=g["ts"], y=g["CPULoad"], name="Engine CPU", colour=ui.AQUA))
            panels.append(dict(title="CPU % (blue = whole server, green = Qlik engine)", unit="%", ymax=100, traces=tr, height=1.7,
                               hlines=[(cpu_warn, ui.WARN, f"warning {cpu_warn}%"), (cpu_thr, ui.CRIT, f"alert {cpu_thr}%")]))
            if PX_ is not None and len(PX_):
                g = with_gaps(PX_)
                panels.append(dict(title="Users connected", traces=[dict(x=g["ts"], y=g["ActiveSessions"], name="Users", colour=ui.VIOLET, kind="area")], height=.9))
            if TE_ is not None and len(TE_):
                conc_ = qe.reload_concurrency(TE_).resample("5min").max()
                conc_ = conc_[(conc_.index >= win[0]) & (conc_.index <= win[1])]
                panels.append(dict(title="Reloads running at once", traces=[dict(x=conc_.index, y=conc_.values, name="Reloads", colour=ui.ORANGE, kind="step")],
                                   height=.9, hlines=[(conc_thr, ui.CRIT, f"pile-up {conc_thr}")]))
            show(ui.ts_panels(panels, EVW_, x_range=(win[0], win[1])))

    # ---- where the load comes from -------------------------------------------------------------
    section("Where the load comes from")
    c1, c2, c3 = st.columns(3, gap="medium")
    with c1:
        with card("Apps using the most CPU", "Seconds of session CPU by app (Session_Engine log). Includes reloads."):
            if S is not None and len(S):
                g = S.groupby("app")["cpu_s"].sum().sort_values(ascending=False).head(8)
                tot = max(S["cpu_s"].sum(), 1)
                st.markdown(ui.toplist([(k, v, f"{v / tot * 100:.0f}%") for k, v in g.items()], ui.BLUE), unsafe_allow_html=True)
            else:
                st.caption("Add a Session_Engine log.")
    with c2:
        with card("Busiest reload tasks", "Hours spent running; the figure after the name is runs an hour."):
            if TE_ is not None and len(TE_):
                tt_ = qe.task_table(TE_).head(8)
                st.markdown(ui.toplist([(r_["TaskName"], r_["busy_h"], f"{r_['runs_per_h']:.0f}/h") for _, r_ in tt_.iterrows()],
                                       ui.ORANGE, fmt="{:,.1f}"), unsafe_allow_html=True)
            else:
                st.caption("Add a TaskExecution_Scheduler log.")
    with c3:
        R_ = qe.engine_requests(d)
        with card("Sessions making the most requests", "Engine requests in the loaded audit files."):
            if not R_.empty:
                g = R_.groupby(["UserId", "app"]).size().sort_values(ascending=False).head(8)
                st.markdown(ui.toplist([(f"{u} · {a_}", n) for (u, a_), n in g.items()], ui.VIOLET), unsafe_allow_html=True)
            elif Y is not None and len(Y):
                w = Y[Y["Level"] != "INFO"].groupby("cat").size().sort_values(ascending=False).head(8)
                st.caption("No audit files loaded; most frequent engine warnings instead.")
                st.markdown(ui.toplist([(k[:60], v) for k, v in w.items()], ui.SERIOUS), unsafe_allow_html=True)
            else:
                st.caption("Add AuditActivity_Engine / Service_Engine logs.")

    # ---- apps, storage, reload failures, logins ------------------------------------------------
    section("Apps, storage and logins", "beyond CPU: what's failing, who can log in, and what fills the share")
    o1, o2, o3, o4 = st.columns(4, gap="medium")
    with o1:
        with card("Reload failures", "Failed reloads in the time range, with the error from the app's own reload log."):
            ft = fail_table()
            th = qr.task_health(d.get("task_exec"))
            now_failing = int((th["failing_streak"] > 0).sum()) if len(th) else 0
            st.markdown(ui.tile("Failed runs", f"{len(ft)}", "", f"{now_failing} task(s) failing at their last run",
                                "bad" if now_failing else ("warn" if len(ft) else "good")), unsafe_allow_html=True)
            if st.button("Open Reload failures", key="ov_fail", use_container_width=True):
                go_to("Reload failures")
    with o2:
        with card("Logins", "From the proxy's audit log: logins, how long they took, and problems."):
            pc = qp.classify(d.get("proxy_audit"))
            sm_ = qp.summary(pc, d.get("proxy_perf")) if len(pc) else {}
            if sm_:
                med = sm_.get("login_median_s")
                st.markdown(ui.tile("Logins", f"{sm_['logins']:,}", "",
                                    (f"median {med:.0f}s to log in · " if med is not None else "") + f"{sm_['problems']} problems",
                                    "warn" if sm_["problems"] > 20 else "good"), unsafe_allow_html=True)
            else:
                st.markdown(ui.tile("Logins", "–", "", "load an Audit_Proxy log"), unsafe_allow_html=True)
            if st.button("Open Logins & proxy", key="ov_login", use_container_width=True):
                go_to("Logins & proxy")
    with o3:
        with card("Storage", "The QlikShare$ folder: apps, search indexes and archived logs."):
            if len(LISTING):
                tot = LISTING["size"].sum() / 1024 ** 3
                ch = qs.churn(LISTING)
                st.markdown(ui.tile("Share size", f"{tot:,.0f}", "GB", f"{ch['apps']} apps rewritten in 24 h ({ch['GB']:.0f} GB)"),
                            unsafe_allow_html=True)
            else:
                st.markdown(ui.tile("Share size", "–", "", "scanning…" if qs.JOB.running else "no scan yet"), unsafe_allow_html=True)
            if st.button("Open Storage", key="ov_storage", use_container_width=True):
                go_to("Storage")
    with o4:
        with card("Apps", "Every app with its owner, stream, size, reloads and users."):
            gaps_ = int(MASTER["name"].eq("").sum()) if len(MASTER) else 0
            st.markdown(ui.tile("Apps known", f"{len(MASTER):,}", "",
                                f"{int(MASTER['published_flag'].sum()) if len(MASTER) else 0} published · {gaps_} without a name",
                                "warn" if gaps_ > 20 else ""), unsafe_allow_html=True)
            if st.button("Open Apps", key="ov_apps", use_container_width=True):
                go_to("Apps")


# ==============================================================================================
# Apps: every app, and one app end to end (reloads, failures, users, events, storage)
# ==============================================================================================
APP_SECTIONS = ["Reloads", "Usage", "Events", "Storage and copies"]


def catalogue_panel():
    n = len(CAT)
    last = CAT["imported"].max() if n else ""
    with st.expander(f"📋  App list from the QMC · {n:,} apps" + (f" · last import {last}" if last else " · not imported yet"),
                     expanded=not n):
        st.markdown("Names, owners and streams come from the QMC. In the QMC open **Apps**, add the columns you want "
                    "(at least **ID** and **Name**; also Owner, Stream, Published, File size, Last reload), scroll to the "
                    "bottom so every app is loaded, select all and export. Import the file here whenever apps change. "
                    "Imports add to what's already here, so a partial export never loses apps.")
        ver = ss.setdefault("cat_ver", 0)
        u1, u2 = st.columns([2.2, 1])
        with u1:
            up = st.file_uploader("QMC Apps export (CSV, Excel, or the /qrs/app/full JSON)",
                                  type=["csv", "tsv", "txt", "xlsx", "json"], key=f"cat_up_{ver}")
        if up is not None:
            try:
                new = qc.read_export(up.getvalue(), up.name)
            except ValueError as exc:
                st.error(str(exc))
                new = None
            if new is not None:
                warn = qc.environment_check(new, set(APPFILES["app_id"]) if len(APPFILES) else set())
                merged, cnt = qc.merge(CAT, new, up.name)
                qc.save(merged)
                ss["cat_ver"] = ver + 1
                ss["cat_msg"] = (f"Imported {up.name}: {cnt['added']} new, {cnt['updated']} updated, {cnt['kept']} kept "
                                 "from earlier imports.", warn)
                st.rerun()
        with u2:
            if n:
                st.download_button("⬇ App list (CSV)", CAT.to_csv(index=False).encode(), "qlik_app_list.csv", "text/csv",
                                   use_container_width=True)
                with st.popover("Clear the app list", use_container_width=True):
                    st.caption("Removes every imported app. Names learned from the logs stay.")
                    if st.button("Yes, clear it", key="cat_clear"):
                        qc.save(qc.load().iloc[0:0])
                        ss["cat_ver"] = ver + 1
                        st.rerun()
        if ss.get("cat_msg"):
            ok, warn = ss["cat_msg"]
            st.success(ok)
            if warn:
                st.warning(warn)


def page_apps():
    catalogue_panel()
    M = MASTER.copy()
    if M.empty:
        st.info("No apps yet. Import a QMC Apps export above, or let the Storage page scan the share (it finds every "
                "app file), or load the Scheduler logs.")
        return
    act = app_activity()
    M = M.join(act, on="id")
    ft = fail_table(window_only=False)
    fails = ft.groupby("app_id").size() if len(ft) else pd.Series(dtype=int)
    M["failures"] = M["id"].map(fails).fillna(0).astype(int)
    for c_ in ("reloads", "failed", "users", "sessions", "cpu_s"):
        if c_ not in M:
            M[c_] = 0
        M[c_] = pd.to_numeric(M[c_], errors="coerce").fillna(0)
    M["stale"] = M["age_days"].fillna(0) >= 365
    M["owner_s"] = M["owner"].map(owner_short)

    named = M[M["name"].ne("")]
    tiles([dict(label="Apps", value=f"{len(M):,}", sub=f"{int(M['in_qmc'].sum()):,} from the QMC · {int(M['name_source'].eq('logs').sum())} named by logs"),
           dict(label="Published", value=f"{int(M['published_flag'].sum()):,}", sub=f"{M['stream'].replace('', pd.NA).nunique()} streams"),
           dict(label="On the share", value=f"{M['file_MB'].sum() / 1024:,.0f}", unit="GB",
                sub=f"+ {M['search_MB'].sum() / 1024:,.0f} GB of search indexes"),
           dict(label="Unchanged a year+", value=f"{int(M['stale'].sum())}", unit="apps",
                sub=f"{M.loc[M['stale'], 'file_MB'].sum() / 1024:,.0f} GB · {int((M['stale'] & ~M['published_flag']).sum())} unpublished",
                level="warn" if M["stale"].sum() else ""),
           dict(label="Reloads failing", value=f"{int((M['failures'] > 0).sum())}", unit="apps",
                sub=f"{len(ft)} failed runs", level="bad" if len(ft) else "good"),
           dict(label="No name yet", value=f"{int(M['name'].eq('').sum())}", sub="import a QMC export to name them",
                level="warn" if M["name"].eq("").sum() > 20 else "")])

    with card("All apps", "Click a row to open the app. Sizes come from the share scan, names and owners from the QMC export, "
              "reloads and users from the logs in the time range."):
        f1, f2, f3, f4 = st.columns([2.2, 1.6, 1.6, 1.1])
        with f1:
            txt = st.text_input("Search", placeholder="app name, owner or ID", key="apps_q", label_visibility="collapsed")
        with f2:
            streams = sorted(x for x in M["stream"].unique() if x)
            sf = st.multiselect("Stream", streams, placeholder="All streams", key="apps_stream", label_visibility="collapsed")
        with f3:
            show_ = st.selectbox("Show", ["All apps", "Published", "Reloads failing", "Not changed in a year",
                                          "Unpublished copies", "No name yet", "Used in the time range"], key="apps_show",
                                 label_visibility="collapsed")
        with f4:
            sort_ = st.selectbox("Sort", ["Size", "Name", "Reloads", "Users", "Last changed"], key="apps_sort",
                                 label_visibility="collapsed")
        F = M
        if txt:
            blob = (F["display"] + " " + F["owner"] + " " + F["id"] + " " + F["stream"]).str.lower()
            F = F[blob.str.contains(txt.lower(), regex=False)]
        if sf:
            F = F[F["stream"].isin(sf)]
        F = {"Published": lambda x: x[x["published_flag"]], "Reloads failing": lambda x: x[x["failures"] > 0],
             "Not changed in a year": lambda x: x[x["stale"]],
             "Unpublished copies": lambda x: x[x["copy"] & ~x["published_flag"]],
             "No name yet": lambda x: x[x["name"].eq("")],
             "Used in the time range": lambda x: x[(x["users"] > 0) | (x["reloads"] > 0)]}.get(show_, lambda x: x)(F)
        by_, asc_ = {"Size": ("file_MB", False), "Name": ("display", True), "Reloads": ("reloads", False),
                     "Users": ("users", False), "Last changed": ("modified", False)}[sort_]
        F = F.sort_values(by_, ascending=asc_, na_position="last")
        view = pd.DataFrame({
            "App": F["display"], "Stream": F["stream"], "Owner": F["owner_s"],
            "Published": F["published"].str[:10], "File MB": F["file_MB"].round(0), "Memory MB": F["base_MB"].round(0),
            "Last reload": F["last_reload"].str[:16], "Changed": F["modified"], "Reloads": F["reloads"].astype(int),
            "Failed": F["failures"], "Users": F["users"].astype(int),
        })
        st.caption(f"{len(F):,} of {len(M):,} apps")
        pos = select_table(view.reset_index(drop=True), "apps_tbl", height=420, column_config={
            "File MB": st.column_config.NumberColumn(format="%,.0f"), "Memory MB": st.column_config.NumberColumn(format="%,.0f"),
            "Changed": st.column_config.DatetimeColumn(format="DD MMM YY"),
            "Failed": st.column_config.NumberColumn(help="Failed reloads (task runs and reload logs)")})
        if pos is not None:
            pick = F.iloc[pos]["id"]
            if pick != ss.get("app_id"):
                ss["app_id"] = pick
                ss.pop("app_pick", None)
    labels = dict(zip(M["id"], M["display"] + "  ·  " + M["stream"].where(M["stream"].ne(""), "no stream")))
    ids = M.sort_values("display")["id"].tolist()
    if ss.get("app_id") not in labels:
        ss["app_id"] = F.iloc[0]["id"] if len(F) else ids[0]
    if ss.get("app_pick") != ss["app_id"]:
        ss["app_pick"] = ss["app_id"]
    pick = st.selectbox("Open an app", ids, format_func=lambda i: labels.get(i, i), key="app_pick")
    ss["app_id"] = pick
    app_detail(M.set_index("id").loc[pick], pick, ft)


def app_detail(r, aid: str, ft: pd.DataFrame):
    name = r["name"] or "(no name yet)"
    chips = []
    if r["stream"]:
        chips.append(chip(r["stream"], ui.RAIL))
    chips.append(chip("Published" if r["published_flag"] else "Not published", ui.GOOD if r["published_flag"] else "#9a98a6"))
    if r["copy"]:
        chips.append(chip("Copy", ui.SERIOUS))
    if r["stale"]:
        chips.append(chip("Not changed in a year", ui.WARN))
    if r["failures"]:
        chips.append(chip(f"{int(r['failures'])} failed reloads", ui.CRIT))
    if r["name_source"] == "logs":
        chips.append(chip("Name from logs", ui.BLUE))
    meta = [f"ID <code>{html.escape(aid)}</code>"]
    if r["owner"]:
        meta.append("Owner <b>" + html.escape(owner_short(r["owner"])) + "</b>")
    if r["published"]:
        meta.append(f"published {html.escape(r['published'][:16])}")
    if r["modified_by"]:
        meta.append(f"last changed by {html.escape(r['modified_by'])}")
    with card():
        st.markdown(f'<div class="ah"><span class="an">{html.escape(name)}</span><span class="chips">{"".join(chips)}</span></div>'
                    f'<div class="am">{" · ".join(meta)}</div>'
                    + (f'<div class="am" style="margin-top:4px">{html.escape(r["description"][:400])}</div>' if r["description"] else ""),
                    unsafe_allow_html=True)
        lr = r["last_reload"][:16] if r["last_reload"] else ""
        sc_ = SCRIPTS[SCRIPTS["app_id"].eq(aid)].sort_values("start") if len(SCRIPTS) else SCRIPTS
        last_log = sc_.iloc[-1] if len(sc_) else None
        tiles([dict(label="App file", value=f"{r['file_MB']:,.0f}" if pd.notna(r["file_MB"]) else "–", unit="MB",
                    sub=(f"+ {r['search_MB']:,.0f} MB search index" if r["search_MB"] else "no search index") if pd.notna(r["file_MB"]) else "not found on the share"),
               dict(label="Memory when open", value=f"{r['base_MB']:,.0f}" if pd.notna(r["base_MB"]) else "–", unit="MB",
                    sub="QMC base memory size"),
               dict(label="Last reload", value=(lr[11:16] if lr else "–"), sub=(lr[:10] if lr else "from the QMC export"),
                    level=("bad" if last_log is not None and last_log["status"] == "failed" else "")),
               dict(label="Reloads", value=f"{int(r['reloads'])}", sub=f"{int(r['failed'])} failed in the time range",
                    level="bad" if r["failed"] else ""),
               dict(label="Users", value=f"{int(r['users'])}", sub=f"{int(r['sessions'])} sessions in the time range"),
               dict(label="Changed on the share", value=f"{int(r['age_days'])}" if pd.notna(r["age_days"]) else "–", unit="days ago",
                    sub=f"{r['modified']:%d %b %Y %H:%M}" if pd.notna(r["modified"]) else "", level="warn" if r["stale"] else "")])
    sec = seg("Section", APP_SECTIONS, "app_section")
    if sec == "Reloads":
        app_reloads_section(aid, name, ft)
    elif sec == "Usage":
        app_usage_section(aid, name)
    elif sec == "Events":
        app_events_section(aid, name)
    else:
        app_storage_section(r, aid)


def app_reloads_section(aid: str, name: str, ft: pd.DataFrame):
    te = d.get("task_exec")
    runs = te[te["AppId"].astype(str).str.lower().eq(aid) & te["Status"].ne("Skipped")] if te is not None and len(te) and "AppId" in te else pd.DataFrame()
    logs = SCRIPTS[SCRIPTS["app_id"].eq(aid)].sort_values("start") if len(SCRIPTS) else SCRIPTS
    f = ft[ft["app_id"].eq(aid)] if len(ft) else ft
    if runs.empty and logs.empty:
        st.info("No reloads of this app in the loaded Scheduler logs or the reload logs read so far.")
        return
    with card("Reload runs", "Each dot is one run: how long it took. Red = failed. From the Scheduler (time range) and the app's "
              "reload logs (last few weeks)."):
        fig = go.Figure()
        if len(runs):
            bad = runs["Status"].isin(qr.FAILED)
            for m_, colr, nm in [(~bad, ui.BLUE, "task run"), (bad, ui.CRIT, "failed")]:
                x = runs[m_]
                if len(x):
                    fig.add_scatter(x=x["start"], y=x["dur_s"] / 60, mode="markers", name=nm, marker=dict(color=colr, size=7),
                                    customdata=x[["TaskName", "Status"]],
                                    hovertemplate="%{x|%d %b %H:%M} · %{y:.1f} min<br>%{customdata[0]} · %{customdata[1]}<extra></extra>")
        if len(logs):
            for st_, colr, nm in [("ok", ui.AQUA, "reload log: ok"), ("failed", ui.CRIT, "reload log: failed"), ("warn", ui.WARN, "reload log: warnings")]:
                x = logs[logs["status"].eq(st_)]
                if len(x):
                    fig.add_scatter(x=x["start"], y=x["duration_s"].fillna(0) / 60, mode="markers", name=nm,
                                    marker=dict(color=colr, size=8, symbol="diamond-open", line=dict(width=2)),
                                    customdata=x[["error"]], hovertemplate="%{x|%d %b %H:%M} · %{y:.1f} min<br>%{customdata[0]}<extra></extra>")
        fig.update_yaxes(title_text="minutes", rangemode="tozero")
        show(fig, 300, legend_below=True)
    if len(runs):
        th = qr.task_health(runs)
        with card("Its reload tasks", "Per task: runs, failures, and whether it is failing right now."):
            table(rnd(th[["task", "runs", "failed", "fail_pct", "last_status", "last_run", "last_success", "failing_streak", "aborts_at"]], 1)
                  .rename(columns={"task": "Task", "runs": "Runs", "failed": "Failed", "fail_pct": "Fail %", "last_status": "Last status",
                                   "last_run": "Last run", "last_success": "Last success", "failing_streak": "Failing in a row",
                                   "aborts_at": "Cut off at"}))
    if len(f):
        with card("Why it failed", "The error from the reload log where there is one, otherwise the Scheduler's message."):
            table(f[["start", "task", "status", "duration_s", "error", "why_source"]].rename(columns={
                "start": "When", "task": "Task", "status": "Status", "duration_s": "Seconds", "error": "Error", "why_source": "From"}))
    if len(logs):
        with st.expander(f"Reload logs read ({len(logs)})"):
            table(logs.sort_values("start", ascending=False)[["start", "status", "duration_s", "trigger", "error", "file"]]
                  .assign(status=lambda x: x["status"].map(qr.STATUS_WORD)).rename(columns={
                      "start": "Started", "status": "Result", "duration_s": "Seconds", "trigger": "By", "error": "Error", "file": "Log file"}))


def app_usage_section(aid: str, name: str):
    shown = False
    if S is not None and len(S) and "AppId" in S:
        x = S[S["AppId"].astype(str).str.lower().eq(aid) & ~S["is_scheduler"]]
        if len(x):
            shown = True
            with card("Who used it (engine sessions)", "Sessions that closed in the time range, by user. CPU is the engine CPU the "
                      "session used."):
                g = x.groupby("user").agg(sessions=("cpu_s", "size"), cpu_s=("cpu_s", "sum"), minutes=("dur_min", "sum"),
                                          last=("ts", "max")).sort_values("sessions", ascending=False).reset_index()
                c1, c2 = st.columns([1, 1.4], gap="medium")
                with c1:
                    st.markdown(ui.toplist([(u, n) for u, n in g.set_index("user")["sessions"].head(10).items()], ui.VIOLET),
                                unsafe_allow_html=True)
                with c2:
                    h = x.set_index("ts").resample("60min").size()
                    show(go.Figure(go.Bar(x=h.index, y=h.values, marker_color=ui.VIOLET, name="sessions")), 220)
                table(rnd(g, 1).rename(columns={"user": "User", "sessions": "Sessions", "cpu_s": "CPU s", "minutes": "Minutes",
                                                 "last": "Last"}))
    pc = qp.classify(d.get("proxy_audit"))
    if len(pc):
        x = pc[pc["kind"].eq("app_open") & pc["app_id"].eq(aid)]
        if len(x):
            shown = True
            with card("Opened through the proxy", "Each time someone's browser connected to this app (proxy audit log)."):
                table(x.groupby("user").agg(opens=("ts", "size"), last=("ts", "max")).sort_values("opens", ascending=False)
                      .reset_index().rename(columns={"user": "User", "opens": "Opens", "last": "Last"}))
    if not shown:
        st.info("No one used this app in the time range (or the Session_Engine and Audit_Proxy logs aren't loaded).")


def app_events_section(aid: str, name: str):
    E = with_status(EVENTS_ALL)
    if E is None or E.empty:
        st.info("No events detected in the loaded logs.")
        return
    m = E["app"].str.lower().eq(str(name).lower()) | E["title"].str.contains(re.escape(name), case=False) if name else E["app"].eq("~")
    x = E[m]
    if x.empty:
        st.info("No events mention this app.")
        return
    with card("Events for this app", "Click Investigate on the Events page for the likely cause and what else was happening."):
        table(x[["severity", "category", "title", "start", "end", "status", "owner"]])
        pick = st.selectbox("Investigate", x["id"].tolist(), format_func=lambda i: x.set_index("id").loc[i, "title"],
                            key="app_ev")
        if st.button("Open on the Events page", key="app_ev_go"):
            go_to("Events", ev_select=pick, ev_focus=True)


def app_storage_section(r, aid: str):
    base = re.sub(r"\(\d+\)\s*$", "", str(r["name"])).strip().lower()
    M = MASTER
    cp = M[(M["id"] != aid) & ((base and M["name"].str.replace(r"\(\d+\)\s*$", "", regex=True).str.strip().str.lower().eq(base))
                               | M["target_app_id"].eq(aid) | M["id"].eq(r["target_app_id"] or "~"))]
    c1, c2 = st.columns([1, 1.6], gap="medium")
    with c1:
        with card("On the share"):
            rows = [("App file", f"{r['file_MB']:,.1f} MB" if pd.notna(r["file_MB"]) else "not found"),
                    ("Search index", f"{r['search_MB']:,.1f} MB" if pd.notna(r["search_MB"]) else "none"),
                    ("Created", f"{r['created']:%d %b %Y}" if pd.notna(r["created"]) else (r["qmc_created"][:10] or "–")),
                    ("Last changed", f"{r['modified']:%d %b %Y %H:%M}" if pd.notna(r["modified"]) else (r["qmc_modified"][:16] or "–")),
                    ("Lock file", "yes (open or reloading at scan time)" if r["lock"] is True else "no"),
                    ("Reload logs on the share", f"{int(r['script_logs'])}" if pd.notna(r["script_logs"]) else "0")]
            st.markdown('<div class="kv">' + "".join(f"<span>{k}</span><b>{html.escape(str(v))}</b>" for k, v in rows) + "</div>",
                        unsafe_allow_html=True)
    with c2:
        with card(f"Copies of this app ({len(cp)})", "Same name with (1), (2)… or published from / to this app. Unpublished copies "
                  "that haven't changed in a year are usually safe to ask the owner about."):
            if len(cp):
                table(rnd(cp[["display", "stream", "owner", "published", "file_MB", "modified"]], 0).rename(columns={
                    "display": "App", "stream": "Stream", "owner": "Owner", "published": "Published", "file_MB": "MB",
                    "modified": "Changed"}))
                st.caption(f"Copies take {cp['file_MB'].sum() / 1024:,.1f} GB.")
            else:
                st.caption("No copies found.")


# ==============================================================================================
# Storage: the QlikShare$ folder
# ==============================================================================================
def scan_panel():
    J = qs.JOB

    def body():
        if J.running:
            el = (pd.Timestamp.now() - J.started).total_seconds()
            st.markdown(ui.banner("info", f"Scanning the share: {J.files:,} files, {J.bytes / 1024 ** 3:,.0f} GB so far "
                                          f"({el / 60:.0f} min)", f"Now in {J.folder[-90:]}"), unsafe_allow_html=True)
            if st.button("Stop the scan", key="scan_stop"):
                J.cancel()
        elif J.status == "done" and ss.get("scan_seen") != str(J.saved):
            ss["scan_seen"] = str(J.saved)
            if "scope" in inspect.signature(st.rerun).parameters:
                st.rerun(scope="app")
            st.rerun()
        elif J.status == "error":
            st.error(f"The last scan stopped: {J.error}")
        elif J.status == "cancelled":
            st.caption("The last scan was stopped.")

    try:
        st.fragment(run_every=2 if J.running else None)(body)()
    except (AttributeError, TypeError):
        body()


def page_storage():
    scan_panel()
    J = qs.JOB
    with st.expander("⚙  Scan the share or import a listing", expanded=LISTING.empty):
        st.markdown(f"The app lists every file under **{SHARE_ROOT or '(the folder above ArchivedLogs)'}** on a background "
                    "thread: names, sizes and dates only, nothing is opened or changed. It's the same information as the "
                    "share-listing PowerShell script. The production share has about 180,000 files, so a scan takes a few "
                    "minutes; you can keep using the app.")
        s1, s2, s3 = st.columns([1.1, 1.4, 2])
        with s1:
            if st.button("Scan now", type="primary", disabled=J.running or not SHARE_ROOT, key="scan_now"):
                if os.path.isdir(SHARE_ROOT):
                    J.start(SHARE_ROOT)
                    st.rerun()
                else:
                    st.error(f"Can't reach {SHARE_ROOT} from this PC.")
        with s2:
            auto = st.toggle("Scan once a day automatically", value=bool(qs.get_setting("auto_scan", True)), key="auto_scan_t",
                             help="When the app starts and the newest scan is more than a day old.")
            if auto != bool(qs.get_setting("auto_scan", True)):
                qs.set_setting("auto_scan", auto)
        with s3:
            up = st.file_uploader("…or import a listing made by the PowerShell script (CSV)", type=["csv"],
                                  key=f"share_up_{ss.get('share_ver', 0)}")
            if up is not None:
                try:
                    df_ = qs.read_powershell_csv(up.getvalue())
                    m_ = re.search(r"(\d{8})_(\d{6})", up.name)
                    taken = pd.to_datetime("".join(m_.groups()), format="%Y%m%d%H%M%S") if m_ else pd.Timestamp.now()
                    qs.save_snapshot(df_, SHARE_ROOT or "imported", taken=taken, source=f"import {up.name}")
                    ss["share_ver"] = ss.get("share_ver", 0) + 1
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
        if not SHARE_ROOT:
            st.caption("The ArchivedLogs folder in the Load logs panel doesn't sit under a QlikShare$ folder, so the share "
                       "can't be worked out. Set QLIK_SHARE_ROOT, or import a listing.")
    if LISTING.empty:
        st.info("No listing yet. " + ("A scan is running; this page fills in when it finishes." if J.running else
                                       "Press Scan now, or import a listing."))
        return
    C = LISTING
    taken = LISTING_META.get("taken", "")
    st.caption(f"Listing taken {taken} · {len(C):,} files · {LISTING_META.get('source', 'scan')}"
               + (" · a newer scan is running" if J.running else ""))
    A = qs.area_summary(C)
    gb = dict(zip(A["area"].astype(str), A["GB"]))
    ch = qs.churn(C)
    tiles([dict(label="Share", value=f"{C['size'].sum() / 1024 ** 3:,.0f}", unit="GB", sub=f"{len(C):,} files"),
           dict(label="Apps", value=f"{gb.get('Apps', 0):,.0f}", unit="GB", sub=f"{(C['sub'] == 'App file').sum():,} app files"),
           dict(label="Search indexes", value=f"{gb.get('App search index', 0):,.0f}", unit="GB", sub="built when apps reload"),
           dict(label="Archived logs", value=f"{gb.get('Archived logs', 0):,.0f}", unit="GB",
                sub=f"since {C.loc[C['area'] == 'Archived logs', 'mtime'].min():%b %Y}" if (C["area"] == "Archived logs").any() else ""),
           dict(label="Static content", value=f"{gb.get('Static content', 0):,.0f}", unit="GB", sub="images, extensions, files"),
           dict(label="Rewritten in 24 h", value=f"{ch['GB']:,.0f}", unit="GB", sub=f"{ch['apps']} apps saved by reloads",
                level="warn" if ch["GB"] > 10 else "")])

    l_, r_ = st.columns([1, 1.5], gap="medium")
    with l_:
        with card("Where the space goes"):
            fig = go.Figure(go.Bar(y=A["area"].astype(str), x=A["GB"], orientation="h", marker_color=ui.BLUE,
                                   text=[f"{v:,.0f} GB" for v in A["GB"]], textposition="outside", cliponaxis=False))
            fig.update_yaxes(autorange="reversed")
            fig.update_xaxes(range=[0, max(A["GB"].max(), 1) * 1.22], title_text="GB")
            show(fig, 280)
    with r_:
        with card("Archived logs added each month", "By the month each file was archived. Engine audit logs grew sharply from "
                  "September 2026 with the request storms."):
            mb = qs.archive_by_month(C)
            if len(mb):
                top4 = mb.groupby("sub")["GB"].sum().sort_values(ascending=False).index[:4].tolist()
                mb = mb.assign(sub=mb["sub"].where(mb["sub"].isin(top4), "Other")).groupby(["month", "sub"], as_index=False)[["GB", "files"]].sum()
                order = top4 + (["Other"] if (mb["sub"] == "Other").any() else [])
                pal = {"Engine": ui.BLUE, "Proxy": ui.ORANGE, "Scheduler": ui.AQUA, "Repository": ui.VIOLET}
                fig = go.Figure()
                for comp in order:
                    x = mb[mb["sub"] == comp]
                    fig.add_bar(x=x["month"], y=x["GB"], name=comp, marker_color=pal.get(comp, "#b8b5c4"),
                                hovertemplate="%{x|%b %Y}: %{y:.1f} GB<extra>" + comp + "</extra>")
                fig.update_layout(barmode="stack")
                fig.update_yaxes(title_text="GB")
                show(fig, 300)

    with card("Log types", "How much each archived log takes. 'Over a year old' is what a retention limit would free; Qlik can "
              "delete archived logs after a set number of days (ask the Qlik admins what it's set to)."):
        lt = qs.log_types(C)
        if len(lt):
            st.dataframe(rnd(lt, 2), hide_index=True, **FULL_DF, height=300, column_config={
                "component": "Component", "log_type": "Log", "files": st.column_config.NumberColumn("Files", format="%,d"),
                "GB": st.column_config.NumberColumn("GB", format="%.1f"),
                "old_GB": st.column_config.NumberColumn("Over a year old (GB)", format="%.1f"),
                "last30_GB": st.column_config.NumberColumn("Last 30 days (GB)", format="%.1f"),
                "oldest": st.column_config.DatetimeColumn("Oldest", format="DD MMM YY"),
                "newest": st.column_config.DatetimeColumn("Newest", format="DD MMM YY")})
            pa = lt[lt["log_type"].eq("Audit_Proxy")]
            if len(pa):
                st.caption(f"Audit_Proxy alone is {pa['GB'].sum():,.0f} GB. In the logs loaded, most of its lines are malformed "
                           "requests from something probing the proxy about once a second (see Logins & proxy).")

    M = MASTER
    c1, c2 = st.columns(2, gap="medium")
    with c1:
        with card("Biggest apps", "Click a row to open the app."):
            big = M[M["file_MB"].notna()].nlargest(15, "file_MB")
            v = pd.DataFrame({"App": big["display"], "Stream": big["stream"], "GB": (big["file_MB"] / 1024).round(2),
                              "Index GB": (big["search_MB"] / 1024).round(2), "Changed": big["modified"],
                              "Published": big["published_flag"]})
            pos = select_table(v.reset_index(drop=True), "st_big", column_config={"Changed": st.column_config.DatetimeColumn(format="DD MMM YY")})
            if pos is not None:
                open_app(big.iloc[pos]["id"], "Storage and copies")
    with c2:
        with card("Rewritten in the last 24 hours", "App files saved by a reload in the day before the scan. Each save rewrites the "
                  "whole file and its search index."):
            rec = M[M["age_days"].fillna(999) <= 0].nlargest(12, "file_MB") if "age_days" in M else M.iloc[0:0]
            since = ch["since"]
            if since is not None:
                rec = M[(M["modified"] >= since)].nlargest(12, "file_MB")
            st.markdown(ui.toplist([(r_.display, r_.file_MB / 1024, r_.stream) for r_ in rec.itertuples()], ui.ORANGE, fmt="{:,.1f} GB"),
                        unsafe_allow_html=True)

    with card("Clean-up candidates", "Apps whose file hasn't changed in over a year. Unpublished copies are the easiest to ask "
              "owners about. Nothing is deleted from here; this is a list to take to the owners."):
        old = M[M["age_days"].fillna(0) >= 365].copy()
        if old.empty:
            st.caption("No app files older than a year.")
        else:
            old["group"] = "Published"
            old.loc[~old["published_flag"], "group"] = "Unpublished"
            old.loc[~old["published_flag"] & old["copy"], "group"] = "Unpublished copy"
            g = old.groupby("group").agg(apps=("id", "size"), GB=("file_MB", lambda s: s.sum() / 1024)).reindex(
                ["Unpublished copy", "Unpublished", "Published"]).dropna()
            st.markdown(ui.toplist([(k, v["GB"], f"{int(v['apps'])} apps") for k, v in g.iterrows()], ui.WARN, fmt="{:,.1f} GB"),
                        unsafe_allow_html=True)
            ol = old.sort_values("file_MB", ascending=False)[["display", "group", "owner", "stream", "file_MB", "search_MB",
                                                               "modified", "id"]]
            ol = ol.assign(owner=ol["owner"].map(owner_short)).rename(columns={
                "display": "App", "group": "Kind", "owner": "Owner", "stream": "Stream", "file_MB": "MB", "search_MB": "Index MB",
                "modified": "Last changed", "id": "ID"})
            st.dataframe(rnd(ol, 0), hide_index=True, **FULL_DF, height=320,
                         column_config={"Last changed": st.column_config.DatetimeColumn(format="DD MMM YYYY")})
            st.download_button("⬇ Clean-up list (CSV)", ol.to_csv(index=False).encode(), "qlik_cleanup_candidates.csv", "text/csv")

    c3, c4 = st.columns(2, gap="medium")
    with c3:
        with card("Biggest search indexes", "Qlik builds a search index per app for smart search. Large ones belong to large apps."):
            si = M[M["search_MB"].fillna(0) > 0].nlargest(10, "search_MB")
            st.markdown(ui.toplist([(r_.display, r_.search_MB / 1024) for r_ in si.itertuples()], ui.VIOLET, fmt="{:,.1f} GB"),
                        unsafe_allow_html=True)
    with c4:
        with card("Apps with no name", "On the share but not in any QMC export or log. Import a fresh QMC export on the Apps page."):
            gp = qc.gaps(M)
            if gp.empty:
                st.markdown(ui.banner("good", "Every app on the share has a name"), unsafe_allow_html=True)
            else:
                table(rnd(gp[["id", "file_MB", "modified"]], 1).rename(columns={"id": "App ID", "file_MB": "MB", "modified": "Changed"}))

    H = qs.history()
    if H["taken"].nunique() >= 2:
        with card("Growth between scans", "Total size of each area at every scan."):
            fig = go.Figure()
            for area in qs.AREAS:
                x = H[H["area"] == area]
                if len(x):
                    fig.add_scatter(x=x["taken"], y=x["bytes"] / 1024 ** 3, name=area, mode="lines+markers")
            fig.update_yaxes(title_text="GB")
            show(fig, 280, legend_below=True)
            prev, _ = snapshot(1)
            cmp = qs.compare(C, prev)
            if cmp:
                st.caption(f"Since the scan before: {len(cmp['new_apps'])} new app file(s), {len(cmp['gone_apps'])} removed. "
                           + ", ".join(f"{k} {v:+.1f} GB" for k, v in cmp["gb_change"].items() if abs(v) >= 0.1))


# ==============================================================================================
# Reload failures
# ==============================================================================================
def page_failures():
    te = d.get("task_exec")
    c1, c2, c3 = columns_v([1.6, 1, 3])
    with c1:
        whole = st.toggle("Include reload logs outside the time range", value=True, key="fail_whole",
                          help="Reload logs (the app's own log) go back further than the Scheduler log loaded.")
    with c2:
        days_ = st.number_input("Reload logs: days", 1, 60, int(ss["script_days"]), key="script_days_in",
                                help="How far back to read the reload logs in ArchivedLogs\\Script.")
        if days_ != ss["script_days"]:
            ss["script_days"] = int(days_)
            st.rerun()
    with c3:
        st.caption(f"{len(SCRIPTS):,} reload logs read from the last {ss['script_days']} days"
                   + ("" if len(SCRIPT_FILES) else " (no Script folder under the ArchivedLogs folder you loaded)")
                   + f" · Scheduler runs: {0 if te is None else len(te):,} in the time range.")
    F = fail_table(window_only=not whole)
    th = qr.task_health(te)
    failing = th[th["failing_streak"] > 0] if len(th) else th
    if F.empty and (te is None or te.empty) and SCRIPTS.empty:
        st.info("Load a TaskExecution_Scheduler log, or point the Load logs panel at an ArchivedLogs folder with a Script folder.")
        return
    to = th[th["aborts_at"].ne("")] if len(th) else th
    tiles([dict(label="Failed runs", value=f"{len(F)}", level="bad" if len(F) else "good",
                sub=" · ".join(f"{n} {k.lower()}" for k, n in F["status"].value_counts().items()) if len(F) else "none"),
           dict(label="Apps affected", value=f"{F['app_id'].nunique() if len(F) else 0}",
                sub=f"{F['task'].replace('', pd.NA).nunique() if len(F) else 0} tasks"),
           dict(label="Failing right now", value=f"{len(failing)}", sub="tasks whose last run failed", level="bad" if len(failing) else "good"),
           dict(label="Cut off at the same time", value=f"{len(to)}", sub="tasks aborting at a fixed length (time-out)",
                level="warn" if len(to) else ""),
           dict(label="Explained", value=f"{(F['why_source'] != 'status only').mean() * 100:.0f}" if len(F) else "–", unit="%",
                sub="failures with an error message found")])
    if len(failing):
        with card("Failing right now", "Tasks whose most recent run failed. The data in these apps is going stale."):
            last_err = F.sort_values("start").groupby("task")["error"].last() if len(F) else pd.Series(dtype=str)
            v = failing.assign(error=failing["task"].map(last_err).fillna(""))
            pos = select_table(v[["task", "app", "failing_streak", "last_run", "last_success", "error"]].rename(columns={
                "task": "Task", "app": "App", "failing_streak": "Failed in a row", "last_run": "Last run",
                "last_success": "Last success", "error": "Latest error"}), "fail_now")
            if pos is not None and v.iloc[pos]["app_id"]:
                open_app(v.iloc[pos]["app_id"], "Reloads")
    if len(F):
        with card("Failures over time"):
            per = "60min" if (F["start"].max() - F["start"].min()) <= pd.Timedelta(days=4) else "1D"
            g = F.groupby([F["start"].dt.floor(per), "status"]).size().unstack(fill_value=0)
            fig = go.Figure()
            pal = {"Error": ui.CRIT, "Aborted": ui.SERIOUS, "FinishedFail": ui.WARN, "Failed (reload log)": ui.VIOLET}
            for col in g.columns:
                fig.add_bar(x=g.index, y=g[col], name=col, marker_color=pal.get(col, ui.BLUE))
            fig.update_layout(barmode="stack")
            show(fig, 240, legend_below=True)
        with card("Recurring errors", "The same error (numbers and IDs taken out) grouped together, most frequent first."):
            rc = qr.recurring(F)
            table(rc[["failures", "example", "apps", "tasks", "first", "last"]].rename(columns={
                "failures": "Failures", "example": "Error", "apps": "Apps", "tasks": "Tasks", "first": "First", "last": "Last"}))
            errs = [e for e in rc["example"].astype(str).tolist() if e.strip()][:15] if len(rc) else []
            if errs:
                pe = st.selectbox("Search Qlik Community for an error", errs, key="fail_search_pick",
                                  format_func=lambda e: e if len(e) <= 110 else e[:107] + "…")
                community_search(qsr.for_error(pe), f"fail_{hashlib.sha1(pe.encode()).hexdigest()[:8]}",
                                 "Search Qlik Community for this error")
        with card("Every failed run", "Click a row to open the app's reloads. 'From' says where the explanation was found: the app's "
                  "reload log, the task run, the Scheduler's trace, or the status only."):
            v = F.assign(app=F["app"].where(F["app"].ne(""), F["app_id"].map(app_name)))
            pos = select_table(rnd(v[["start", "task", "app", "status", "duration_s", "error", "why_source", "trigger"]], 1).rename(columns={
                "start": "When", "task": "Task", "app": "App", "status": "Status", "duration_s": "Seconds", "error": "Error",
                "why_source": "From", "trigger": "By"}), "fail_all", height=380)
            if pos is not None and v.iloc[pos]["app_id"]:
                open_app(v.iloc[pos]["app_id"], "Reloads")
            st.download_button("⬇ Failed reloads (CSV)", F.to_csv(index=False).encode(), "qlik_reload_failures.csv", "text/csv")
    else:
        st.markdown(ui.banner("good", "No failed reloads found", "in the Scheduler runs and reload logs read."), unsafe_allow_html=True)
    if len(th):
        with card("Every task", "Runs, failures and failure rate per task in the time range. 'Cut off at' shows tasks aborted at "
                  "almost exactly the same length every time: a time-out, not a script error."):
            st.dataframe(rnd(th[["task", "app", "runs", "failed", "fail_pct", "last_status", "last_run", "last_success",
                             "failing_streak", "aborts_at"]], 1), hide_index=True, **FULL_DF, height=320,
                         column_config={"fail_pct": st.column_config.ProgressColumn("Fail %", min_value=0, max_value=100, format="%.1f%%"),
                                        "task": "Task", "app": "App", "runs": "Runs", "failed": "Failed",
                                        "last_status": "Last status", "last_run": "Last run", "last_success": "Last success",
                                        "failing_streak": "Failed in a row", "aborts_at": "Cut off at"})


# ==============================================================================================
# Logins and the proxy
# ==============================================================================================
def page_logins():
    C = qp.classify(d.get("proxy_audit"))
    PX = d.get("proxy_perf")
    if C.empty and (PX is None or PX.empty):
        st.info("Load the proxy logs: Proxy\\Audit\\*_Audit_Proxy (logins, problems) and Proxy\\Trace\\*_Performance_Proxy "
                "(sessions). They're in the default log types; check the Load logs panel.")
        return
    sm = qp.summary(C, PX) if len(C) else {}
    lt = qp.login_times(C)
    items = []
    if sm:
        items += [dict(label="Logins", value=f"{sm['logins']:,}", sub=f"{sm['logins'] / sm['hours']:.1f} an hour"),
                  dict(label="People", value=f"{sm['users']:,}", sub="different users logged in"),
                  dict(label="Time to log in", value=f"{sm['login_median_s']:.0f}" if sm["login_median_s"] is not None else "–",
                       unit="s", sub=f"median · slowest 10% over {sm['login_p90_s']:.0f}s" if sm["login_p90_s"] is not None else "login page → session",
                       level="warn" if (sm["login_median_s"] or 0) >= 20 else ("good" if sm["login_median_s"] is not None else "")),
                  dict(label="Login problems", value=f"{sm['problems']:,}", sub="tickets rejected, repository and TLS failures",
                       level="warn" if sm["problems"] else "good"),
                  dict(label="Sessions timed out", value=f"{sm['timeouts']:,}", sub="closed after inactivity")]
        if sm["probe"]:
            items.append(dict(label="Malformed requests", value=f"{sm['probe']:,}", sub=f"{sm['probe_share'] * 100:.0f}% of the proxy log",
                              level="warn"))
    if PX is not None and len(PX) and not sm:
        items.append(dict(label="Sessions", value=f"{PX['ActiveSessions'].max():.0f}", sub="peak connected"))
    tiles(items)

    with card("Logins, problems and sessions over time", "Hover to read every panel at the same moment."):
        panels = []
        if len(C):
            ph = qp.per_hour(C, ["login", "login_page"])
            if len(ph):
                tr = [dict(x=ph.index, y=ph[k], name=qp.LABEL[k], colour=col, kind="bar")
                      for k, col in (("login", ui.BLUE), ("login_page", ui.AQUA)) if k in ph]
                panels.append(dict(title="Per hour: logins (blue), sent to the login page (green)", traces=tr, height=1.2))
            pr = qp.per_hour(C, qp.PROBLEM + ["timeout"])
            if len(pr):
                pal = {"ticket_bad": ui.WARN, "repo_fail": ui.CRIT, "tls": ui.VIOLET, "denied": ui.SERIOUS,
                       "session_invalid": "#b8b5c4", "timeout": ui.ORANGE}
                panels.append(dict(title="Problems per hour", height=1.1, traces=[
                    dict(x=pr.index, y=pr[k], name=qp.LABEL[k], colour=pal.get(k, ui.BLUE), kind="bar") for k in pr.columns]))
        if PX is not None and len(PX):
            g = with_gaps(PX)
            tr = [dict(x=g["ts"], y=g["ActiveSessions"], name="Sessions", colour=ui.VIOLET, kind="area")]
            if "ActiveClientWebsockets" in g:
                tr.append(dict(x=g["ts"], y=g["ActiveClientWebsockets"], name="Open app connections", colour=ui.BLUE))
            panels.append(dict(title="Connected (purple = sessions, blue = open app connections)", traces=tr, height=1))
        if panels:
            show(ui.ts_panels(panels, x_range=(win[0], win[1])))
    if len(C):
        l_, r_ = st.columns(2, gap="medium")
        with l_:
            with card("How long logins take", "From being sent to the login page to having a Qlik session, matched by address. "
                      "Includes the time the person takes to sign in."):
                if len(lt):
                    fig = go.Figure(go.Scatter(x=lt["ts"], y=lt["seconds"], mode="markers", marker=dict(color=ui.BLUE, size=7),
                                               customdata=lt[["user"]], hovertemplate="%{x|%H:%M} · %{y:.1f}s · %{customdata[0]}<extra></extra>"))
                    fig.add_hline(y=lt["seconds"].median(), line_dash="dot", line_color=ui.INK,
                                  annotation_text=f"median {lt['seconds'].median():.0f}s")
                    fig.update_yaxes(title_text="seconds", rangemode="tozero")
                    show(fig, 280)
                else:
                    st.caption("No login-page → login pairs in this window (logins with a still-valid ticket skip the login page).")
        with r_:
            with card("What the proxy logged", "Every audit message sorted into a kind. Problems are explained below."):
                k = C["kind"].value_counts()
                st.markdown(ui.toplist([(qp.LABEL.get(i, i), n) for i, n in k.items()], ui.VIOLET), unsafe_allow_html=True)
        probs = C[C["kind"].isin(qp.NOTABLE)]
        if len(probs):
            with card("Problems", "What each one means and when it happened."):
                expl = {"ticket_bad": f"The login ticket from the {site_config.LOGIN_SERVICE} had expired or was already used. A few are normal "
                                      "(a refreshed page); bursts mean logins are failing.",
                        "repo_fail": "The proxy lost its connection to the Qlik repository (port 4242) and reconnected. Users see "
                                     "slow logins or hub errors meanwhile.",
                        "tls": "A connection dropped during the secure handshake: usually a scanner or an old client.",
                        "denied": "Someone was refused access.", "session_invalid": "A browser used a session that had already ended "
                                                                                    "(timed out or logged out). Normal in small numbers."}
                g = probs.groupby("kind").agg(count=("ts", "size"), users=("user", lambda s: s.replace("", pd.NA).nunique()),
                                              first=("ts", "min"), last=("ts", "max")).reset_index()
                g["what"] = g["kind"].map(expl)
                g["kind"] = g["kind"].map(qp.LABEL)
                table(g.rename(columns={"kind": "Problem", "count": "Count", "users": "Users", "first": "First", "last": "Last",
                                        "what": "What it means"}))
        u_ = qp.users(C)
        c1, c2 = st.columns([1.3, 1], gap="medium")
        with c1:
            with card("People", "Who logged in, how often, from how many addresses."):
                if len(u_):
                    table(u_.rename(columns={"user": "User", "logins": "Logins", "first": "First", "last": "Last",
                                             "addresses": "Addresses", "method": "Method", "apps_opened": "Apps opened",
                                             "timeouts": "Timed out"}), height=320)
                else:
                    st.caption("No logins in this window.")
        with c2:
            with card("Apps opened", "Engine connections made through the proxy. Click one to open the app."):
                ao = qp.apps_opened(C, NAMES)
                if len(ao):
                    v = ao.assign(app=ao["app"].where(ao["app"].ne(""), ao["app_id"].str[:8] + "…"))
                    pos = select_table(v[["app", "opens", "users", "last"]].rename(columns={"app": "App", "opens": "Opens",
                                                                                           "users": "Users", "last": "Last"}),
                                       "lg_apps", height=320)
                    if pos is not None:
                        open_app(v.iloc[pos]["app_id"], "Usage")
                else:
                    st.caption("No app connections in this window.")
        pb = C[C["kind"].eq("probe")]
        if len(pb):
            with card("Malformed requests", "Requests with a broken first line ('GET /' and nothing else). A steady rate around the clock "
                      "is a load balancer or monitoring health check set up wrong. They fill the proxy audit log."):
                ph = pb.set_index("ts").resample("60min").size()
                show(go.Figure(go.Bar(x=ph.index, y=ph.values, marker_color=ui.SERIOUS, name="per hour")), 200)
                lt_ = qs.log_types(LISTING) if len(LISTING) else pd.DataFrame()
                pa = lt_[lt_["log_type"].eq("Audit_Proxy")] if len(lt_) else lt_
                st.caption(f"About {ph.median():,.0f} an hour ({ph.median() / 3600:.1f} a second)."
                           + (f" The archived Audit_Proxy logs take {pa['GB'].sum():,.0f} GB on the share." if len(pa) else "")
                           + " The address isn't logged; the network team can find the source from the proxy's port 443 traffic.")
    tp = qp.trace_problems(d.get("svc_system"))
    if len(tp):
        with card("Proxy trace warnings and errors", "From Proxy\\Trace\\*_System_Proxy."):
            table(tp.rename(columns={"level": "Level", "message": "Message", "count": "Count", "first": "First", "last": "Last",
                                     "example": "Detail"}))


# ==============================================================================================
# Reported issues: report, investigate (likely causes), register, trends, bulk import
# ==============================================================================================
ISS_VIEWS = ["Investigate", "Register", "Trends", "Bulk import"]
ISS_C = {"Open": ui.CRIT, "Investigating": ui.SERIOUS, "Resolved": ui.GOOD, "Closed": "#9a98a6", "Not a fault": "#9a98a6"}
SRV_OFF = qi.server_offset_min(data) if data else None
TZ_TEXT = qi.tz_label(SRV_OFF)


def reports() -> pd.DataFrame:
    p_ = qrp.path()
    return _reports(str(p_), p_.stat().st_mtime if p_.exists() else 0.0).copy()


@st.cache_data(show_spinner=False)
def _reports(path: str, mtime: float) -> pd.DataFrame:
    return qrp.load(pathlib.Path(path))


def tz_note(choice: str) -> str:
    srv = SRV_OFF if SRV_OFF is not None else qi.LOCAL_MIN
    entered = {qi.LOCAL_LABEL: qi.LOCAL_MIN, "UTC": 0}.get(choice, srv)
    diff = (srv - entered) / 60
    same = "the same clock as the logs" if diff == 0 else f"{abs(diff):g} h {'behind' if diff > 0 else 'ahead of'} the logs; converted"
    return f"The logs use {TZ_TEXT}. You're entering times in {choice}: {same}."


def report_label(r) -> str:
    return (f"{r['reported']:%d %b %y %H:%M} · {r['symptom'] if r['symptom'] != 'Not sure' else 'Problem'}"
            + (f" · {r['app']}" if r["app"] else "") + (f" · {r['reporter']}" if r["reporter"] else ""))


def page_issues():
    view = seg("View", ISS_VIEWS, "iss_view")
    {"Investigate": iss_investigate, "Register": iss_register, "Trends": iss_trends, "Bulk import": iss_import}[view]()


def _from_server(ts: pd.Timestamp, tz_choice: str) -> pd.Timestamp:
    """Server time -> the clock the person types in (inverse of qi.to_server_time)."""
    return ts - (qi.to_server_time(ts, tz_choice, SRV_OFF) - ts)


def report_fields(prefix: str, rec: dict | None = None):
    """The report fields as keyed widgets. Defaults are put in session state once (from rec, or 'now'), so a
    rerun - including the one a submit causes - never resets what was typed."""
    names = sorted({n for n in MASTER["name"] if n}, key=str.lower) if len(MASTER) else []
    k = lambda n: f"{prefix}_{n}"  # noqa: E731
    if not ss.get(k("init")):
        tz0 = ss.get("iss_tz_pref", qi.TZ_CHOICES[0])
        if rec is not None and pd.notna(rec.get("reported")):
            rep_local = _from_server(pd.Timestamp(rec["reported"]), tz0)
        else:
            rep_local = pd.Timestamp.now().floor("min")
        st_local = (_from_server(pd.Timestamp(rec["started"]), tz0) if rec is not None and pd.notna(rec.get("started"))
                    else rep_local - pd.Timedelta(minutes=20))
        app_txt = [a_.strip() for a_ in str((rec or {}).get("app") or "").split(",") if a_.strip()]
        users0 = (rec or {}).get("users_affected")
        ss.update({k("tz"): tz0, k("day"): rep_local.date(), k("time"): rep_local.time().replace(second=0, microsecond=0),
                   k("st_on"): rec is not None and pd.notna(rec.get("started")), k("st_tm"): st_local.time().replace(second=0, microsecond=0),
                   k("apps"): [a_ for a_ in app_txt if a_ in names], k("app_other"): ", ".join(a_ for a_ in app_txt if a_ not in names),
                   k("who"): (rec or {}).get("reporter", ""), k("ticket"): (rec or {}).get("ticket", ""),
                   k("sym"): (rec or {}).get("symptom") if (rec or {}).get("symptom") in R.SYMPTOMS else R.SYMPTOMS[0],
                   k("users"): int(users0) if users0 is not None and pd.notna(users0) and str(users0) != "" else 0,
                   k("rep"): (rec or {}).get("replicated") if (rec or {}).get("replicated") in ("Unknown", "Yes", "No") else "Unknown",
                   k("err"): (rec or {}).get("error_text", ""), k("notes"): (rec or {}).get("notes", ""), k("init"): True})
    c1, c2, c3, c4 = st.columns([1.1, 1, 1.5, 1.3])
    with c1:
        st.date_input("Date", format="DD/MM/YYYY", key=k("day"))
    with c2:
        st.time_input("Time", step=60, key=k("time"))
    with c3:
        tzc = st.radio("Times are in", qi.TZ_CHOICES, horizontal=True, key=k("tz"))
    with c4:
        st.checkbox("I know roughly when it started", key=k("st_on"))
        st.time_input("Started around", step=60, key=k("st_tm"), label_visibility="collapsed")
    st.caption(tz_note(tzc))
    c5, c6, c7 = st.columns([2.2, 1.3, 1.5])
    with c5:
        st.multiselect("App or dashboard", names, placeholder="Search the app list (from the QMC export)", key=k("apps"))
        st.text_input("…or type it if it isn't listed", key=k("app_other"))
    with c6:
        st.text_input("Reported by", key=k("who"))
        st.text_input("Ticket (optional)", key=k("ticket"), placeholder=site_config.TICKET_HINT)
    with c7:
        st.selectbox("What happened", R.SYMPTOMS, key=k("sym"))
        st.number_input("Users affected (0 = don't know)", 0, 10000, key=k("users"))
        st.radio("Could it be reproduced?", ["Unknown", "Yes", "No"], horizontal=True, key=k("rep"))
    st.text_area("Error text shown (paste it)", height=68, key=k("err"),
                 placeholder="e.g. ProxyError.OnNoEngineAvailable or ErrorDialog.NoConnectionCreated")
    st.text_area("Notes", height=68, key=k("notes"), placeholder="sheet, object, what they were doing…")


def report_record(prefix: str) -> dict:
    """What the report fields hold, with times converted to server time."""
    k = lambda n: ss.get(f"{prefix}_{n}")  # noqa: E731
    tzc = k("tz") or qi.TZ_CHOICES[0]
    ss["iss_tz_pref"] = tzc
    rep_t = qi.to_server_time(pd.Timestamp.combine(k("day"), k("time")), tzc, SRV_OFF)
    started = None
    if k("st_on"):
        s_ = qi.to_server_time(pd.Timestamp.combine(k("day"), k("st_tm")), tzc, SRV_OFF)
        started = s_ if s_ <= rep_t else s_ - pd.Timedelta(days=1)
    apps_ = list(k("apps") or [])
    app_list = apps_ + [a_.strip() for a_ in str(k("app_other") or "").split(",") if a_.strip()]
    return {"reported": rep_t, "started": started, "app": ", ".join(app_list),
            "app_id": ", ".join(app_id_for(a_) for a_ in apps_ if app_id_for(a_)), "symptom": k("sym"),
            "error_text": str(k("err") or "").strip(), "reporter": str(k("who") or "").strip(),
            "users_affected": k("users") or None, "replicated": k("rep"), "ticket": str(k("ticket") or "").strip(),
            "notes": str(k("notes") or "").strip()}


def clear_fields(prefix: str):
    for key in [x for x in ss.keys() if str(x).startswith(prefix + "_")]:
        del ss[key]


def iss_form():
    """New report. Returns (record, investigate_only) on submit, else None."""
    with card("Report an issue", "Fill in what you know; only the time is needed. Users usually report after the problem, so "
              "the time is treated as the latest it could have happened. Set 'started around' if you know it."):
        with st.form("iss_form", clear_on_submit=False):
            report_fields("new")
            b1, b2, b3 = st.columns([1.3, 1.3, 3])
            save_ = b1.form_submit_button("Save and investigate", type="primary")
            just = b2.form_submit_button("Investigate without saving")
        if st.button("Start again (time = now)", key="new_reset"):
            clear_fields("new")
            st.rerun()
        if not (save_ or just):
            return None
        rec = report_record("new") | {"status": "Open", "source": "manual"}
        return rec, just


def iss_investigate():
    R_ = reports()
    ids = R_.sort_values("reported", ascending=False)["id"].tolist() if len(R_) else []
    labels = {"__new": "➕ New report"} | {i: report_label(R_.set_index("id").loc[i]) for i in ids}
    if ss.get("iss_pick") not in labels:
        ss["iss_pick"] = "__new"
    # The browser keeps a list's old wording while its key stays the same, so an edited report would still show its
    # old time here. Tie the key to the wording; ss["iss_pick"] remembers the choice across the change.
    sig = hashlib.sha1("\n".join(f"{k_}={v_}" for k_, v_ in labels.items()).encode()).hexdigest()[:10]
    c1, c2 = columns_v([3, 1.2])
    with c1:
        wkey = f"iss_pick_{sig}"
        ss[wkey] = ss["iss_pick"]
        pick = st.selectbox("Report", list(labels), format_func=labels.get, key=wkey, label_visibility="collapsed",
                            on_change=lambda: ss.update(iss_pick=ss[wkey]))
    with c2:
        proj = st.text_input("Jira project", value=qs.get_setting("jira_project", site_config.JIRA_PROJECT), key="jira_proj",
                             help="Used in the Jira Rovo prompt.")
        if proj.strip() and proj.strip() != qs.get_setting("jira_project", site_config.JIRA_PROJECT):
            qs.set_setting("jira_project", proj.strip())
    rec, rid = None, None
    if pick == "__new":
        got = iss_form()
        if got:
            rec_, just = got
            if just:
                ss["iss_adhoc"] = rec_
            else:
                R2, rid_ = qrp.add(R_, rec_)
                qrp.save(R2)
                ss.pop("iss_adhoc", None)
                clear_fields("new")
                go_to("Reported issues", iss_pick=rid_)
        rec = ss.get("iss_adhoc")
    else:
        r = R_.set_index("id").loc[pick]
        rec = dict(r) | {"id": pick}
        rid = pick
        with card():
            st.markdown(f'<div class="ah"><span class="an">{html.escape(report_label(rec))}</span>'
                        f'<span class="chips">{chip(rec["status"], ISS_C.get(rec["status"], ui.BLUE))}</span></div>'
                        f'<div class="am">Reported {rec["reported"]:%a %d %b %Y %H:%M} ({TZ_TEXT})'
                        + (f" · started around {rec['started']:%H:%M}" if pd.notna(rec["started"]) else "")
                        + (f" · {int(rec['users_affected'])} users" if pd.notna(rec["users_affected"]) else "")
                        + (f" · reproducible: {rec['replicated']}" if rec["replicated"] not in ("", "Unknown") else "")
                        + (f" · ticket {html.escape(rec['ticket'])}" if rec["ticket"] else "") + "</div>"
                        + (f'<div class="am">Error: <code>{html.escape(rec["error_text"][:300])}</code></div>' if rec["error_text"] else "")
                        + (f'<div class="am">{html.escape(rec["notes"][:400])}</div>' if rec["notes"] else ""),
                        unsafe_allow_html=True)
            e1, e2, e3, e4 = columns_v([1.2, 1.3, 2.5, 1])
            with e1:
                stt = st.selectbox("Status", qrp.STATUSES, index=qrp.STATUSES.index(rec["status"]) if rec["status"] in qrp.STATUSES else 0,
                                   key=f"iss_status_{pick}")
            with e2:
                tk = st.text_input("Ticket", value=rec["ticket"], key=f"iss_tk_{pick}")
            with e3:
                nt = st.text_input("Notes", value=rec["notes"], key=f"iss_nt_{pick}")
            with e4:
                st.write("")
                if st.button("Save", key=f"iss_save_{pick}"):
                    qrp.save(qrp.update(R_, pick, status=stt, ticket=tk, notes=nt))
                    clear_fields(f"ed_{pick}")
                    st.rerun()
        with st.expander("✎  Edit this report (time, app, symptom, error…)"):
            with st.form(f"edit_form_{pick}"):
                report_fields(f"ed_{pick}", rec)
                if st.form_submit_button("Save changes and investigate again", type="primary"):
                    upd = report_record(f"ed_{pick}")
                    qrp.save(qrp.update(R_, pick, **upd))
                    clear_fields(f"ed_{pick}")
                    st.rerun()
    if rec is None:
        return
    investigate(rec, rid, R_)


def _incident(rec: dict) -> qi.Incident:
    apps_ = [a_.strip() for a_ in str(rec.get("app") or "").split(",") if a_.strip()]
    users = rec.get("users_affected")
    return qi.Incident(reported=pd.Timestamp(rec["reported"]),
                       started=pd.Timestamp(rec["started"]) if rec.get("started") is not None and pd.notna(rec.get("started")) else None,
                       symptom=rec.get("symptom") or "Not sure", error_text=rec.get("error_text") or "", apps=apps_,
                       users_affected=int(users) if users is not None and pd.notna(users) and str(users) != "" else 0,
                       replicated=rec.get("replicated") or "Unknown", reporter=rec.get("reporter") or "",
                       notes=rec.get("notes") or "")


def _settings() -> dict:
    return {"cpu_warn": cpu_warn, "cpu_thr": cpu_thr, "ram_gb": ram, "low_pct": low_pct, "high_pct": high_pct,
            "conc_thr": conc_thr, "storm": storm_thr}


def run_investigation(rec: dict):
    inc = _incident(rec)
    cov = qi.coverage(data, inc)
    ev = qi.evidence(data, inc, EVENTS_ALL, _settings(), fail_table(window_only=False), cov)
    return inc, cov, ev, qi.score(ev, inc, cov["score"])


SIG_ICON = {True: "✓", False: "–"}


def signal_list(s_) -> str:
    """The five restart signals as a checklist (HTML)."""
    texts = dict(zip(s_["signals"], s_["texts"]))
    rows = []
    for k_, label in qrs.SIGNALS.items():
        on = k_ in texts
        rows.append(f'<div style="display:flex;gap:8px;padding:3px 0;color:{"var(--ink)" if on else "var(--muted)"}">'
                    f'<b style="width:14px;color:{ui.CRIT if on else "var(--muted)"}">{SIG_ICON[on]}</b>'
                    f'<span><b>{html.escape(label)}</b>{": " + html.escape(texts[k_]) if on else " – not seen"}</span></div>')
    return "".join(rows)


VERDICT_C = {"Plausible – not confirmed": ui.SERIOUS, "Possible": ui.WARN, "Unlikely": "#9a98a6",
             "Can't tell from these logs": "#9a98a6", "No sign in these logs": "#9a98a6"}


def community_search(items: list, key: str, title: str = "Search Qlik Community", expanded: bool = False):
    """Ready-made web searches for what was seen: each opens Google (limited to community.qlik.com and help.qlik.com) or
    Qlik Community's own search in the browser. The words searched are shown exactly as they will be sent."""
    if not items:
        return
    with st.expander(f"🔎  {title} ({len(items)})", expanded=expanded):
        st.caption("Opens in your browser. Server names, users, paths, addresses, IDs, times and quoted names are taken "
                   "out first; what is sent is shown under each search.")
        for i, it in enumerate(items):
            c1, c2, c3 = st.columns([5, 1.2, 1.5])
            with c1:
                st.markdown(f"**{html.escape(it['label'])}**" + (f" · {html.escape(it['why'])}" if it.get("why") else "")
                            + f"  \n`{it['query']}`")
            with c2:
                st.link_button("Google", it["google"], **FULL_W)
            with c3:
                st.link_button("Qlik Community", it["community"], **FULL_W)


def restart_causes_panel(rf: dict, key: str, search: bool = True):
    """The possible causes of one restart, ranked, with the 'insufficient data' warning and what to check."""
    st.markdown(ui.banner("warn", "Insufficient data to confirm the cause", rf["insufficient"].split(". ", 1)[1]
                          if ". " in rf["insufficient"] else rf["insufficient"]), unsafe_allow_html=True)
    blocks = []
    for i, c_ in enumerate(rf["ranked"], 1):
        def ul(items, empty):
            return ("<ul style='margin:2px 0 6px 18px;padding:0'>" + "".join(f"<li>{html.escape(x)}</li>" for x in items)
                    + "</ul>") if items else f"<div class='fd'>{empty}</div>"
        col = VERDICT_C.get(c_["verdict"], "#9a98a6")
        blocks.append(
            f'<details class="fi" style="--c:{col}" {"open" if i <= 2 else ""}><summary>{i}. {html.escape(c_["title"])} '
            f'{chip(c_["verdict"], col)}</summary><div class="fd"><b>Consistent with</b>'
            f'{ul(c_["for"], "Nothing in the loaded logs.")}<b>Against</b>{ul(c_["against"], "Nothing in the loaded logs.")}'
            f'<b>Can these logs tell?</b> {html.escape(c_["determinable"])}</div></details>')
    st.markdown("".join(blocks), unsafe_allow_html=True)
    st.caption("Ranked by simple points for what the loaded logs show (rules in qlik_restart.causes). "
               "'Plausible – not confirmed' is the strongest verdict the logs alone can give.")
    st.markdown("**What to check next (to confirm the cause)**\n" + "\n".join(f"- {c_}" for c_ in rf["checks"]))
    if search:
        community_search(qsr.for_restart(rf), f"rs_{key}", "Search Qlik Community for this restart")


def investigate(rec: dict, rid, R_):
    inc, cov, ev, ranked = run_investigation(rec)
    rf = qi.restart_finding(data, inc, EVENTS_ALL, _settings(), RESTARTS)
    a, b = inc.window
    top = ranked[0]
    if rid and rid in set(R_["id"]):
        p_ = round(top["p"] * 100, 1)
        cur = R_.set_index("id").loc[rid]
        if cur["likely_cause"] != top["title"] or pd.isna(cur["likely_p"]) or abs(cur["likely_p"] - p_) > 0.5:
            qrp.save(qrp.update(R_, rid, likely_cause=top["title"], likely_p=p_, coverage=round(cov["score"], 2),
                                investigated=pd.Timestamp.now().floor("s")))

    section("1 · Do the logs cover it?", f"window {a:%a %d %b %H:%M} – {b:%H:%M} ({TZ_TEXT}); context {inc.context[0]:%H:%M} – {inc.context[1]:%H:%M}")
    lvl = "good" if cov["score"] >= 0.7 else "warn" if cov["score"] >= 0.35 else "bad"
    st.markdown(ui.banner(lvl, f"Log coverage of the window: {cov['score'] * 100:.0f}%",
                          " ".join(cov["warnings"]) or "Every main log source covers the window without gaps."),
                unsafe_allow_html=True)
    with st.expander("Coverage by log source", expanded=cov["score"] < 0.7):
        t = cov["table"].copy()
        table(t.drop(columns=["kind"]).rename(columns={"source": "Log", "status": "Status", "first": "First entry", "last": "Last entry",
                                                       "in_window": "Rows in window", "largest_gap_min": "Largest gap (min)"}))

    section("2 · What was happening", "the reported time (red), when it probably started (orange), the window (shaded), gaps (grey)")
    incident_chart(inc, cov)

    section("3 · Likely causes", "a heuristic estimate from the logs (prior × evidence, rules in incident_rules.py), not proof")
    main = [r for r in ranked if r.get("role", "cause") == "cause"]
    if rf:
        sg = rf["sig"]
        with card("Engine restart found in this window",
                  "Read from the engine performance log. It shows that the engine went down and came back, not why."):
            st.markdown(ui.banner("bad", qrs.headline(sg), "Recovery: " + qrs.recovery_text(sg) + "."), unsafe_allow_html=True)
            st.markdown(signal_list(sg), unsafe_allow_html=True)
    rows = [{"Rank": i, "Likely cause": r["title"], "Confidence": r["band"], "%": round(r["p"] * 100),
             "For": len(r["support"]), "Against": len(r["contra"])} for i, r in enumerate(main, 1)]
    st.dataframe(pd.DataFrame(rows), hide_index=True, **FULL_DF, column_config={
        "%": st.column_config.ProgressColumn("Estimate", min_value=0, max_value=100, format="%d%%")})
    if rf:
        st.markdown(f"**What may have caused the restart** · ranked by what the loaded logs are consistent with")
        restart_causes_panel(rf, f"inv_{rid or 'adhoc'}", search=False)
        up = rf["upstream"]
        st.markdown("**Possible upstream causes** · what was building up in the hour before the restart. These may have "
                    "led to it; they are not alternatives to it.")
        table(pd.DataFrame([{"Upstream cause": u["title"], "Seen in the hour before": " · ".join(u["seen"]) or "nothing"}
                            for u in up]))
        if st.button("Open Restart history", key=f"inv_rh_{rid or 'adhoc'}"):
            go_to("Restart history", rh_pick=sg["id"])
    for i, r in enumerate(main[:6], 1):
        with st.expander(f"{i}. {r['title']} · {r['band']} ({r['p'] * 100:.0f}%)", expanded=i == 1):
            c1, c2 = st.columns(2, gap="medium")
            with c1:
                st.markdown("**Consistent with**")
                if r["support"]:
                    table(pd.DataFrame([{"When": f"{s['ts']:%d %b %H:%M}" if s["ts"] is not None else "", "Evidence": s["text"], "From": s["source"],
                                         "Weight": round(s["contribution"], 2)} for s in r["support"]]))
                else:
                    st.caption("Nothing in the logs points to this.")
            with c2:
                st.markdown("**Against**")
                if r["contra"]:
                    table(pd.DataFrame([{"Evidence": s["text"], "From": s["source"], "Weight": round(s["contribution"], 2)}
                                        for s in r["contra"]]))
                else:
                    st.caption("Nothing in the logs counts against this.")
            if r["error_why"]:
                st.caption("The error text suggests " + "; ".join(r["error_why"]) + ".")
            chk = rf["checks"] if rf and r["id"] == "engine_restart" else r["checks"]
            st.markdown("**What to check next**\n" + "\n".join(f"- {c_}" for c_ in chk))
            st.markdown(f"**Would raise it:** {r['raise']}  \n**Would lower it:** {r['lower']}")
            st.caption(f"Score: prior {r['prior']:.1f} × symptom {r['symptom_x']:.1f} × error text {r['error_x']:.1f} × "
                       f"evidence e^{r['evidence_sum']:.2f}, normalised across all causes."
                       + (f" Raised to at least {r['floor'] * 100:.0f}% because the restart signature is in the window "
                          "(RESTART_FLOOR in incident_rules.py)." if r.get("floor") else ""))

    community_search(qsr.for_incident(inc.symptom, inc.error_text, ranked, rf), f"inv_{rid or 'adhoc'}",
                     "Search Qlik Community for this issue", expanded=True)

    section("4 · Hand it on")
    md = qi.note(inc, cov, ranked, TZ_TEXT, restart=rf)
    jira = qrp.jira_rovo_prompt(rec, ranked, cov["score"], TZ_TEXT, qs.get_setting("jira_project", site_config.JIRA_PROJECT),
                                restart=rf)
    code_kw = {"wrap_lines": True} if "wrap_lines" in inspect.signature(st.code).parameters else {}
    h1, h2 = st.columns(2, gap="medium")
    with h1:
        with card("Incident note", "Copy (icon at top right) into an email, Teams or a ticket."):
            st.code(md, language="markdown", **code_kw)
            st.download_button("⬇ Incident note (.md)", md.encode(), f"incident_{inc.reported:%Y%m%d_%H%M}.md", "text/markdown")
    with h2:
        with card("Prompt for Jira Rovo", "Paste into Rovo in Jira; it creates the Bug with these details."):
            st.code(jira, language=None, **code_kw)
            if qe.FAULT_URL:
                st.link_button(f"↗  Log a fault in {site_config.FAULT_SYSTEM}", qe.FAULT_URL)


def incident_chart(inc: qi.Incident, cov: dict):
    ca, cb = inc.context
    a, b = inc.window
    panels = []
    RP_, PF_, PX_, TE_ = data.get("repo_perf"), data.get("performance"), data.get("proxy_perf"), data.get("task_exec")

    def cut(df, col="ts"):
        return df[(df[col] >= ca) & (df[col] <= cb)] if df is not None and len(df) else None
    tr = []
    x = cut(RP_)
    if x is not None and len(x):
        tr.append(dict(x=x["ts"], y=x["machine_cpu"], name="Server CPU", colour=ui.BLUE, width=2.2))
    x = cut(PF_)
    if x is not None and len(x):
        tr.append(dict(x=x["ts"], y=x["CPULoad"], name="Engine CPU", colour=ui.AQUA))
    if tr:
        panels.append(dict(title="CPU % (blue = server, green = engine)", unit="%", ymax=100, traces=tr, height=1.3,
                           hlines=[(cpu_warn, ui.WARN, f"warning {cpu_warn}%"), (cpu_thr, ui.CRIT, f"alert {cpu_thr}%")]))
    x = cut(PF_)
    if x is not None and len(x) and "VM_GB" in x:
        panels.append(dict(title="Engine memory (GB)", traces=[dict(x=x["ts"], y=x["VM_GB"], name="Memory GB", colour=ui.VIOLET)],
                           height=.9, hlines=[(ram * low_pct / 100, ui.WARN, "low limit"), (ram * high_pct / 100, ui.CRIT, "high limit")]))
    for df_, col, nm in ((PX_, "ActiveSessions", "Users connected"), (PF_, "ActiveUsers", "Active users")):
        x = cut(df_)
        if x is not None and len(x) and col in x:
            panels.append(dict(title=nm, traces=[dict(x=x["ts"], y=x[col], name=nm, colour=ui.VIOLET, kind="area")], height=.8))
            break
    if TE_ is not None and len(TE_):
        conc_ = qe.reload_concurrency(TE_)
        conc_ = conc_[(conc_.index >= ca) & (conc_.index <= cb)]
        if len(conc_):
            panels.append(dict(title="Reloads running at once", traces=[dict(x=conc_.index, y=conc_.values, name="Reloads",
                                                                              colour=ui.ORANGE, kind="step")], height=.8))
    pa = cut(data.get("proxy_audit"))
    if pa is not None and len(pa):
        pc = qp.classify(pa)
        per = "5min"
        lg = pc[pc["kind"].eq("login")].set_index("ts").resample(per).size()
        pb = pc[pc["kind"].isin(qp.NOTABLE)].set_index("ts").resample(per).size()
        tr = [dict(x=s_.index, y=s_.values, name=nm, colour=col, kind="bar") for s_, nm, col in
              ((lg, "Logins", ui.BLUE), (pb, "Proxy problems", ui.CRIT)) if len(s_)]
        if tr:
            panels.append(dict(title="Proxy per 5 min: logins (blue), problems (red)", traces=tr, height=.8))
    rq = qe.engine_requests({k: cut(v) for k, v in data.items() if k in ("activity", "service") and v is not None})
    if rq is not None and len(rq):
        pm = rq.set_index("ts").resample("1min").size()
        panels.append(dict(title="Engine requests a minute", traces=[dict(x=pm.index, y=pm.values, name="Requests",
                                                                           colour=ui.VIOLET, kind="bar")], height=.8))
    if not panels:
        st.info("No CPU, memory, user, reload, proxy or request data loaded for this time.")
        return
    EV_ = EVENTS_ALL[(EVENTS_ALL["start"] <= cb) & (EVENTS_ALL["end"] >= ca)] if EVENTS_ALL is not None and len(EVENTS_ALL) else None
    fig = ui.ts_panels(panels, EV_, x_range=(ca, cb), row_px=150)
    fig.add_vrect(x0=a, x1=b, fillcolor="rgba(91,46,166,.08)", line_width=0, layer="below", row="all", col=1)
    for g in cov["gaps"]:
        fig.add_vrect(x0=g["start"], x1=g["end"], fillcolor="rgba(120,120,130,.22)", line_width=0, layer="below", row="all", col=1)
    rs_ = qrs.restarts(RESTARTS)
    for _, r_ in rs_[(rs_["end"] >= ca) & (rs_["start"] <= cb)].iterrows() if len(rs_) else []:
        fig.add_vrect(x0=r_["start"], x1=max(r_["end"], r_["start"] + pd.Timedelta(seconds=40)), fillcolor="rgba(200,40,40,.28)",
                      line_width=0, layer="below", row="all", col=1)
        fig.add_annotation(x=r_["end"], y=1, xref="x", yref="paper", text="Engine restart", showarrow=False, xanchor="left",
                           yanchor="bottom", font=dict(size=11, color=ui.CRIT))
    fig.add_vline(x=inc.reported, line_color=ui.CRIT, line_width=2)
    if inc.started is not None:
        fig.add_vline(x=inc.started, line_color=ui.ORANGE, line_width=2, line_dash="dash")
    show(fig)


def iss_register():
    R_ = reports()
    if R_.empty:
        st.info("No reported issues yet. Use 'Report an issue' (top right), or Bulk import.")
        return
    c1, c2, c3 = st.columns([2, 1.4, 1.4])
    with c1:
        txt = st.text_input("Search", key="reg_q", placeholder="app, reporter, error, ticket", label_visibility="collapsed")
    with c2:
        stf = st.multiselect("Status", qrp.STATUSES, default=["Open", "Investigating"], key="reg_st", label_visibility="collapsed")
    with c3:
        symf = st.multiselect("Symptom", R.SYMPTOMS, key="reg_sym", placeholder="All symptoms", label_visibility="collapsed")
    F = R_
    if stf:
        F = F[F["status"].isin(stf)]
    if symf:
        F = F[F["symptom"].isin(symf)]
    if txt:
        blob = (F["app"] + " " + F["reporter"] + " " + F["error_text"] + " " + F["ticket"] + " " + F["notes"]).str.lower()
        F = F[blob.str.contains(txt.lower(), regex=False)]
    F = F.sort_values("reported", ascending=False)
    with card(f"Reported issues ({len(F)} of {len(R_)})", "Edit any white cell (time, app, symptom, reporter, users, status, "
              "ticket, notes); changes save straight away. Times are server time. Tick Investigate on a row to open it."):
        view = F[["id", "reported", "app", "symptom", "reporter", "users_affected", "status", "ticket", "likely_cause", "likely_p",
                  "notes", "source"]].assign(open_=False)
        ed = st.data_editor(view, key=f"reg_ed_{ss.get('reg_ver', 0)}", hide_index=True, **FULL_ED, height=min(560, 38 + 35 * max(3, len(view))),
                            disabled=["likely_cause", "likely_p", "source"],
                            column_config={"id": None, "reported": st.column_config.DatetimeColumn("When", format="DD MMM YY HH:mm"),
                                           "app": "App", "symptom": st.column_config.SelectboxColumn("Symptom", options=R.SYMPTOMS),
                                           "reporter": "Reported by",
                                           "users_affected": st.column_config.NumberColumn("Users", format="%d"),
                                           "status": st.column_config.SelectboxColumn("Status", options=qrp.STATUSES, required=True),
                                           "ticket": "Ticket", "likely_cause": "Likely cause",
                                           "likely_p": st.column_config.NumberColumn("%", format="%.0f"), "notes": "Notes",
                                           "source": "Source", "open_": st.column_config.CheckboxColumn("Investigate")})
        cols_ = ["reported", "app", "symptom", "reporter", "users_affected", "status", "ticket", "notes"]
        chg = ed.merge(view, on="id", suffixes=("", "_o"))

        def _diff(a_, b_):
            return ~((a_ == b_) | (a_.isna() & b_.isna()))
        changed = pd.concat([_diff(chg[c_], chg[c_ + "_o"]) for c_ in cols_], axis=1).any(axis=1)
        chg = chg[changed]
        if len(chg):
            R2 = R_
            for _, r_ in chg.iterrows():
                R2 = qrp.update(R2, r_["id"], **{c_: (r_[c_] if not (isinstance(r_[c_], float) and pd.isna(r_[c_])) else
                                                     (None if c_ in ("reported", "users_affected") else "")) for c_ in cols_
                                                if not (c_ == "reported" and pd.isna(r_[c_]))})
            qrp.save(R2)
            ss["reg_ver"] = ss.get("reg_ver", 0) + 1
            st.toast(f"Saved {len(chg)} change(s)")
            st.rerun()
        go_ = ed[ed["open_"]]
        if len(go_):
            go_to("Reported issues", iss_view="Investigate", iss_pick=go_["id"].iloc[0])
        d1, d2, d3 = st.columns([1, 1, 3])
        with d1:
            st.download_button("⬇ Register (CSV)", F.to_csv(index=False).encode(), "qlik_reported_issues.csv", "text/csv")
        with d2:
            with st.popover("Delete a report"):
                rid = st.selectbox("Report", F["id"].tolist(), format_func=lambda i: report_label(R_.set_index("id").loc[i]), key="reg_del")
                if st.button("Delete it", key="reg_del_go"):
                    qrp.save(qrp.remove(R_, rid))
                    st.rerun()
    with st.expander("Investigate every report the loaded logs cover (fills in 'Likely cause' for trending)"):
        st.caption("Runs the same investigation for each report whose time falls inside the logs loaded now, and saves the most "
                   "likely cause with it. Reports outside the loaded logs keep what they had.")
        if st.button("Investigate them", key="reg_bulk_inv"):
            R2, n = R_, 0
            lo_, hi_ = (pd.Timestamp(lo), pd.Timestamp(hi)) if data else (None, None)
            bar = st.progress(0.0)
            todo = R_[(R_["reported"] >= lo_) & (R_["reported"] <= hi_)] if lo_ is not None else R_.iloc[0:0]
            for i, r_ in enumerate(todo.itertuples()):
                _, cov_, _, rk = run_investigation(R_.set_index("id").loc[r_.id].to_dict() | {"id": r_.id})
                R2 = qrp.update(R2, r_.id, likely_cause=rk[0]["title"], likely_p=round(rk[0]["p"] * 100, 1),
                                coverage=round(cov_["score"], 2), investigated=pd.Timestamp.now().floor("s"))
                n += 1
                bar.progress((i + 1) / max(len(todo), 1))
            qrp.save(R2)
            st.success(f"Investigated {n} report(s).")


def iss_trends():
    R_ = reports()
    T = qrp.trends(R_)
    if not T:
        st.info("No reports yet. Trends appear as reports build up (Report an issue, or Bulk import).")
        return
    inv = R_[R_["likely_cause"].ne("")]
    tiles([dict(label="Reports", value=f"{T['total']}", sub=f"{R_['reported'].min():%d %b %Y} – {R_['reported'].max():%d %b %Y}"),
           dict(label="Still open", value=f"{T['open']}", level="warn" if T["open"] else "good", sub="open or investigating"),
           dict(label="Apps reported", value=f"{R_['app'].replace('', pd.NA).nunique()}", sub="different apps or dashboards"),
           dict(label="Users affected", value=f"{int(R_['users_affected'].fillna(0).sum()):,}", sub="as reported"),
           dict(label="Investigated", value=f"{T['investigated']}", sub=f"{T['investigated'] / T['total'] * 100:.0f}% have a likely cause")])
    l_, r_ = st.columns([1.5, 1], gap="medium")
    with l_:
        with card(f"Reports per {T['period']}, by what happened"):
            g = T["by_symptom"]
            pal = [ui.BLUE, ui.ORANGE, ui.AQUA, ui.VIOLET, ui.WARN, ui.CRIT, "#b8b5c4"]
            fig = go.Figure()
            for i, col in enumerate(g.columns):
                fig.add_bar(x=g.index, y=g[col], name=col, marker_color=pal[i % len(pal)])
            fig.update_layout(barmode="stack")
            show(fig, 300)
    with r_:
        with card("Apps reported most", "Click through on the Apps page for their reloads, users and events."):
            st.markdown(ui.toplist([(k, v["reports"], f"last {v['last']:%d %b}") for k, v in T["apps"].head(10).iterrows()], ui.BLUE),
                        unsafe_allow_html=True)
    c1, c2 = st.columns([1.3, 1], gap="medium")
    with c1:
        with card("When problems are reported", "Weekday by hour (server time). A hot spot that matches a reload schedule or a "
                  "busy hour is a lead."):
            hw = T["hour_weekday"]
            fig = go.Figure(go.Heatmap(z=hw.values, x=[f"{h:02d}" for h in hw.columns], y=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
                                       colorscale=HEAT, hovertemplate="%{y} %{x}:00 · %{z} report(s)<extra></extra>", showscale=False))
            fig.update_yaxes(autorange="reversed")
            show(fig, 260)
    with c2:
        with card("Likely causes by month", "From investigated reports. A heuristic per report; the pattern over time is what counts."):
            cz = T["causes"]
            if len(cz):
                short = {h["title"]: h.get("short", h["title"]) for h in R.HYPOTHESES}
                cz = cz.rename(columns=lambda c_: short.get(c_, c_[:30]))
                cz.index = [f"{x:%b %Y}" for x in cz.index]
                fig = go.Figure()
                pal = [ui.BLUE, ui.ORANGE, ui.AQUA, ui.VIOLET, ui.WARN, ui.CRIT, "#b8b5c4", ui.GREEN, ui.SERIOUS, "#6da7ec"]
                for i, col in enumerate(cz.columns):
                    fig.add_bar(x=cz.index, y=cz[col], name=col, marker_color=pal[i % len(pal)])
                fig.update_layout(barmode="stack")
                show(fig, 260, legend_below=True)
            else:
                st.caption("No investigated reports yet. Investigate them from the Register (bottom of that view).")
    if len(T["errors"]):
        with card("Error texts reported", "Same message (numbers removed) grouped together."):
            table(T["errors"].reset_index().rename(columns={"sig": "Error", "reports": "Reports", "apps": "Apps", "last": "Last"}))


def iss_import():
    with card("Bulk import reported issues", "A CSV or Excel file with one report per row. Column names are flexible (When or Date + "
              "Time, App or Dashboard, Reported by, Symptom, Error, Users affected, Replicated, Ticket, Notes). Times are read "
              "day-first (28/10/2026 09:15) unless written 2026-10-28 09:15. Importing the same rows again skips them."):
        c1, c2 = st.columns([1, 2])
        with c1:
            st.download_button("⬇ Template (CSV)", qrp.template_csv(), "reported_issues_template.csv", "text/csv")
            tzc = st.radio("Times in the file are in", qi.TZ_CHOICES, key="imp_tz")
            st.caption(tz_note(tzc))
        with c2:
            up = st.file_uploader("File", type=["csv", "tsv", "txt", "xlsx"], key=f"imp_up_{ss.get('imp_ver', 0)}")
        if up is None:
            return
        try:
            new, problems = qrp.read_bulk(up.getvalue(), up.name, lambda t: qi.to_server_time(t, tzc, SRV_OFF))
        except ValueError as exc:
            st.error(str(exc))
            return
        for p_ in problems:
            st.warning(p_)
        R_ = reports()
        dup = new["id"].isin(set(R_["id"])) if len(R_) else pd.Series(False, index=new.index)
        st.markdown(f"**{len(new)} report(s) read**, {int(dup.sum())} already in the register.")
        table(new.assign(already=dup)[["reported", "app", "symptom", "reporter", "users_affected", "error_text", "ticket", "notes", "already"]]
              .rename(columns={"reported": "When (server time)", "app": "App", "symptom": "Symptom", "reporter": "Reported by",
                               "users_affected": "Users", "error_text": "Error", "ticket": "Ticket", "notes": "Notes",
                               "already": "Already there"}), height=min(400, 38 + 35 * max(3, len(new))))
        if st.button(f"Import {int((~dup).sum())} report(s)", type="primary", disabled=bool(dup.all()), key="imp_go"):
            R2, n = qrp.merge_bulk(R_, new)
            qrp.save(R2)
            ss["imp_ver"] = ss.get("imp_ver", 0) + 1
            ss["imp_msg"] = f"Imported {n['added']} report(s); skipped {n['skipped']} already there."
            st.rerun()
    if ss.get("imp_msg"):
        st.success(ss.pop("imp_msg"))


# ==============================================================================================
# Dispatch
# ==============================================================================================
sig = tuple(sorted((n, k, len(df_)) for n, k, df_ in loaded))
store = qe.load_store()
if store.get(qe.REPORTED_KEY) and not store.get("_reported_moved"):   # issues logged on the Events page before 3.1
    _R0, _n = qrp.migrate_events_store(qrp.load(), store, qe.REPORTED_KEY)
    qrp.save(_R0)
    store["_reported_moved"] = True
    qe.save_store(store)
# ==============================================================================================
# Restart history
# ==============================================================================================
def restart_chart(P_: pd.DataFrame, s_, pad_min: int = 60):
    """CPU, users, memory and cache hit rate around one restart, with the restart and the gap before it marked."""
    a_, b_ = pd.Timestamp(s_["start"]) - pd.Timedelta(minutes=pad_min), pd.Timestamp(s_["end"]) + pd.Timedelta(minutes=pad_min)
    x = P_[(P_["ts"] >= a_) & (P_["ts"] <= b_)] if P_ is not None and len(P_) else None
    if x is None or x.empty:
        st.info("No engine performance samples around this restart in the data shown.")
        return
    if "Hostname" in x and s_["host"]:
        x = x[x["Hostname"].astype(str).eq(s_["host"])]
    panels = [dict(title="Engine CPU %", unit="%", ymax=100, traces=[dict(x=x["ts"], y=x["CPULoad"], name="Engine CPU", colour=ui.AQUA)],
                   height=.9, hlines=[(cpu_thr, ui.CRIT, f"alert {cpu_thr}%")])]
    tr = [dict(x=x["ts"], y=x["ActiveUsers"], name="Active users", colour=ui.VIOLET, kind="area")] if "ActiveUsers" in x else []
    if "ActiveDocSessions" in x:
        tr.append(dict(x=x["ts"], y=x["ActiveDocSessions"], name="Document sessions", colour=ui.BLUE, dash="dot"))
    if tr:
        panels.append(dict(title="Active users (area) and document sessions (dotted)", traces=tr, height=.9))
    if "VM_GB" in x:
        panels.append(dict(title="Engine memory (GB)", traces=[dict(x=x["ts"], y=x["VM_GB"], name="Memory GB", colour=ui.VIOLET)],
                           height=.9, hlines=[(ram * low_pct / 100, ui.WARN, "low limit"), (ram * high_pct / 100, ui.CRIT, "high limit")]))
    if "cache_hit_pct" in x:
        panels.append(dict(title="Cache hit rate %", unit="%", ymax=105, traces=[dict(x=x["ts"], y=x["cache_hit_pct"],
                                                                                  name="Cache hit %", colour=ui.BLUE)], height=.7))
    fig = ui.ts_panels(panels, None, x_range=(a_, b_), row_px=125)
    if pd.notna(s_["gap_start"]) and s_["gap_start"] is not None:
        fig.add_vrect(x0=s_["gap_start"], x1=s_["gap_end"], fillcolor="rgba(120,120,130,.22)", line_width=0, layer="below",
                      row="all", col=1)
    fig.add_vrect(x0=s_["start"], x1=max(pd.Timestamp(s_["end"]), pd.Timestamp(s_["start"]) + pd.Timedelta(seconds=40)),
                  fillcolor="rgba(200,40,40,.3)", line_width=0, layer="below", row="all", col=1)
    fig.add_annotation(x=s_["end"], y=1, xref="x", yref="paper", text="restart", showarrow=False, xanchor="left",
                       yanchor="bottom", font=dict(size=11, color=ui.CRIT))
    show(fig)


def page_restart_history():
    st.markdown('<div class="note">A restart shows in the engine performance log as several things at once: '
                '<b>users and engine CPU fall to near zero</b>, <b>memory falls by more than 70% and builds up again</b>, '
                '<b>the cache hit rate reads ~100% straight after</b> (seen on a fresh engine), often <b>a gap in the log just before</b> '
                '(the engine stalled), and a <b>new engine process</b>. Two or more = a restart (an event, severity High); '
                'three or more = strong. One alone is weak: a partial memory drop with users steady is a cache purge. '
                'Thresholds are in <code>incident_rules.py</code> (RESTART).</div>', unsafe_allow_html=True)
    c1, c2, c3, c4 = columns_v([1.6, 1.1, 1.2, 2])
    with c1:
        scope = seg("Data", ["Loaded logs", "Archive history"], "rh_scope")
    pf_files = listing[listing["type"].eq("Performance_Engine")] if len(listing) else pd.DataFrame()
    with c2:
        ss.setdefault("rh_days", 90)
        days_ = st.number_input("Days back", 7, 3650, step=30, key="rh_days", disabled=scope != "Archive history",
                                help="How far back to read the archive's Performance_Engine files (small: about 50 KB each).")
    with c3:
        weak = st.toggle("Show weak candidates", key="rh_weak",
                         help="Single-signal candidates (for example memory falling with users steady). Usually not restarts.")
    P_, SG = data.get("performance"), RESTARTS
    if scope == "Archive history":
        if pf_files.empty:
            with c4:
                st.caption("No archive folder loaded (Load logs panel), so only the loaded logs can be searched.")
        else:
            P_, SG = archive_restarts(ss.get("arch_root", ""), len(pf_files), str(pf_files["mtime"].max()), int(days_), pf_files)
            with c4:
                st.caption(f"Read {len(P_):,} engine performance samples from {pf_files[pf_files['mtime'] >= pf_files['mtime'].max() - pd.Timedelta(days=int(days_))].shape[0]:,} "
                           "archive files. Kept until the app restarts.")
    span = (P_["ts"].min(), P_["ts"].max()) if P_ is not None and len(P_) else (None, None)
    real = qrs.restarts(SG)
    shown = SG if weak else real
    rec = real["recovery_min"].dropna() if len(real) else pd.Series(dtype=float)
    tiles([
        {"label": "Restarts", "value": f"{len(real)}", "sub": f"{(real['strength'] == 'Strong').sum() if len(real) else 0} strong · "
                                                            f"{(SG['strength'] == 'Weak').sum() if len(SG) else 0} weak candidate(s)",
         "level": "bad" if len(real) else "good"},
        {"label": "Users lost", "value": f"{real['users_lost'].sum():,.0f}" if len(real) else "0", "sub": "active users at the time, all restarts"},
        {"label": "Recovery", "value": f"{rec.median():.0f}" if len(rec) else "–", "unit": "min" if len(rec) else "",
         "sub": "median time for users to get back to half"},
        {"label": "Last restart", "value": f"{real['start'].max():%d %b}" if len(real) else "–",
         "sub": f"{real['start'].max():%a %H:%M}" if len(real) else (f"none since {span[0]:%d %b}" if span[0] is not None else "no data")},
    ])
    st.markdown(ui.banner("warn" if len(real) > 1 else "info" if len(real) else "good", "One-off or pattern?",
                          qrs.pattern(SG, span)), unsafe_allow_html=True)
    starts = qrs.engine_starts(P_)
    if len(starts):
        slot = qrs.usual_slot(starts)
        with st.expander(f"Engine start times recorded in the log ({len(starts)})" +
                         (f" · usually {slot['weekday']} about {slot['time']}" if slot else ""), expanded=False):
            st.caption("Each engine process writes the time it started ('Server Started'), so this lists every start the "
                       "loaded samples mention, even where the samples around it weren't loaded. A regular weekday and time "
                       "looks like a scheduled restart; anything else is worth explaining.")
            sg_starts = real["engine_started"].dropna() if len(real) and "engine_started" in real else pd.Series(dtype="datetime64[ns]")
            table(pd.DataFrame({
                "Engine started": starts["started"].dt.strftime("%a %d %b %Y %H:%M:%S"),
                "Process": starts["pid"], "Host": starts["host"],
                "Samples seen": starts["first_seen"].dt.strftime("%d %b %H:%M") + " – " + starts["last_seen"].dt.strftime("%d %b %H:%M"),
                "Usual slot": ["yes" if qrs.in_slot(t_, slot) else "" for t_ in starts["started"]],
                "Restart signature": ["yes" if len(sg_starts) and (sg_starts - t_).abs().min() <= pd.Timedelta(minutes=10) else ""
                                      for t_ in starts["started"]],
            }).iloc[::-1])
            if slot:
                st.caption(f"{slot['count']} starts on {slot['weekday']} at about {slot['time']} ({', '.join(slot['dates'][:8])}): "
                           "looks like a scheduled restart. Restarts outside that slot are the ones to explain.")
    if shown.empty:
        st.info("No restart signatures in this data." + (" Try Archive history to look further back." if scope == "Loaded logs" else ""))
        return
    shown = shown.sort_values("start", ascending=False).reset_index(drop=True)
    tab = pd.DataFrame({
        "When": shown["start"].dt.strftime("%a %d %b %Y %H:%M:%S"),
        "Back": shown["end"].dt.strftime("%H:%M:%S"),
        "Signals": shown["n"].astype(int).astype(str) + f" of {len(qrs.SIGNALS)}",
        "Strength": shown["strength"],
        "Users lost": shown["users_lost"].round(0),
        "Memory GB (before → low → after)": [f"{qrs._fmt_gb(a_)} → {qrs._fmt_gb(b_)} → {qrs._fmt_gb(c_)}" for a_, b_, c_ in
                                            zip(shown["vm_before"], shown["vm_low"], shown["vm_settled"])],
        "Gap before (min)": shown["gap_min"].round(0),
        "Recovery (min)": shown["recovery_min"].round(0),
        "What it had": [", ".join(qrs.SIGNALS[k_] for k_ in sg_) for sg_ in shown["signals"]],
    })
    pick = select_table(tab, "rh_table")
    if pick is None:
        want = ss.get("rh_pick")
        hit = shown.index[shown["id"].eq(want)].tolist() if want else []
        pick = hit[0] if hit else 0
    s_ = shown.iloc[pick]
    section(f"{s_['start']:%a %d %b %Y %H:%M:%S}", f"{s_['strength']} signature, {s_['n']} of {len(qrs.SIGNALS)} signals")
    l_, r_ = st.columns([1, 1.25], gap="medium")
    with l_:
        with card("What the performance log shows"):
            st.markdown(ui.banner("bad" if s_["n"] >= 2 else "warn", qrs.headline(s_), "Recovery: " + qrs.recovery_text(s_) + "."),
                        unsafe_allow_html=True)
            st.markdown(signal_list(s_), unsafe_allow_html=True)
            if s_["entry_types"]:
                st.caption("Entry types logged around it: " + ", ".join(s_["entry_types"]))
    with r_:
        with card("Around the restart", "One hour either side. Red = the restart, grey = the gap in the log before it."):
            restart_chart(P_, s_)
    with card("What may have caused it", "Ranked by what the loaded logs are consistent with. Logs loaded for that time "
                                         "(engine system log, scheduler, audit) make this sharper."):
        rf = qrs.causes(s_, data if scope == "Loaded logs" else {"performance": P_, **{k_: v_ for k_, v_ in data.items()
                                                                                      if k_ != "performance"}},
                        EVENTS_ALL, _settings(), SG)
        restart_causes_panel(rf, f"rh_{pick}")
        up = [u for u in rf["upstream"] if u["seen"]]
        if up:
            st.markdown("**Building up in the hour before** (possible upstream causes)\n"
                        + "\n".join(f"- {u['title']}: " + " · ".join(u["seen"]) for u in up))


# ==============================================================================================
# Qlik Community search
# ==============================================================================================
def page_search():
    st.markdown('<div class="note">Builds web searches from an error or log line: Google limited to Qlik Community and '
                'Qlik Help, or Qlik Community\'s own search. Server and user names, paths, addresses, IDs, times and '
                'quoted names are taken out first, so what is searched is the generic wording other people\'s posts '
                'contain. Searches open in your browser; the app itself sends nothing.</div>', unsafe_allow_html=True)
    with card("Search for an error or a problem", "Paste an error message or a log line, or describe the problem."):
        txt = st.text_area("Error, log line or description", key="cs_text", height=90, label_visibility="collapsed",
                           placeholder="e.g. Server aborted. Reason for restart: Phoenix detected: Server Watchdog is hung.")
        if txt.strip():
            items = qsr.for_text(txt)
            if items:
                community_search(items, "cs_text", "Searches", expanded=True)
            else:
                st.caption("Nothing left to search once site detail is taken out. Try more of the message.")
    if not data:
        st.caption("Load logs to see the warnings and errors in them here, ready to search.")
        return
    cm = qsr.common_messages(d if d else data, 15)
    with card("Warnings and errors in the loaded logs", "The most frequent, with site detail taken out and alike ones "
              "grouped. Pick one to search for it."):
        if cm.empty:
            st.caption("No warnings or errors with searchable wording in the time range.")
            return
        table(cm[["count", "message", "source", "first", "last"]].rename(columns={
            "count": "Times", "message": "Message (as searched)", "source": "Log", "first": "First", "last": "Last"}))
        pick = st.selectbox("Search for", list(range(len(cm))), key="cs_pick",
                            format_func=lambda i: f"{cm.loc[i, 'count']}× {cm.loc[i, 'message']}")
        community_search(qsr.for_error(cm.loc[pick, "example"]), f"cs_m{pick}", "Searches for this message", expanded=True)


def page_logsetup():
    import qlik_logsetup as ls
    st.markdown('<div class="note">How to set up Qlik Sense logging and keep the logs so this tool (and anything else) can '
                'pull history. Qlik archives logs for you but never deletes them and keeps no fixed amount of history, so '
                'how far back you can look is decided by what you switch on and what you keep.</div>', unsafe_allow_html=True)

    with card("1. What to switch on", "QMC > Engines > (each engine) > Logging and Tracing. Names can differ a little by version; defaults are Qlik's."):
        st.table(pd.DataFrame(ls.QMC_SETTINGS, columns=["Setting", "Suggested", "Why"]).set_index("Setting"))
        st.caption("Qlik's defaults leave Audit activity at Basic and Audit, QIX performance and Traffic Off. The "
                   "Requests page needs the engine audit activity log; the rest of this tool needs only the performance, "
                   "system, session and service logs.")

    with card("2. What the tool reads, and where it lives", "Each log type and the pages that go quiet without it."):
        st.table(pd.DataFrame(ls.LOG_NEEDS, columns=["Log type (in the file name)", "Component", "Used for", "Pages that need it"]).set_index("Log type (in the file name)"))
        st.code(ls.TREE, language="text")
        st.caption("Qlik moves a log to the archive when the service restarts, when a file reaches 8 MB, or when it is more "
                   "than 12 hours old (per Qlik Support's description of logging). Each archived file is named "
                   "<node>_<type>_<date>_<timestamp>.log, which is how the tool tells the types apart.")

    with card("3. Keep history", "Qlik does not clean the archive and has no retention setting for it. You decide."):
        st.markdown("- **Nothing is deleted by Qlik.** The ArchivedLogs folder grows until someone removes files. Qlik "
                    "Support's answer to \"can we delete old logs\" is that Qlik Sense will not do it and a scheduled "
                    "third-party job can.\n"
                    "- **Qlik's own monitoring apps** read about 3 months of the archive by default, so anything you "
                    "keep beyond that is for your own analysis (like this tool).\n"
                    "- **Qlik suggests at least one month** for root-cause work. For trend and year-on-year views keep "
                    "longer; the table below is a starting point, not a rule.")
        st.table(ls.targets().set_index("Environment"))
        st.markdown("**Reload script logs are different.** Qlik keeps only a few script logs per app (by default the "
                    "latest plus three older ones) and Qlik Support advises against raising that. To keep them, copy the "
                    "`Script` folder on a schedule (robocopy) at least as often as your apps reload.")
        st.markdown("**Move, don't delete.** The script below moves files older than N days from the live archive to a "
                    "history folder, keeping the layout, so the live archive stays small and nothing is lost. Delete from "
                    "the history folder on your own retention rule.")
        k1, k2, k3, k4 = st.columns([2.2, 2.2, 1, 1])
        with k1:
            sc_src = st.text_input("Live archive (source)", value=ss.get("arch_root", "") if ss.get("log_source") == SRC_SHARE else "",
                                   key="ls_src", placeholder=r"\\server\QlikShare$\ArchivedLogs\server")
        with k2:
            sc_dst = st.text_input("History folder (destination)", key="ls_dst", placeholder=r"D:\QlikLogHistory\server")
        with k3:
            sc_keep = st.number_input("Keep live (days)", 7, 365, 35, key="ls_keep")
        with k4:
            sc_dry = st.toggle("Dry run", value=True, key="ls_dry", help="Lists what would move without moving it.")
        script = ls.archive_script(sc_src, sc_dst, int(sc_keep), sc_dry)
        st.code(script, language="powershell")
        st.download_button("Download script (.ps1)", script.replace("\n", "\r\n"), "Move-QlikArchivedLogs.ps1",
                           key="ls_dl")
        st.caption("Run it on a schedule with Windows Task Scheduler under an account that can read and write both "
                   "folders. Test with the dry run first.")

    with card("4. Check what history you have", "From the archive listing in the Load panel (share source), or the Storage scan."):
        lst = listing if len(listing) else pd.DataFrame()
        need = st.number_input("Days of history you want", 7, 730, 90, key="ls_need")
        if lst.empty:
            st.caption("Choose 'Qlik server share' in the Load logs panel and point it at the ArchivedLogs folder to see "
                       "how much history each log type holds.")
        else:
            h = ls.history(lst, need_days=int(need))
            miss = ls.missing_types(lst)
            bad = h[h["status"].ne("OK")]
            st.markdown(f"**{len(h) - len(bad)} of {len(h)} log types** have {int(need)} days with no gaps."
                        + (f" **Not in the archive at all:** {', '.join(miss)}." if miss else ""))
            table(h.assign(oldest=h["oldest"].dt.strftime("%d %b %Y"), newest=h["newest"].dt.strftime("%d %b %Y %H:%M")))
            est = ls.storage_estimate(lst, int(need))
            st.caption(f"At the rate in this archive (about {est['per_day_mb']:,.0f} MB a day, measured over "
                       f"{est['basis_days']:.0f} days), {int(need)} days is about {est['gb']:,.1f} GB.")

    with card("Sources"):
        for t, u, w in ls.SOURCES:
            st.markdown(f"- [{t}]({u}) - {w}")
        st.caption("Qlik documents the log folders, the rollover triggers, the engine logging properties and that "
                   "archived logs are not deleted by Qlik. The retention figures are suggestions to adjust for your own "
                   "audit and compliance needs, not Qlik defaults.")


EVENTS_ALL = all_events()
RESTARTS = restart_sigs(sig, data.get("performance")) if data else qrs.find(None)
HEALTH = health()
set_title(ui.pill(HEALTH["level"], HEALTH["short"]))

PAGES = {
    "Overview": page_overview, "Events": page_events, "Reported issues": page_issues, "Apps": page_apps, "Storage": page_storage,
    "Server CPU": page_server_cpu, "Reloads": page_reloads, "Reload failures": page_failures,
    "Logins & proxy": page_logins, "Requests": page_requests, "Engine overview": page_engine_overview,
    "Engine health": page_engine_health, "Restart history": page_restart_history, "Apps & users": page_apps_users,
    "System events": page_system_events,
    "Trends": page_trends, "Qlik Community search": page_search, "Log setup guide": page_logsetup, "Export": page_export,
}
with safe(PAGE):
    PAGES[PAGE]()

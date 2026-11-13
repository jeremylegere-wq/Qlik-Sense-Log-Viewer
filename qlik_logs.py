"""Parsing and analysis helpers for Qlik Sense engine logs.

Handles the three tab-separated engine logs:
  *_Performance_Engine.txt  - 5 minute engine health samples (CPU load, users, memory, cache)
  *_Session_Engine.txt      - one row per closed session (app, user, CPU seconds spent)
  *_System_Engine.txt       - engine messages (warnings, suspends, app loads, security lookups)

No Streamlit code in here, so everything can be tested or reused from a notebook.
"""
from __future__ import annotations

import io
import re

import numpy as np
import pandas as pd

TS_FMT = "%Y%m%dT%H%M%S.%f"

NUM_PERF = [
    "ActiveDocSessions", "DocSessions", "DocSessionStarts", "ActiveDocs", "RefDocs", "LoadedDocs",
    "DocLoads", "DocLoadFails", "Calls", "Selections", "ActiveIpAddrs", "IpAddrs", "ActiveUsers",
    "Users", "CPULoad", "VMCommitted(MB)", "VMAllocated(MB)", "VMFree(MB)", "VMLargestFreeBlock(MB)",
    "CacheHits", "CacheLookups", "CacheObjectAdded", "CacheBytesAdded", "CacheTimeAdded", "CacheReplaced",
]
NUM_SESS = ["Session Duration", "CPU Spent (s)", "Bytes Received", "Bytes Sent", "Calls", "Selections"]

BUCKETS = {"15 min": "15min", "30 min": "30min", "Hour": "60min", "Day": "1D"}


# ----------------------------------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------------------------------
def _ts(s: pd.Series) -> pd.Series:
    """Qlik timestamps look like 20261016T040500.065+1000. Keep local time, drop the offset."""
    return pd.to_datetime(s.astype(str).str[:19], format=TS_FMT, errors="coerce")


def _ts_plain(s: pd.Series) -> pd.Series:
    return pd.to_datetime(s.astype(str).str[:15], format="%Y%m%dT%H%M%S", errors="coerce")


def read_raw(raw: bytes) -> pd.DataFrame:
    return pd.read_csv(
        io.BytesIO(raw), sep="\t", encoding="utf-8-sig", dtype=str, quoting=3,
        on_bad_lines="skip", keep_default_na=False,
    )


def parse_log(name: str, raw: bytes):
    """Return (kind, dataframe, message). See qlik_events.KIND_LABELS for the kinds."""
    import qlik_events as qe
    kind, df = qe.parse_text(raw[:4_000_000]) if b"\t" not in raw[:2000] else (None, None)
    if kind:
        return kind, df, ""
    try:
        df = read_raw(raw)
    except Exception as exc:  # noqa: BLE001
        return None, None, f"Could not read file: {exc}"
    cols = set(df.columns)
    if "Timestamp" not in cols:
        return None, None, "Not a Qlik log or a recognised PowerShell output - skipped"
    if "CPULoad" in cols:
        return "performance", prep_performance(df), ""
    if "CPU Spent (s)" in cols and "App Title" in cols:
        return "session", prep_session(df), ""
    if {"Message", "Logger"} <= cols and df["Logger"].str.startswith("System.Engine").any():
        return "system", prep_system(df), ""
    kind = qe.detect_kind(df)
    if kind:
        return kind, qe.prep(kind, df), ""
    return None, None, "Recognised as a Qlik log but not one this tool uses (licence, security, user sync...) - skipped"


def prep_performance(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["ts"] = _ts(df["Timestamp"])
    df = df.dropna(subset=["ts"])
    for c in NUM_PERF:
        if c in df:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    df["VM_GB"] = df["VMCommitted(MB)"] / 1024
    lookups = df["CacheLookups"].where(df["CacheLookups"] > 0)
    df["cache_hit_pct"] = df["CacheHits"] / lookups * 100
    if "Server Started" in df:
        df["server_started"] = _ts_plain(df["Server Started"])
    return df.sort_values("ts").reset_index(drop=True)


def prep_session(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["ts"] = _ts(df["Timestamp"])  # time the session closed
    df = df.dropna(subset=["ts"])
    for c in NUM_SESS:
        if c in df:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    df["cpu_s"] = df["CPU Spent (s)"].fillna(0.0)
    # Qlik logs session duration as a fraction of a day
    df["dur_min"] = df["Session Duration"] * 1440
    df["user"] = df["ActiveUserDirectory"].fillna("") + "\\" + df["ActiveUserId"].fillna("")
    df["is_scheduler"] = df["ActiveUserId"].eq("sa_scheduler")
    df["app"] = df["App Title"].replace("", "(no title)")
    return df.sort_values("ts").reset_index(drop=True)


_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEX = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{12,}(?![0-9a-fA-F])")
_NUM = re.compile(r"\d+(?:\.\d+)?")
_WS = re.compile(r"\s+")


def categorise(level: str, msg: str) -> str:
    """Collapse a message to a short, number-free type so similar messages group together."""
    if msg.startswith("WorkingSet: Virtual Memory"):
        m = re.search(r"is (growing CRITICALLY|growing|still) beyond", msg)
        word = {"growing CRITICALLY": "growing CRITICALLY", "growing": "growing", "still": "still"}.get(
            m.group(1) if m else "", "")
        return f"WARN WorkingSet: virtual memory {word} beyond limit".replace("  ", " ")
    msg = msg.split("jwt payload")[0]
    msg = _WS.sub(" ", _NUM.sub("#", _HEX.sub("#", _GUID.sub("#", msg)))).strip()[:90]
    return (f"{level} " if level and level != "INFO" else "") + msg


def prep_system(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["ts"] = _ts(df["Timestamp"])
    df = df.dropna(subset=["ts"])
    msgs = df[["Level", "Message"]].drop_duplicates()
    msgs["cat"] = [categorise(a, b) for a, b in zip(msgs["Level"], msgs["Message"])]
    df = df.merge(msgs, on=["Level", "Message"], how="left")
    df["doc"] = df["Message"].str.extract(r"DocName: ([0-9a-fA-F-]{36})", expand=False)
    return df.sort_values("ts").reset_index(drop=True)


def combine(parts: list[tuple[str, pd.DataFrame]]) -> dict[str, pd.DataFrame]:
    """Join files of the same kind (e.g. several days) and drop rows loaded twice."""
    out: dict[str, pd.DataFrame] = {}
    for kind in dict.fromkeys(k for k, _ in parts):
        frames = [d for k, d in parts if k == kind]
        df = pd.concat(frames, ignore_index=True)
        keys = [c for c in ("Id", "Sequence#", "Timestamp", "Hostname") if c in df]
        if not keys:
            keys = [c for c in ("ts", "files", "TopAppUser", "app", "user") if c in df]
        if keys:
            df = df.drop_duplicates(subset=keys)
        out[kind] = df.sort_values("ts").reset_index(drop=True)
    return out


# ----------------------------------------------------------------------------------------------
# Analysis helpers
# ----------------------------------------------------------------------------------------------
def restarts(perf: pd.DataFrame) -> pd.DataFrame:
    """Rows where the engine process / start time changed between samples."""
    if perf is None or perf.empty or "ProcessId" not in perf:
        return pd.DataFrame()
    rows = []
    for host, g in perf.groupby("Hostname"):
        key = g["ProcessId"].astype(str) + "|" + g.get("Server Started", pd.Series("", index=g.index)).astype(str)
        changed = key != key.shift()
        for i in g.index[changed]:
            rows.append({
                "Hostname": host, "First sample": g.at[i, "ts"], "ProcessId": g.at[i, "ProcessId"],
                "Engine started": g.at[i, "server_started"] if "server_started" in g else pd.NaT,
                "Note": "first sample in data" if i == g.index[0] else "engine restarted",
            })
    return pd.DataFrame(rows)


def bucket_pivot(df, ts_col, row_col, value_col, agg, freq, top_n=20, sort_by="sum"):
    """Rows = top_n values of row_col, columns = time buckets."""
    if df is None or df.empty:
        return pd.DataFrame()
    d = df.copy()
    d["_b"] = d[ts_col].dt.floor(freq)
    if value_col is None:
        d["_v"] = 1
        value_col = "_v"
        agg = "sum"
    pv = d.pivot_table(index=row_col, columns="_b", values=value_col, aggfunc=agg, fill_value=0)
    order = pv.sum(axis=1).sort_values(ascending=False).index[:top_n]
    return pv.loc[order]


def attribution(perf: pd.DataFrame, sess: pd.DataFrame, cores: int) -> pd.DataFrame:
    """Hourly: engine CPU load vs the CPU seconds the session log can account for."""
    if perf is None or sess is None or perf.empty or sess.empty:
        return pd.DataFrame()
    p = perf.assign(h=perf["ts"].dt.floor("60min")).groupby("h").agg(
        engine_cpu_pct=("CPULoad", "mean"), samples=("CPULoad", "size"))
    s = sess.assign(h=sess["ts"].dt.floor("60min")).groupby("h").agg(
        session_cpu_s=("cpu_s", "sum"),
        scheduler_cpu_s=("cpu_s", lambda x: x[sess.loc[x.index, "is_scheduler"]].sum()))
    a = p.join(s, how="inner")
    a = a[a["samples"] >= 10]  # skip partial hours
    capacity = cores * 3600
    a["session_cpu_pct_of_capacity"] = a["session_cpu_s"] / capacity * 100
    a["engine_cpu_core_s"] = a["engine_cpu_pct"] / 100 * capacity
    a["attributed_share_pct"] = (a["session_cpu_s"] / a["engine_cpu_core_s"].where(a["engine_cpu_core_s"] > 0) * 100)
    return a.reset_index().rename(columns={"h": "Hour"})


def suspends_by_app(system: pd.DataFrame, sess: pd.DataFrame) -> pd.DataFrame:
    if system is None or system.empty:
        return pd.DataFrame()
    s = system[system["Message"].str.startswith("Suspending: Queuing suspend") & system["doc"].notna()]
    if s.empty:
        return pd.DataFrame()
    names = {}
    if sess is not None and "AppId" in sess:
        names = sess.drop_duplicates("AppId").set_index("AppId")["app"].to_dict()
    out = s.groupby("doc").size().rename("suspends").reset_index()
    out["App"] = out["doc"].map(names).fillna(out["doc"].str[:8] + " (name not in session log)")
    return out.sort_values("suspends", ascending=False)[["App", "suspends"]].reset_index(drop=True)


def _runs(mask: pd.Series, ts: pd.Series, vals: pd.Series) -> pd.DataFrame:
    grp = (mask != mask.shift()).cumsum()
    rows = []
    for _, idx in mask.groupby(grp).groups.items():
        if mask.loc[idx[0]]:
            rows.append({"start": ts.loc[idx[0]], "end": ts.loc[idx[-1]], "samples": len(idx),
                         "avg": vals.loc[idx].mean()})
    return pd.DataFrame(rows)


def breach_runs(P: pd.DataFrame, thr: float, min_samples: int = 2) -> pd.DataFrame:
    """Stretches where engine CPU stayed at or above thr for at least min_samples samples."""
    if P is None or P.empty:
        return pd.DataFrame()
    r = _runs(P["CPULoad"] >= thr, P["ts"], P["CPULoad"])
    return r[r["samples"] >= min_samples] if len(r) else r


def findings(d: dict, cores: int, ram_gb: float, low_pct: float, high_pct: float, cpu_thr: float) -> list[dict]:
    """Plain-English observations ranked by severity. These are leads, not conclusions."""
    out: list[dict] = []

    def add(sev, title, detail):
        out.append({"severity": sev, "finding": title, "detail": detail})

    P, S, Y = d.get("performance"), d.get("session"), d.get("system")

    if P is not None and len(P):
        hot = P["CPULoad"] >= cpu_thr
        add("info", f"Engine CPU: mean {P['CPULoad'].mean():.0f}%, peak {P['CPULoad'].max():.0f}%",
            f"{hot.mean() * 100:.0f}% of {len(P)} samples were at or above {cpu_thr:.0f}%.")
        r = _runs(hot, P["ts"], P["CPULoad"])
        if len(r):
            r = r.sort_values("samples", ascending=False).iloc[0]
            if r["samples"] >= 3:
                add("high", f"Sustained high CPU: {r['start']:%d %b %H:%M} to {r['end']:%H:%M}",
                    f"{int(r['samples'])} consecutive samples at or above {cpu_thr:.0f}% (average {r['avg']:.0f}%).")
        h = P.assign(h=P["ts"].dt.floor("60min")).groupby("h")["CPULoad"].mean()
        if len(h) > 2:
            jump = h.diff()
            if jump.max() >= 15:
                t = jump.idxmax()
                add("medium", f"CPU stepped up around {t:%d %b %H:%M}",
                    f"Hourly average rose by {jump.max():.0f} points to {h[t]:.0f}%. Worth asking what changed at that time "
                    "(reload chain start, users logging on, a restart, a patch or agent update).")
        if "VM_GB" in P:
            peak = P["VM_GB"].max()
            low, high = ram_gb * low_pct / 100, ram_gb * high_pct / 100
            if peak > high:
                add("high", f"Engine memory peaked at {peak:.0f} GB, above the {high:.0f} GB high limit",
                    f"That is {peak / ram_gb * 100:.0f}% of {ram_gb:.0f} GB RAM. Above the high limit the engine evicts cache and "
                    "refuses new app loads. This is the engine's virtual memory figure, which can differ from Task Manager.")
            elif peak > low:
                add("medium", f"Engine memory peaked at {peak:.0f} GB, above the {low:.0f} GB low limit", "")
        if "cache_hit_pct" in P and P["cache_hit_pct"].notna().any():
            ch = P["cache_hit_pct"]
            if len(ch) > 20 and ch.tail(12).mean() < ch.head(12).mean() - 4:
                add("medium", "Cache hit rate fell over the period",
                    f"{ch.head(12).mean():.0f}% at the start vs {ch.tail(12).mean():.0f}% at the end.")
        rs = restarts(P)
        if len(rs) > 1:
            add("medium", f"Engine restarted {len(rs) - 1} time(s) in this data", "Restart first seen in the sample at " + ", ".join(rs.iloc[1:]["First sample"].dt.strftime("%d %b %H:%M")) + ".")

    if P is not None and S is not None:
        a = attribution(P, S, cores)
        if len(a):
            share = a["session_cpu_s"].sum() / a["engine_cpu_core_s"].sum() * 100
            sev = "high" if share < 25 else "medium" if share < 60 else "info"
            add(sev, f"Session CPU explains only {share:.0f}% of engine CPU",
                f"Across {len(a)} full hours, the session log accounts for {a['session_cpu_s'].sum():,.0f} CPU-seconds, against "
                f"about {a['engine_cpu_core_s'].sum():,.0f} implied by the engine CPU load on {cores} cores. The rest is work the "
                "session log doesn't count (app loads/saves, security checks, suspends) or another process on the server "
                "(security software, endpoint agents). Check Task Manager / typeperf to tell which. Note: I can't confirm whether "
                "CPULoad is engine-only or machine-wide.")

    if S is not None and len(S):
        tot = S["cpu_s"].sum()
        if tot > 0:
            sched = S.loc[S["is_scheduler"], "cpu_s"].sum() / tot * 100
            top = S.groupby("app")["cpu_s"].sum().sort_values(ascending=False).head(3)
            add("info", f"Top apps by session CPU: " + ", ".join(f"{k} ({v / tot * 100:.0f}%)" for k, v in top.items()),
                f"Scheduler (reload) sessions account for {sched:.0f}% of session CPU. Total {tot:,.0f} CPU-seconds.")

    if Y is not None and len(Y):
        c = Y["cat"].value_counts()
        for key, sev, label in [
            ("virtual memory growing CRITICALLY", "high", "Memory 'growing CRITICALLY beyond limit' warnings"),
            ("Low on RAM", "high", "'Low on RAM' warnings"),
            ("Average CPU usage high", "medium", "'Average CPU usage high' health warnings"),
            ("Long pre-generation time", "medium", "'Long pre-generation time' (costly expressions) warnings"),
            ("Multiple Overlapping Suspends", "medium", "Overlapping suspends (engine can't keep up with app refreshes)"),
        ]:
            n = int(c[c.index.str.contains(key, regex=False)].sum())
            if n:
                add(sev, f"{label}: {n}", f"First {Y.loc[Y['cat'].str.contains(key, regex=False), 'ts'].min():%d %b %H:%M}, "
                    f"last {Y.loc[Y['cat'].str.contains(key, regex=False), 'ts'].max():%H:%M}.")
        sus = suspends_by_app(Y, S)
        if len(sus):
            add("info", f"Most suspended app: {sus.iloc[0]['App']} ({int(sus.iloc[0]['suspends'])} suspends)",
                "Each suspend happens when an app is changed (e.g. a real-time reload saves it); every open session on it is refreshed.")
        sec = int(c[c.index.str.startswith("QrsSecurityManagement")].sum())
        if sec > 500:
            add("info", f"{sec:,} security rule lookups", "Engine asks the repository for object permissions each time apps are opened or refreshed.")

    order = {"high": 0, "medium": 1, "info": 2}
    return sorted(out, key=lambda r: order[r["severity"]])


def daily_summary(P: pd.DataFrame) -> pd.DataFrame:
    if P is None or P.empty:
        return pd.DataFrame()
    g = P.assign(Date=P["ts"].dt.date).groupby("Date")
    return g.agg(samples=("CPULoad", "size"), cpu_mean=("CPULoad", "mean"),
                 cpu_p95=("CPULoad", lambda x: x.quantile(0.95)), cpu_max=("CPULoad", "max"),
                 users_max=("ActiveUsers", "max"), vm_gb_max=("VM_GB", "max"),
                 cache_hit_mean=("cache_hit_pct", "mean")).round(1).reset_index()

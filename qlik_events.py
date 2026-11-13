"""Server-wide Qlik Sense logs and event detection.

The engine logs (Performance / Session / System engine) are handled in qlik_logs.py. This module adds
the other logs found under the ArchivedLogs share and turns everything into a list of *events*:
things worth looking at, each with a start/end, severity, plain-English detail and a stable id so a
status and notes can be tracked against it.

Log kinds added here
  repo_perf     Repository\\Trace\\*_Performance_Repository   machine-wide CPU every 5 min
  proxy_perf    Proxy\\Trace\\*_Performance_Proxy             active sessions / websockets every 5 min
  task_exec     Scheduler\\Trace\\*_TaskExecution_Scheduler   one row per reload task run
  service       <Service>\\System\\*_Service_<Service>        warnings/errors with a command + result
  activity      <Service>\\Audit\\*_AuditActivity_<Service>   every request (engine Get layout, repository Open app...)
  proxy_audit   Proxy\\Trace\\*_Audit_Proxy                   proxy audit (malformed requests, logins)
  svc_system    <Service>\\Trace\\*_System_<Service>          trace messages for non-engine services
  audit_counts  text output of the "audit files per hour" PowerShell command
  audit_sample  text output of the "top app/user per day" PowerShell script
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
from pathlib import Path

import numpy as np
import pandas as pd

import site_config

TS_FMT = "%Y%m%dT%H%M%S.%f"
LONG_KINDS = {"audit_counts", "audit_sample"}  # long-history summaries, not cut by the time window

KIND_LABELS = {
    "performance": "Engine performance", "session": "Engine sessions", "system": "Engine system",
    "repo_perf": "Repository performance (machine CPU)", "proxy_perf": "Proxy performance (sessions)",
    "task_exec": "Scheduler task runs", "service": "Service warnings/errors", "activity": "Audit activity (requests)",
    "proxy_audit": "Proxy audit", "svc_system": "Service trace (non-engine)",
    "audit_counts": "Engine audit files per hour", "audit_sample": "Engine audit daily sample",
}

STATUSES = ["New", "Investigating", "Monitoring", "Resolved", "Ignored"]
OPEN_STATUSES = ["New", "Investigating", "Monitoring"]


def _ts(s: pd.Series) -> pd.Series:
    return pd.to_datetime(s.astype(str).str[:19], format=TS_FMT, errors="coerce")


def _num(df, cols):
    for c in cols:
        if c in df:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    return df


def _keep(df, cols):
    return df[[c for c in cols if c in df]].copy()


# ----------------------------------------------------------------------------------------------
# Detection + preparation
# ----------------------------------------------------------------------------------------------
def detect_kind(df: pd.DataFrame) -> str | None:
    cols = set(df.columns)
    logger = df["Logger"].astype(str) if "Logger" in cols else pd.Series([], dtype=str)
    if "Machine_ProcessorTimePercent" in cols:
        return "repo_perf"
    if {"ActiveSessions", "ActiveClientWebsockets"} <= cols:
        return "proxy_perf"
    if {"TaskName", "Status", "Duration", "StartTime"} <= cols:
        return "task_exec"
    if {"Command", "Result", "Service", "Severity"} <= cols:
        return "service"
    if {"Command", "Result", "Service", "ObjectName"} <= cols:
        return "activity"
    if len(logger) and logger.str.startswith("Audit.Proxy").any():
        return "proxy_audit"
    if "Message" in cols and len(logger) and logger.str.startswith("System.").any():
        return "svc_system"
    return None


def prep(kind: str, df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["ts"] = _ts(df["Timestamp"])
    df = df.dropna(subset=["ts"])
    if kind == "repo_perf":
        df = _num(df, ["Machine_ProcessorTimePercent", "Repository_ProcessorTimePercent", "Repository_WorkingSetMemory"])
        df["machine_cpu"] = df["Machine_ProcessorTimePercent"]
        df["repo_cpu"] = df["Repository_ProcessorTimePercent"]
        df = _keep(df, ["ts", "Timestamp", "Sequence#", "Id", "Hostname", "machine_cpu", "repo_cpu"])
    elif kind == "proxy_perf":
        cols = ["ActiveSessions", "ActiveConnections", "ActiveStreams", "ActiveClientWebsockets", "ActiveEngineWebsockets",
                "Tickets", "WorkerThreads", "HandleCount", "LoadBalancingDecisions"]
        df = _num(df, cols)
        df = _keep(df, ["ts", "Timestamp", "Sequence#", "Id", "Hostname"] + cols)
    elif kind == "task_exec":
        df["start"] = _ts(df["StartTime"])
        df["stop"] = _ts(df["StopTime"])
        df["dur_s"] = pd.to_numeric(df["Duration"], errors="coerce") / 1000
        df["start"] = df["start"].fillna(df["ts"])
        df["stop"] = df["stop"].fillna(df["start"] + pd.to_timedelta(df["dur_s"].fillna(0), unit="s"))
        df = _keep(df, ["ts", "Timestamp", "Sequence#", "Id", "Hostname", "TaskName", "TaskId", "AppName", "AppId",
                        "ExecutionId", "Status", "FailureReason", "start", "stop", "dur_s"])
    elif kind in ("service", "activity"):
        df["app"] = df["ObjectName"].astype(str).str.split("|").str[0]
        if kind == "service" and "Service" in df:
            # for the Scheduler the object is "Task name|App name"
            sch = df["Service"].eq("Scheduler")
            df.loc[sch, "app"] = df.loc[sch, "ObjectName"].astype(str).str.split("|").str[-1]
            df["task"] = np.where(sch, df["ObjectName"].astype(str).str.split("|").str[0], "")
        df["obj"] = df["ObjectId"].astype(str).str.split("|").str[-1] if "ObjectId" in df else ""
        df = _keep(df, ["ts", "Timestamp", "Sequence#", "Id", "Hostname", "Severity", "Service", "Command", "Result",
                        "Description", "Message", "UserId", "ProxySessionId", "SessionId", "ObjectName", "ObjectId",
                        "app", "obj", "task"])
    elif kind == "proxy_audit":
        df = _keep(df, ["ts", "Timestamp", "Sequence#", "Id", "Hostname", "Level", "Message", "ActiveUserId",
                        "ActiveUserDirectory", "IpAddress", "AppId", "ProxySessionId", "VirtualProxy", "TargetHost"])
    elif kind == "svc_system":
        df["service"] = df["Logger"].astype(str).str.split(".").str[1]
        df = _keep(df, ["ts", "Timestamp", "Sequence#", "Id", "Hostname", "Level", "Logger", "service", "Message",
                        "Exception", "TaskName", "AppName", "AppId", "ExecutionId", "User"])
    return df.sort_values("ts").reset_index(drop=True)


# --- PowerShell text outputs -----------------------------------------------------------------
_COUNT_RE = re.compile(r"^\s*(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}))?\s+(\d+)\s*$")
_SAMPLE_RE = re.compile(r"^\s*(\d{4}-\d{2}-\d{2})\s+(\d+)\s+(\d{2}:\d{2})\s+(.+?)\s+(\d+)\s*$")


def _decode(raw: bytes) -> str:
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def parse_text(raw: bytes):
    """Recognise the two PowerShell outputs. Returns (kind, df) or (None, None)."""
    text = _decode(raw)
    lines = [l for l in text.splitlines() if l.strip() and not set(l.strip()) <= set("- ")]
    if not lines:
        return None, None
    samp = [m for m in (_SAMPLE_RE.match(l) for l in lines) if m]
    if len(samp) >= 3 and len(samp) >= 0.6 * len(lines):
        rows = []
        for m in samp:
            top = m.group(4)
            app, _, user = top.partition(", ")
            rows.append({"day": pd.Timestamp(m.group(1)), "files": int(m.group(2)), "sampled": m.group(3),
                         "app": app.split("|")[0], "user": user, "share_pct": int(m.group(5))})
        df = pd.DataFrame(rows)
        df["ts"] = df["day"] + pd.to_timedelta(df["sampled"] + ":00")
        return "audit_sample", df.sort_values("ts").reset_index(drop=True)
    cnt = [m for m in (_COUNT_RE.match(l) for l in lines) if m]
    if len(cnt) >= 5 and len(cnt) >= 0.8 * len(lines):
        df = pd.DataFrame({"ts": pd.to_datetime([m.group(1) + " " + (m.group(2) or "00:00") for m in cnt]),
                           "files": [int(m.group(3)) for m in cnt]})
        df["hourly"] = any(m.group(2) for m in cnt)
        return "audit_counts", df.sort_values("ts").reset_index(drop=True)
    return None, None


# ----------------------------------------------------------------------------------------------
# Event model + status store
# ----------------------------------------------------------------------------------------------
def _ev(category, title, start, end, severity, detail, app="", user="", metric="", source="", key=""):
    start, end = pd.Timestamp(start), pd.Timestamp(end if end is not None else start)
    if end < start:
        end = start
    eid = hashlib.sha1(f"{category}|{key or title}|{start:%Y%m%d%H}".encode()).hexdigest()[:10]
    return {"id": eid, "start": start, "end": end, "severity": severity, "category": category, "title": title,
            "app": app, "user": user, "metric": metric, "detail": detail, "source": source}


def _groups(ts: pd.Series, gap: pd.Timedelta) -> pd.Series:
    """Label rows (sorted by ts) into groups wherever the gap to the previous row exceeds `gap`."""
    return (ts.diff() > gap).cumsum()


def _dur(a, b) -> str:
    m = (pd.Timestamp(b) - pd.Timestamp(a)).total_seconds() / 60
    return f"{m:.0f} min" if m < 120 else f"{m / 60:.1f} h" if m < 72 * 60 else f"{m / 1440:.0f} days"


def default_store_path() -> Path:
    return Path(os.environ.get("QLIK_EVENT_STORE", Path.home() / ".qlik_log_analyzer" / "event_status.json"))


def load_store(path: Path | None = None) -> dict:
    p = path or default_store_path()
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - missing or unreadable store just means nothing tracked yet
        return {}


def save_store(store: dict, path: Path | None = None) -> None:
    p = path or default_store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(store, indent=1, default=str), encoding="utf-8")
    tmp.replace(p)


# ----------------------------------------------------------------------------------------------
# Detectors
# ----------------------------------------------------------------------------------------------
def engine_requests(d: dict) -> pd.DataFrame:
    """Engine requests from AuditActivity_Engine (successes) and Service_Engine (failures)."""
    frames = []
    for k in ("activity", "service"):
        df = d.get(k)
        if df is not None and len(df) and "Service" in df:
            e = df[df["Service"].eq("Engine")]
            if len(e):
                frames.append(e.assign(failed=~e["Result"].astype(str).eq("0")))
    if not frames:
        return pd.DataFrame()
    r = pd.concat(frames, ignore_index=True)
    r["sess"] = r["ProxySessionId"].where(r["ProxySessionId"].astype(str).str.len() > 1, r["UserId"])
    return r.sort_values("ts")


def session_storms(r: pd.DataFrame, per_min: int = 600) -> pd.DataFrame:
    """Minute-level request rates per browser session (all apps together, so a session spread across several apps
    is still caught); returns merged runs at/above per_min requests a minute, naming the app(s) involved."""
    if r is None or r.empty:
        return pd.DataFrame()
    r = r.assign(minute=r["ts"].dt.floor("min"))
    pm = r.groupby(["sess", "UserId", "minute"]).size().rename("n").reset_index()
    hot = pm[pm["n"] >= per_min].sort_values(["sess", "minute"])
    rows = []
    for (sess, user), g in hot.groupby(["sess", "UserId"]):
        for _, gg in g.groupby(_groups(g["minute"], pd.Timedelta(minutes=2))):
            a, b = gg["minute"].min(), gg["minute"].max() + pd.Timedelta(minutes=1)
            sub = r[(r["sess"] == sess) & (r["UserId"] == user) & (r["ts"] >= a) & (r["ts"] < b)]
            apps = sub["app"].value_counts()
            app = apps.index[0] if len(apps) == 1 else ", ".join(apps.index[:3]) + (" …" if len(apps) > 3 else "")
            rows.append({"start": a, "end": b, "session": sess, "user": user, "app": app, "apps": len(apps),
                         "requests": len(sub), "peak_per_s": gg["n"].max() / 60, "objects": sub["obj"].nunique(),
                         "failed_pct": sub["failed"].mean() * 100})
    return pd.DataFrame(rows)


def detect_storms(d, per_min=600):
    out = []
    for _, s in session_storms(engine_requests(d), per_min).iterrows():
        sev = "High" if s["peak_per_s"] >= 50 or (s["end"] - s["start"]) >= pd.Timedelta(minutes=30) else "Medium"
        out.append(_ev(
            "Request storm", f"Request storm on {s['app']} ({s['user']})", s["start"], s["end"], sev,
            f"One session made {s['requests']:,} engine requests in {_dur(s['start'], s['end'])} "
            + (f"across {s['apps']} apps ({s['app']}) " if s["apps"] > 1 else "") +
            f"(peak {s['peak_per_s']:.0f} a second) across {s['objects']:,} different objects; "
            f"{s['failed_pct']:.0f}% failed. A healthy session goes quiet after its sheet loads. Open the app in a "
            "browser, press F12 > Network > WS and watch Messages while idle: if they never stop, switch sheets to "
            "find the object that keeps re-creating itself (often an extension or container).",
            app=s["app"], user=s["user"], metric=f"{s['peak_per_s']:.0f}/s peak", source="Engine audit/service",
            key=f"{s['session']}|{s['user']}"))
    return out


def audit_daily(counts: pd.DataFrame) -> pd.DataFrame:
    if counts is None or counts.empty:
        return pd.DataFrame()
    day = counts.set_index("ts")["files"].resample("1D").sum()
    df = day.rename("files").to_frame()
    df["weekend"] = df.index.day_of_week >= 5
    df["baseline"] = np.nan
    for we in (False, True):
        m = df["weekend"] == we
        df.loc[m, "baseline"] = df.loc[m, "files"].expanding(min_periods=14).median().shift(1)
    return df


def detect_audit_volume(counts):
    df = audit_daily(counts)
    if df.empty:
        return []
    base = df["baseline"].clip(lower=2)
    hot = df[(df["files"] >= np.maximum(4 * base, base + 30)) & df["baseline"].notna()]
    out = []
    if hot.empty:
        return out
    hourly = counts.set_index("ts")["files"] if bool(counts["hourly"].iloc[0]) else None
    for _, g in hot.groupby(_groups(hot.index.to_series(), pd.Timedelta(days=2))):
        a, b = g.index.min(), g.index.max() + pd.Timedelta(days=1)
        ratio = (g["files"] / base.loc[g.index]).mean()
        days = len(g)
        sev = "High" if days >= 3 and ratio >= 4 else "Medium" if days >= 2 else "Low"
        extra = ""
        if hourly is not None:
            h = hourly[(hourly.index >= a) & (hourly.index < b)]
            quiet = h[(h.index.hour < 6) | (h.index.day_of_week >= 5)]
            busy_quiet = int((quiet >= 4).sum())
            if busy_quiet:
                extra = (f" {busy_quiet} of those hours were overnight or at the weekend with 4+ files, so something "
                         "keeps the engine busy with nobody using it (usually a session left open on a misbehaving sheet).")
        out.append(_ev(
            "Request volume", f"Engine request volume {ratio:.0f}x normal for {days} day(s)", a, b, sev,
            f"{int(g['files'].sum()):,} audit log files (about 8 MB each) written from {a:%a %d %b %Y} to "
            f"{(b - pd.Timedelta(days=1)):%a %d %b %Y}; normal for that kind of day is about {base.loc[g.index].median():.0f}. "
            f"Peak {int(g['files'].max())} on {g['files'].idxmax():%a %d %b}." + extra,
            metric=f"{ratio:.0f}x", source="Audit file counts", key="volume"))
    return out


def detect_audit_sample(sample, share=70):
    out = []
    if sample is None or sample.empty:
        return out
    for _, r in sample[sample["share_pct"] >= share].iterrows():
        sev = "High" if r["share_pct"] >= 90 and r["files"] >= 100 else "Medium"
        out.append(_ev(
            "Request storm", f"One session filled {r['share_pct']}% of the engine audit log: {r['app']} ({r['user']})",
            r["ts"], r["ts"] + pd.Timedelta(minutes=10), sev,
            f"In the file sampled at {r['sampled']} on {r['day']:%a %d %b}, {r['share_pct']}% of all engine requests came "
            f"from {r['user']} on {r['app']}. {r['files']} audit files were written that day. One file per day was "
            "sampled, so this is a snapshot.",
            app=r["app"], user=r["user"], metric=f"{r['share_pct']}%", source="Audit daily sample",
            key=f"{r['app']}|{r['user']}"))
    return out


def detect_cpu(d, thr=80):
    out = []
    rp = d.get("repo_perf")
    if rp is not None and len(rp):
        for host, g in rp.groupby("Hostname"):
            g = g.sort_values("ts")
            hot = g["machine_cpu"] >= thr
            for _, gg in g[hot].groupby((~hot).cumsum()[hot]):
                if len(gg) < 2:
                    continue
                out.append(_ev("Server CPU", f"Server CPU at or above {thr}% ({host})", gg["ts"].min(),
                               gg["ts"].max() + pd.Timedelta(minutes=5), "High" if len(gg) >= 4 else "Medium",
                               f"{len(gg)} consecutive 5-minute samples at or above {thr}% (average "
                               f"{gg['machine_cpu'].mean():.0f}%, peak {gg['machine_cpu'].max():.0f}%). This is the whole "
                               "machine, from the Repository performance log.", metric=f"{gg['machine_cpu'].max():.0f}%",
                               source="Repository performance", key=host))
    P = d.get("performance")
    if P is not None and len(P):
        hot = P["CPULoad"] >= thr
        for _, gg in P[hot].groupby((~hot).cumsum()[hot]):
            if len(gg) < 2:
                continue
            out.append(_ev("Engine CPU", f"Engine CPU at or above {thr}%", gg["ts"].min(),
                           gg["ts"].max() + pd.Timedelta(minutes=5), "High" if len(gg) >= 4 else "Medium",
                           f"{len(gg)} consecutive samples at or above {thr}% (average {gg['CPULoad'].mean():.0f}%, "
                           f"peak {gg['CPULoad'].max():.0f}%), from the Engine performance log.",
                           metric=f"{gg['CPULoad'].max():.0f}%", source="Engine performance"))
    return out


def _cluster_messages(Y, mask, gap_min, category, title_fn, sev_fn, detail_fn, source, key=""):
    out = []
    w = Y[mask]
    if w.empty:
        return out
    for _, g in w.groupby(_groups(w["ts"], pd.Timedelta(minutes=gap_min))):
        out.append(_ev(category, title_fn(g), g["ts"].min(), g["ts"].max(), sev_fn(g), detail_fn(g),
                       metric=f"{len(g)}", source=source, key=key))
    return out


def detect_engine_system(d, names: dict):
    Y = d.get("system")
    out = []
    if Y is None or Y.empty:
        return out
    out += _cluster_messages(
        Y, Y["cat"].str.contains("WorkingSet", regex=False), 30, "Memory",
        lambda g: f"Engine memory beyond its limit ({len(g)} warnings)",
        lambda g: "High" if g["cat"].str.contains("CRITICALLY").any() else "Medium",
        lambda g: f"{len(g)} working-set warnings between {g['ts'].min():%d %b %H:%M} and {g['ts'].max():%H:%M}. "
                  "Above its limits the engine throws away cached results and may unload apps, which then have to be "
                  "loaded from disk again.", "Engine system")
    out += _cluster_messages(
        Y, Y["Message"].str.contains("Average CPU usage high", regex=False), 30, "Engine CPU",
        lambda g: f"Engine health check: CPU high ({len(g)} warnings)", lambda g: "Medium",
        lambda g: f"The engine's own health check reported sustained high CPU {len(g)} times between "
                  f"{g['ts'].min():%d %b %H:%M} and {g['ts'].max():%H:%M}.", "Engine system", key="healthcpu")
    out += _cluster_messages(
        Y, Y["Message"].str.contains("Low on RAM", regex=False), 30, "Memory",
        lambda g: f"Engine low on RAM ({len(g)} warnings)", lambda g: "High",
        lambda g: f"'Low on RAM' reported {len(g)} times.", "Engine system", key="lowram")
    # suspend churn: apps refreshed for every open session after each change
    s = Y[Y["Message"].str.contains("Queuing suspend", regex=False)].dropna(subset=["doc"])
    if len(s):
        s = s.assign(hr=s["ts"].dt.floor("60min"))
        ph = s.groupby(["doc", "hr"]).size().rename("n").reset_index()
        hot = ph[ph["n"] >= 200]
        for doc, g in hot.groupby("doc"):
            g = g.sort_values("hr")
            for _, gg in g.groupby(_groups(g["hr"], pd.Timedelta(hours=1))):
                name = names.get(doc, doc[:8])
                out.append(_ev("App refresh churn", f"{name}: {int(gg['n'].sum()):,} session refreshes",
                               gg["hr"].min(), gg["hr"].max() + pd.Timedelta(hours=1), "Medium",
                               f"Every time {name} changes (usually a reload saving it) each open session on it is "
                               f"suspended and refreshed. Peak {int(gg['n'].max())} an hour. Frequent reloads of an app "
                               "many people keep open (wallboards) multiply engine work.",
                               app=name, metric=f"{int(gg['n'].max())}/h", source="Engine system", key=doc))
    return out


def detect_restarts(d):
    """Engine restarts from the restart signature (qlik_restart): users and CPU to zero, memory falling and building up
    again, a full cache straight after, a data gap before, a new engine process. Two or more signals = an event."""
    import qlik_restart as qrs
    out = []
    for _, s in qrs.restarts(qrs.find(d.get("performance"))).iterrows():
        lost = f"{s['users_lost']:.0f} users lost" if pd.notna(s["users_lost"]) else "users not logged"
        host = f" ({s['host']})" if s["host"] else ""
        detail = (f"The engine went down and came back between {s['start']:%a %d %b %H:%M:%S} and {s['end']:%H:%M:%S}"
                  f"{host}: {s['strength'].lower()} restart signature, {s['n']} of {len(qrs.SIGNALS)} signals. "
                  + " ".join(t.rstrip(".") + "." for t in s["texts"]) + f" Recovery: {qrs.recovery_text(s)}. "
                  "The performance log shows that it restarted, not why: see Restart history for the possible causes "
                  "and what to check.")
        out.append(_ev("Restart", f"Engine restart: {lost}", s["start"], s["end"], "High", detail,
                       metric=lost, source="Engine performance", key=f"{s['host']}|{s['start']:%Y%m%d%H%M}"))
    return out


def reload_concurrency(te: pd.DataFrame, freq="1min") -> pd.Series:
    ex = te[te["Status"] != "Skipped"] if te is not None and len(te) else None
    if ex is None or ex.empty:
        return pd.Series(dtype=float)
    ev = pd.concat([pd.Series(1, index=ex["start"]), pd.Series(-1, index=ex["stop"])]).sort_index()
    running = ev.groupby(level=0).sum().cumsum()
    grid = pd.date_range(ex["start"].min().floor(freq), ex["stop"].max().ceil(freq), freq=freq)
    return running.reindex(running.index.union(grid)).ffill().reindex(grid).fillna(0).clip(lower=0)


def task_table(te: pd.DataFrame) -> pd.DataFrame:
    if te is None or te.empty:
        return pd.DataFrame()
    span_h = max((te["stop"].max() - te["start"].min()).total_seconds() / 3600, 1 / 60)
    g = te.groupby("TaskName")
    t = pd.DataFrame({
        "app": g["AppName"].first(),
        "runs": g["Status"].apply(lambda s: (s != "Skipped").sum()),
        "ok": g["Status"].apply(lambda s: (s == "FinishedSuccess").sum()),
        "failed": g["Status"].apply(lambda s: s.isin(["Error", "Aborted", "FinishedFail"]).sum()),
        "skipped": g["Status"].apply(lambda s: (s == "Skipped").sum()),
        "median_s": g["dur_s"].median(), "max_s": g["dur_s"].max(),
        "busy_h": g["dur_s"].sum() / 3600,
    })
    t["runs_per_h"] = t["runs"] / span_h
    t["busy_pct"] = t["busy_h"] / span_h * 100
    return t.sort_values("busy_h", ascending=False).round(1).reset_index()


def detect_reloads(d, conc_thr=10):
    te = d.get("task_exec")
    out = []
    if te is not None and len(te):
        bad = te[te["Status"].isin(["Error", "Aborted", "FinishedFail"])].sort_values("start")
        for task, g in bad.groupby("TaskName"):
            for _, gg in g.groupby(_groups(g["start"], pd.Timedelta(minutes=60))):
                reasons = ", ".join(sorted(set(gg["Status"])))
                why = gg["FailureReason"].dropna().astype(str) if "FailureReason" in gg else pd.Series(dtype=str)
                why = why[why.str.strip().ne("")]
                out.append(_ev("Reload failure", f"{task}: {len(gg)} failed run(s)", gg["start"].min(), gg["stop"].max(),
                               "High" if len(gg) >= 3 else "Medium",
                               f"Status {reasons}." + (f" Reason: {why.iloc[0][:200]}" if len(why) else ""),
                               app=gg["AppName"].iloc[0], metric=str(len(gg)), source="Scheduler task runs", key=task))
        tt = task_table(te)
        span = (te["start"].min(), te["stop"].max())
        for _, r in tt[(tt["runs_per_h"] >= 20) & (tt["busy_pct"] >= 5)].iterrows():
            every = 60 / r["runs_per_h"]
            out.append(_ev("Reload load", f"{r['TaskName']} reloads every {every:.0f} min", span[0], span[1],
                           "Medium" if r["busy_pct"] >= 10 else "Low",
                           f"{int(r['runs'])} runs ({r['runs_per_h']:.0f} an hour), median {r['median_s']:.0f}s, "
                           f"longest {r['max_s']:.0f}s. Running {r['busy_pct']:.0f}% of the time. Each run opens, reloads "
                           "and saves the app, and every open session on it is refreshed. Check whether the business "
                           "really needs it this often.", app=r["app"], metric=f"{r['runs_per_h']:.0f}/h",
                           source="Scheduler task runs", key=r["TaskName"]))
        for _, r in tt[tt["skipped"] >= 50].iterrows():
            out.append(_ev("Scheduler housekeeping", f"{r['TaskName']} skipped {int(r['skipped'])} times", span[0], span[1],
                           "Low", "The trigger keeps firing but the task never runs (preconditions not met). Cheap, "
                           "but it adds noise; disable the trigger or fix the dependency.", app=r["app"],
                           metric=str(int(r["skipped"])), source="Scheduler task runs", key=r["TaskName"]))
        ex = te[te["Status"] != "Skipped"].copy()
        ex["med"] = ex.groupby("TaskName")["dur_s"].transform("median")
        ex["n"] = ex.groupby("TaskName")["dur_s"].transform("size")
        long = ex[(ex["dur_s"] >= np.maximum(600, 5 * ex["med"])) & (ex["n"] >= 3)]
        for (task, day), g in long.groupby(["TaskName", long["start"].dt.date]):
            out.append(_ev("Slow reload", f"{task}: {len(g)} unusually long run(s)", g["start"].min(), g["stop"].max(), "Low",
                           f"Longest {g['dur_s'].max() / 60:.1f} min against a usual {g['med'].iloc[0]:.0f}s. A slow run "
                           "overlaps the next trigger and the scheduler refuses it.", app=g["AppName"].iloc[0],
                           metric=f"{g['dur_s'].max() / 60:.0f} min", source="Scheduler task runs", key=task))
        conc = reload_concurrency(te)
        hot = conc[conc >= conc_thr]
        if len(hot):
            for _, g in hot.groupby(_groups(hot.index.to_series(), pd.Timedelta(minutes=5))):
                a, b = g.index.min(), g.index.max() + pd.Timedelta(minutes=1)
                names_ = ex[(ex["start"] < b) & (ex["stop"] > a)]["TaskName"].value_counts().head(5).index.tolist()
                out.append(_ev("Reload pile-up", f"{int(g.max())} reloads running at once", a, b,
                               "High" if g.max() >= 2 * conc_thr else "Medium",
                               f"Up to {int(g.max())} reloads ran together for {_dur(a, b)}. Included: " + "; ".join(names_) + ".",
                               metric=str(int(g.max())), source="Scheduler task runs", key="conc"))
    svc = d.get("service")
    if svc is not None and len(svc) and "Service" in svc:
        sc = svc[svc["Service"].eq("Scheduler")]
        coll = sc[sc["Message"].astype(str).str.contains("Found active session|already exist", regex=True)]
        for (task, day), g in coll.groupby(["task", coll["ts"].dt.date]):
            out.append(_ev("Reload overlap", f"{task}: fired {len(g)} time(s) while the last run was still going",
                           g["ts"].min(), g["ts"].max(), "Medium" if len(g) >= 10 else "Low",
                           "The trigger came round before the previous run finished, so the scheduler refused it. Either "
                           "the reload has slowed down or the trigger is too frequent.", app=g["app"].iloc[0],
                           metric=str(len(g)), source="Scheduler service", key=task))
    return out


def detect_proxy(d, per_hour=600):
    out = []
    pa = d.get("proxy_audit")
    if pa is None or pa.empty:
        return out
    bad = pa[pa["Message"].astype(str).str.startswith("Bad request, malformed")]
    if bad.empty:
        return out
    ph = bad.set_index("ts").resample("60min").size()
    hot = ph[ph >= per_hour]
    for _, g in hot.groupby(_groups(hot.index.to_series(), pd.Timedelta(hours=2))):
        a, b = g.index.min(), g.index.max() + pd.Timedelta(hours=1)
        out.append(_ev("Proxy noise", f"Malformed requests hitting the proxy (~{g.mean():.0f} an hour)", a, b, "Low",
                       f"{int(g.sum()):,} requests with a malformed first line ('GET /' with no HTTP version). A steady "
                       "once-a-second rate is usually a load balancer or monitoring health check set up wrong. Ask the "
                       "network team to fix the probe.", metric=f"{g.mean():.0f}/h", source="Proxy audit", key="malformed"))
    return out


def detect_reopens(d, min_total=300):
    out = []
    a = d.get("activity")
    if a is None or a.empty:
        return out
    o = a[a["Service"].eq("Repository") & a["Command"].eq("Open app")]
    if o.empty:
        return out
    for app, g in o.groupby("app"):
        if len(g) < min_total:
            continue
        users = g["UserId"].value_counts()
        out.append(_ev("App refresh churn", f"{app} re-opened {len(g):,} times by {len(users)} users", g["ts"].min(),
                       g["ts"].max(), "Low",
                       "Repeated opens of the same app, including overnight, usually mean wallboards or tabs left open "
                       "reconnecting after every reload. Top: " + ", ".join(f"{u} {n:,}" for u, n in users.head(5).items()) + ".",
                       app=app, metric=f"{len(g):,}", source="Repository audit", key=app))
    return out


def app_names(d) -> dict:
    names = {}
    te = d.get("task_exec")
    if te is not None and len(te):
        names.update(te.dropna(subset=["AppId"]).drop_duplicates("AppId").set_index("AppId")["AppName"].to_dict())
    S = d.get("session")
    if S is not None and len(S) and "AppId" in S:
        names.update(S.drop_duplicates("AppId").set_index("AppId")["app"].to_dict())
    return {k: v for k, v in names.items() if k and v}


def detect_all(d: dict, cpu_thr=80, storm_per_min=600, conc_thr=10) -> pd.DataFrame:
    names = app_names(d)
    ev = []
    for fn in (lambda: detect_storms(d, storm_per_min), lambda: detect_audit_volume(d.get("audit_counts")),
               lambda: detect_audit_sample(d.get("audit_sample")), lambda: detect_cpu(d, cpu_thr),
               lambda: detect_engine_system(d, names), lambda: detect_restarts(d),
               lambda: detect_reloads(d, conc_thr), lambda: detect_proxy(d), lambda: detect_reopens(d)):
        try:
            ev += fn()
        except Exception as exc:  # noqa: BLE001 - one bad detector shouldn't hide the others
            ev.append(_ev("Analyzer", "A detector failed on this data", pd.Timestamp.now().floor("D"), None, "Low",
                          f"{type(exc).__name__}: {exc}", source="analyzer", key=str(exc)[:40]))
    cols = ["id", "start", "end", "severity", "category", "title", "app", "user", "metric", "detail", "source"]
    df = pd.DataFrame(ev, columns=cols)
    if df.empty:
        return df
    df = df.drop_duplicates("id")
    df["_s"] = df["severity"].map({"High": 0, "Medium": 1, "Low": 2})
    return df.sort_values(["_s", "start"], ascending=[True, False]).drop(columns="_s").reset_index(drop=True)


def cpu_drivers(d) -> pd.DataFrame:
    """How strongly machine CPU moves with sessions, reload activity and individual tasks (correlation)."""
    rp, px, te = d.get("repo_perf"), d.get("proxy_perf"), d.get("task_exec")
    if rp is None or rp.empty:
        return pd.DataFrame()
    m = rp[["ts", "machine_cpu"]].dropna().sort_values("ts")
    rows = []
    if px is not None and len(px):
        mm = pd.merge_asof(m, px[["ts", "ActiveSessions"]].sort_values("ts"), on="ts", direction="nearest",
                           tolerance=pd.Timedelta("3min"))
        rows.append(("Users connected (proxy sessions)", mm["machine_cpu"].corr(mm["ActiveSessions"])))
    if te is not None and len(te):
        ex = te[te["Status"] != "Skipped"]

        def busy(mask=None):
            e = ex if mask is None else ex[mask]
            vals = []
            for t in m["ts"]:
                lo = t - pd.Timedelta(minutes=5)
                vals.append((e["stop"].clip(upper=t) - e["start"].clip(lower=lo)).dt.total_seconds().clip(lower=0).sum())
            return pd.Series(vals, index=m.index)

        rows.append(("All reloads (seconds running in previous 5 min)", m["machine_cpu"].corr(busy())))
        for task in task_table(te).head(8)["TaskName"]:
            rows.append((f"Reload: {task}", m["machine_cpu"].corr(busy(ex["TaskName"].eq(task)))))
    out = pd.DataFrame(rows, columns=["Driver", "correlation"]).dropna()
    return out.sort_values("correlation", ascending=False).round(2).reset_index(drop=True)


# ----------------------------------------------------------------------------------------------
# ArchivedLogs folder scanning
# ----------------------------------------------------------------------------------------------
DEFAULT_ARCHIVE_ROOT = site_config.ARCHIVE_ROOT          # set per site in site_config.py (or QLIK_ARCHIVE_ROOT)

# log types (from the file name) that this tool uses, in the order they're listed in the UI
USED_TYPES = [
    "Performance_Engine", "Session_Engine", "System_Engine", "AuditActivity_Engine", "Service_Engine",
    "Performance_Repository", "AuditActivity_Repository", "Performance_Proxy", "Audit_Proxy",
    "TaskExecution_Scheduler", "Service_Scheduler", "System_Scheduler", "System_Proxy",
]
_ARCH_RE = re.compile(r"^[^_]+_(?P<t>.+?)(?:_\d{8})?_\d{4}-\d{2}-\d{2}T[\d.]+Z?\.(?:log|txt)$", re.I)
_LIVE_RE = re.compile(r"^[^_]+_(?P<t>[A-Za-z]+_[A-Za-z]+)\.(?:log|txt)$", re.I)


def log_type(name: str) -> str | None:
    m = _ARCH_RE.match(name) or _LIVE_RE.match(name)
    return m.group("t") if m else None


def scan_archive(root: str) -> pd.DataFrame:
    """Every log file under root with its type, folder, modified time and size. Uses the directory listing only."""
    rows = []
    for dirpath, _dirs, _files in os.walk(root):
        try:
            entries = list(os.scandir(dirpath))
        except OSError:
            continue
        is_script = os.path.basename(dirpath).lower() == "script"
        for e in entries:
            if not e.is_file():
                continue
            t = "Script" if is_script and e.name.lower().endswith(".log") else log_type(e.name)
            if not t:
                continue
            try:
                stt = e.stat()
            except OSError:
                continue
            rows.append({"path": e.path, "name": e.name, "folder": os.path.relpath(dirpath, root), "type": t,
                         "mtime": pd.Timestamp.fromtimestamp(stt.st_mtime),  # this PC's local time, as Explorer shows
                         "size_mb": stt.st_size / 1_048_576})
    return pd.DataFrame(rows, columns=["path", "name", "folder", "type", "mtime", "size_mb"])


def pick_latest(files: pd.DataFrame, days: float = 2, mb_per_type: float = 64, types=None,
                now: pd.Timestamp | None = None) -> pd.DataFrame:
    """Newest files of each used type: everything modified in the last `days`, newest first, until `mb_per_type`
    is used up. The newest file of each type is always included if it is less than 45 days old."""
    if files is None or files.empty:
        return files
    types = types or USED_TYPES
    now = now or files["mtime"].max()
    out = []
    for t, g in files[files["type"].isin(types)].groupby("type"):
        g = g.sort_values("mtime", ascending=False)
        if now - g["mtime"].iloc[0] > pd.Timedelta(days=45):
            continue
        recent = g[g["mtime"] >= now - pd.Timedelta(days=days)]
        if recent.empty:
            recent = g.head(1)
        keep = recent[recent["size_mb"].cumsum() - recent["size_mb"] < mb_per_type]  # always at least the newest
        out.append(keep)
    return pd.concat(out, ignore_index=True) if out else files.iloc[0:0]


def audit_counts_from_listing(files: pd.DataFrame, log="AuditActivity_Engine") -> pd.DataFrame:
    """Same as the 'audit files per hour' PowerShell command, built from the folder listing."""
    a = files[files["type"] == log] if files is not None and len(files) else pd.DataFrame()
    if a.empty:
        return pd.DataFrame()
    c = a.groupby(a["mtime"].dt.floor("60min")).size().rename("files").reset_index().rename(columns={"mtime": "ts"})
    c["hourly"] = True
    return c


def audit_daily_sample(files: pd.DataFrame, days: int = 90, progress=None, log="AuditActivity_Engine") -> pd.DataFrame:
    """Open one audit file per day (the middle one) and report which app/user filled it. Reads ~8 MB per day."""
    a = files[files["type"] == log] if files is not None and len(files) else pd.DataFrame()
    if a.empty:
        return pd.DataFrame()
    a = a[a["mtime"] >= a["mtime"].max().normalize() - pd.Timedelta(days=days - 1)]
    rows = []
    groups = list(a.groupby(a["mtime"].dt.normalize()))
    for i, (day, g) in enumerate(groups):
        g = g.sort_values("mtime")
        f = g.iloc[len(g) // 2]
        try:
            df = pd.read_csv(f["path"], sep="\t", dtype=str, quoting=3, on_bad_lines="skip", keep_default_na=False,
                             usecols=lambda c: c in ("ObjectName", "UserId"), encoding="utf-8-sig",
                             encoding_errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if progress:
            progress((i + 1) / len(groups), f"{day:%d %b}")
        if df.empty:
            continue
        top = df.groupby(["ObjectName", "UserId"]).size().sort_values(ascending=False)
        (obj, user), n = top.index[0], int(top.iloc[0])
        rows.append({"day": day, "files": len(g), "sampled": f["mtime"].strftime("%H:%M"), "app": obj.split("|")[0],
                     "user": user, "share_pct": round(100 * n / len(df))})
    df = pd.DataFrame(rows)
    if len(df):
        df["ts"] = df["day"] + pd.to_timedelta(df["sampled"] + ":00")
    return df


# ----------------------------------------------------------------------------------------------
# Issues reported by people (logged by hand in the app)
# ----------------------------------------------------------------------------------------------
REPORTED_KEY = "_reported"


def add_reported(store: dict, title: str, start, end, severity: str, app: str = "", user: str = "",
                 detail: str = "") -> str:
    start, end = pd.Timestamp(start), pd.Timestamp(end)
    eid = "r" + hashlib.sha1(f"{title}|{start:%Y%m%d%H%M}|{pd.Timestamp.now()}".encode()).hexdigest()[:9]
    store.setdefault(REPORTED_KEY, []).append({
        "id": eid, "start": str(start), "end": str(max(end, start)), "severity": severity, "title": title,
        "app": app, "user": user, "detail": detail, "logged": str(pd.Timestamp.now().floor("s"))})
    return eid


def remove_reported(store: dict, eid: str) -> None:
    store[REPORTED_KEY] = [r for r in store.get(REPORTED_KEY, []) if r.get("id") != eid]


def reported_events(store: dict) -> pd.DataFrame:
    rows = []
    for r in store.get(REPORTED_KEY, []):
        rows.append({"id": r["id"], "start": pd.Timestamp(r["start"]), "end": pd.Timestamp(r["end"]),
                     "severity": r.get("severity", "Medium"), "category": "Reported issue", "title": r["title"],
                     "app": r.get("app", ""), "user": r.get("user", ""), "metric": "reported",
                     "detail": r.get("detail", "") or "Logged by hand.", "source": f"Reported (logged {r.get('logged', '')})"})
    return pd.DataFrame(rows)


def overlapping(events: pd.DataFrame, start, end, pad_min: int = 30, exclude_id: str = "") -> pd.DataFrame:
    """Events that overlap [start - pad, end + pad]: what else was going on at the time."""
    if events is None or events.empty:
        return pd.DataFrame()
    a, b = pd.Timestamp(start) - pd.Timedelta(minutes=pad_min), pd.Timestamp(end) + pd.Timedelta(minutes=pad_min)
    m = (events["end"] >= a) & (events["start"] <= b) & (events["id"] != exclude_id)
    # very long background events (e.g. 34-day volume runs) are context, list them last
    out = events[m].copy()
    out["_long"] = (out["end"] - out["start"]) > pd.Timedelta(days=1)
    return out.sort_values(["_long", "start"]).drop(columns="_long")


# ----------------------------------------------------------------------------------------------
# Fault logging (the form is set in site_config.py)
# ----------------------------------------------------------------------------------------------
FAULT_URL = os.environ.get("QLIK_FAULT_URL", site_config.FAULT_URL)


def fault_summary(ev, related: pd.DataFrame | None = None, version: str = "") -> str:
    """Plain-text description to paste into the fault form."""
    lines = [
        f"{site_config.SERVER_LABEL}: {ev['title']}",
        "",
        f"When: {pd.Timestamp(ev['start']):%a %d %b %Y %H:%M} to {pd.Timestamp(ev['end']):%H:%M}"
        + ("" if pd.Timestamp(ev['end']).date() == pd.Timestamp(ev['start']).date() else f" ({pd.Timestamp(ev['end']):%d %b})"),
        f"Severity (tool): {ev['severity']} | Category: {ev['category']}",
    ]
    if ev.get("app"):
        lines.append(f"App: {ev['app']}")
    if ev.get("user"):
        lines.append(f"User: {ev['user']}")
    lines += ["", "What was seen:", str(ev["detail"])]
    if ev.get("notes"):
        lines += ["", "Notes:", str(ev["notes"])]
    if related is not None and len(related):
        lines += ["", "Other events at the same time (±30 min):"]
        for _, r in related.head(8).iterrows():
            lines.append(f"- {r['start']:%H:%M} {r['category']}: {r['title']}")
    lines += ["", f"Source: Qlik Server Event Manager{' v' + version if version else ''} (event id {ev.name if hasattr(ev, 'name') else ''})"]
    return "\n".join(lines)


# ----------------------------------------------------------------------------------------------
# CPU spikes lined up against events, reloads and users
# ----------------------------------------------------------------------------------------------
def cpu_samples(d: dict) -> pd.DataFrame:
    """All CPU samples in one table: whole-server (Repository log) and Qlik engine (Performance_Engine log)."""
    parts = []
    rp, pf = d.get("repo_perf"), d.get("performance")
    if rp is not None and len(rp):
        parts.append(rp[["ts", "machine_cpu"]].rename(columns={"machine_cpu": "cpu"}).assign(source="Server"))
    if pf is not None and len(pf):
        parts.append(pf[["ts", "CPULoad"]].rename(columns={"CPULoad": "cpu"}).assign(source="Engine"))
    if not parts:
        return pd.DataFrame(columns=["ts", "cpu", "source"])
    return pd.concat(parts, ignore_index=True).dropna().sort_values("ts").reset_index(drop=True)


def cpu_spikes(d: dict, warn_thr: float = 60, events: pd.DataFrame | None = None, pad_min: int = 10,
               top_if_none: int = 5) -> pd.DataFrame:
    """Stretches where CPU was at or above warn_thr (per source), with what was going on at the time:
    events overlapping (±pad_min), reloads running, the busiest reload tasks and users connected.
    If nothing reaches the threshold, the highest few samples are listed instead so there is always something to check."""
    s = cpu_samples(d)
    if s.empty:
        return pd.DataFrame()
    runs = []
    for src, g in s.groupby("source"):
        g = g.sort_values("ts").reset_index(drop=True)
        hot = g["cpu"] >= warn_thr
        if hot.any():
            for _, gg in g[hot].groupby((~hot).cumsum()[hot]):
                runs.append((src, gg))
    if not runs:
        for _, r in s.nlargest(top_if_none, "cpu").iterrows():
            runs.append((r["source"], s.loc[[r.name]]))
    te, px, pf = d.get("task_exec"), d.get("proxy_perf"), d.get("performance")
    ex = te[te["Status"] != "Skipped"] if te is not None and len(te) else None
    conc = reload_concurrency(te) if ex is not None and len(ex) else pd.Series(dtype=float)
    rows = []
    for src, gg in runs:
        a, b = gg["ts"].min(), gg["ts"].max()
        pk = gg.loc[gg["cpu"].idxmax()]
        lo, hi = a - pd.Timedelta(minutes=pad_min), b + pd.Timedelta(minutes=pad_min)
        row = {"source": src, "start": a, "end": b, "peak_cpu": pk["cpu"], "peak_at": pk["ts"], "samples": len(gg)}
        if events is not None and len(events):
            ov = events[(events["end"] >= lo) & (events["start"] <= hi)
                        & ((events["end"] - events["start"]) <= pd.Timedelta(days=1))]
            row["events"] = len(ov)
            row["event_titles"] = "; ".join(ov.sort_values("start")["title"].head(4)) + (" …" if len(ov) > 4 else "")
        if len(conc):
            w = conc[(conc.index >= lo) & (conc.index <= hi)]
            row["reloads_running"] = int(w.max()) if len(w) else 0
            busy = ex[(ex["start"] <= hi) & (ex["stop"] >= lo)]
            if len(busy):
                ov_s = (busy["stop"].clip(upper=hi) - busy["start"].clip(lower=lo)).dt.total_seconds()
                row["busiest_reloads"] = "; ".join(ov_s.groupby(busy["TaskName"]).sum().sort_values(ascending=False)
                                                   .head(3).index)
        if px is not None and len(px):
            near = px.iloc[(px["ts"] - pk["ts"]).abs().argsort()[:1]]
            if len(near) and abs(near["ts"].iloc[0] - pk["ts"]) <= pd.Timedelta(minutes=6):
                row["users"] = int(near["ActiveSessions"].iloc[0])
        if "users" not in row and pf is not None and len(pf):
            near = pf.iloc[(pf["ts"] - pk["ts"]).abs().argsort()[:1]]
            if len(near) and abs(near["ts"].iloc[0] - pk["ts"]) <= pd.Timedelta(minutes=6):
                row["users"] = int(near["ActiveUsers"].iloc[0])
        rows.append(row)
    out = pd.DataFrame(rows)
    return out.sort_values("peak_cpu", ascending=False).reset_index(drop=True)


# ----------------------------------------------------------------------------------------------
# Root cause / failure / impact (a lead to follow, not a verdict)
# ----------------------------------------------------------------------------------------------
SYMPTOMS = {"Server CPU", "Engine CPU", "Memory", "Restart", "Reported issue", "Login / proxy"}
CAUSE_ORDER = ["Request storm", "Reload pile-up", "Reload overlap", "Reload load", "Slow reload", "Reload time-out",
               "App refresh churn", "Request volume", "Reload failing", "Reload failure", "Proxy noise",
               "Scheduler housekeeping"]
CAUSE_WHY = {
    "Request storm": "one session making a flood of engine requests keeps the engine busy",
    "Reload pile-up": "many reloads running together compete for the same CPU and memory",
    "Reload overlap": "reload triggers firing before the last run finished mean reloads stack up",
    "Reload load": "a task reloading this often keeps the engine and every open session on that app busy",
    "Slow reload": "a reload running far longer than usual holds CPU and blocks the next trigger",
    "App refresh churn": "every reload refreshes each open session on the app, multiplying engine work",
    "Request volume": "a day with far more engine requests than usual",
    "Reload failure": "failed reloads retry and add load",
    "Reload failing": "the app's data stops updating while every run keeps failing",
    "Reload time-out": "runs cut off at the same length point to a time-out or a source that doesn't answer",
    "Login / proxy": "users can't log in or reach the hub while the proxy has problems",
    "Proxy noise": "constant malformed requests add load at the proxy",
    "Scheduler housekeeping": "triggers firing for tasks that never run add noise",
}


def _cap(t: str) -> str:
    return t[:1].upper() + t[1:]


def _num_users(d: dict, a, b) -> tuple[int, str]:
    px, pf = d.get("proxy_perf"), d.get("performance")
    for df, col, label in ((px, "ActiveSessions", "users connected"), (pf, "ActiveUsers", "active users")):
        if df is not None and len(df):
            w = df[(df["ts"] >= a - pd.Timedelta(minutes=6)) & (df["ts"] <= b + pd.Timedelta(minutes=6))]
            if len(w):
                return int(w[col].max()), label
    return 0, ""


def diagnose(ev, events: pd.DataFrame, d: dict | None = None, pad_min: int = 30) -> dict:
    """Three plain-language boxes for an event: the most likely root cause among what else was happening, the failure
    (what the event itself is) and the impact (people, apps and reloads at the time). Always a lead, never proof."""
    d = d or {}
    a, b = pd.Timestamp(ev["start"]), pd.Timestamp(ev["end"])
    ov = overlapping(events, a - pd.Timedelta(minutes=pad_min), b, pad_min=0, exclude_id=ev["id"]) if events is not None else pd.DataFrame()
    ov = ov[(ov["end"] - ov["start"]) <= pd.Timedelta(days=1)] if len(ov) else ov
    cat = ev["category"]
    cause = None
    if cat in SYMPTOMS and len(ov):
        cand = ov[ov["category"].isin(CAUSE_ORDER)].copy()
        if len(cand):
            cand["_o"] = cand["category"].map({c: i for i, c in enumerate(CAUSE_ORDER)})
            cause = cand.sort_values(["_o", "start"]).iloc[0]
    if cat not in SYMPTOMS:
        root = {"head": ev["title"], "text": f"{_cap(CAUSE_WHY.get(cat, 'this is the thing to check first'))}. "
                f"Started {pd.Timestamp(ev['start']):%a %d %b %H:%M}.", "colour": "#5b2ea6"}
    elif cause is not None:
        root = {"head": cause["title"], "text": f"{_cap(CAUSE_WHY.get(cause['category'], 'overlaps in time'))}. "
                f"Seen {cause['start']:%H:%M}–{cause['end']:%H:%M}.",
                "colour": "#5b2ea6"}
    else:
        root = {"head": "No single lead in the logs", "text": "Nothing else detected overlaps this. Check what runs on the "
                "server at this time outside Qlik (security software, agents, backups) and compare with Server CPU "
                "against Engine CPU.", "colour": "#898781"}
    cpu_ov = ov[ov["category"].isin(["Server CPU", "Engine CPU", "Memory"])] if len(ov) and cat not in SYMPTOMS else pd.DataFrame()
    if cat in SYMPTOMS:
        fail = {"head": ev["title"], "text": (ev["detail"] or "")[:170]}
    elif len(cpu_ov):
        r = cpu_ov.iloc[0]
        fail = {"head": r["title"], "text": f"{r['category']} {r['start']:%H:%M}–{r['end']:%H:%M} overlaps this."}
    else:
        fail = {"head": "No CPU or memory event overlaps", "text": "This may be a slow-burning load rather than a spike. "
                "Check Server CPU for the same hours.", "colour": "#898781"}
    users, ulabel = _num_users(d, a, b)
    apps = sorted({x for x in ([ev["app"]] + (ov["app"].tolist() if len(ov) else [])) if x})
    te = d.get("task_exec")
    run = 0
    if te is not None and len(te):
        c = reload_concurrency(te)
        w = c[(c.index >= a - pd.Timedelta(minutes=5)) & (c.index <= b + pd.Timedelta(minutes=5))]
        run = int(w.max()) if len(w) else 0
    bits = []
    if users:
        bits.append(f"{users} {ulabel}")
    if apps:
        bits.append(f"{len(apps)} app(s): " + ", ".join(apps[:3]) + (" …" if len(apps) > 3 else ""))
    if run:
        bits.append(f"up to {run} reloads running")
    if len(ov):
        bits.append(f"{len(ov)} other event(s) nearby")
    impact = {"head": f"{users} users connected" if users else "Impact not measurable from these logs",
              "text": "; ".join(bits[1:] if users else bits) or "Load the Proxy and Scheduler logs to see who and what was affected."}
    return {"root": root, "failure": fail, "impact": impact}

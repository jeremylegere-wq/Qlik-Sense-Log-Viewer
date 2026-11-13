"""Reload failures: which reloads failed, why, and whether it keeps happening.

Three sources are joined:
  * the Scheduler's task runs (TaskExecution_Scheduler): every run with its status and duration;
  * the Scheduler's own trace (System_Scheduler): abort and error messages, matched to a run by its ExecutionId;
  * the reload script logs (ArchivedLogs\\Script\\<app id>.<start time>.<n>.log): the app's own log, whose last lines
    hold the real error (a missing file, a failed SQL statement, a time-out). Read with qlik_scriptlog, head and tail
    only.
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd

import qlik_events as qe

FAILED = ["Error", "Aborted", "FinishedFail"]
_NAME_TS = re.compile(r"^(?P<id>[0-9a-fA-F-]{36})\.(?P<ts>\d{8}T\d{6})")
_SCRIPT_LINE = re.compile(r"^(\d{8}T\d{6}\S*)\s+(\d{4})\s+(.+)$")
_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
STATUS_WORD = {"failed": "Failed", "warn": "Finished with warnings", "ok": "Succeeded", "running": "Running",
               "incomplete": "Log ends early", "unknown": "Unknown"}


def script_files(listing: pd.DataFrame, days: int = 30) -> pd.DataFrame:
    """Reload script logs from an ArchivedLogs scan (type 'Script'), with app ID and start time from the name."""
    if listing is None or listing.empty or "type" not in listing:
        return pd.DataFrame(columns=["path", "name", "app_id", "start", "mtime", "size_mb"])
    s = listing[listing["type"].eq("Script")].copy()
    if s.empty:
        return pd.DataFrame(columns=["path", "name", "app_id", "start", "mtime", "size_mb"])
    m = s["name"].str.extract(_NAME_TS)
    s["app_id"] = m["id"].str.lower()
    s["start"] = pd.to_datetime(m["ts"], format="%Y%m%dT%H%M%S", errors="coerce")
    s = s.dropna(subset=["app_id"])
    s = s[s["mtime"] >= s["mtime"].max() - pd.Timedelta(days=days)]
    return s[["path", "name", "app_id", "start", "mtime", "size_mb"]].sort_values("start").reset_index(drop=True)


def read_script(path: str) -> dict:
    """Status, error and timing of one reload log (first 4 KB and last 8 KB only)."""
    from qlik_scriptlog import _tail, reload_summary
    r = reload_summary(path)
    last = ""
    try:
        for ln in _tail(path, 6000).splitlines():
            m = _SCRIPT_LINE.match(ln.strip())
            if m:
                last = f"line {int(m.group(2))}: {m.group(3).strip()[:160]}"
    except OSError:
        pass

    def ts(v):
        return pd.to_datetime(str(v)[:19], errors="coerce") if v else pd.NaT
    return {"status": r.status, "error": r.error or "", "started": ts(r.started), "finished": ts(r.finished),
            "duration_s": r.duration_s, "trigger": r.trigger, "last_line": last}


def script_runs(files: pd.DataFrame, reader=read_script) -> pd.DataFrame:
    rows = []
    for f in files.itertuples():
        try:
            info = reader(f.path)
        except Exception:  # noqa: BLE001
            info = {"status": "unknown", "error": "", "started": pd.NaT, "finished": pd.NaT, "duration_s": None,
                    "trigger": ""}
        st = info.get("started")
        rows.append({"app_id": f.app_id, "start": st if pd.notna(st) else f.start, "finished": info.get("finished"),
                     "duration_s": info.get("duration_s"), "status": info.get("status", "unknown"),
                     "error": info.get("error", ""), "trigger": info.get("trigger", ""),
                     "last_line": info.get("last_line", ""), "path": f.path, "file": f.name})
    cols = ["app_id", "start", "finished", "duration_s", "status", "error", "trigger", "last_line", "path", "file"]
    return pd.DataFrame(rows, columns=cols)


def signature(text: str) -> str:
    """An error message with the changing parts (IDs, numbers) taken out, so repeats group together."""
    t = _GUID.sub("<id>", str(text or ""))
    t = re.sub(r"\d+", "#", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:180]


def _sched_messages(sched: pd.DataFrame) -> pd.Series:
    """ExecutionId -> the distinct warning/error messages the Scheduler logged for that run."""
    if sched is None or sched.empty or "ExecutionId" not in sched:
        return pd.Series(dtype=str)
    s = sched[sched["Level"].isin(["WARN", "ERROR"]) & sched["ExecutionId"].astype(str).ne("")]
    if s.empty:
        return pd.Series(dtype=str)
    msg = s["Message"].astype(str).str.replace(r"(handle:?\s*)[0-9a-f-]{36}", r"\1…", regex=True)
    return msg.groupby(s["ExecutionId"]).agg(lambda m: "; ".join(dict.fromkeys(m))[:400])


def failures(te: pd.DataFrame | None, sched: pd.DataFrame | None, scripts: pd.DataFrame | None,
             names: dict | None = None) -> pd.DataFrame:
    """One row per failed reload, with the best explanation found. Columns: start, end, task, app, app_id, status,
    duration_s, error, why_source, signature, trigger, script_file."""
    names = {str(k).lower(): v for k, v in (names or {}).items()}
    rows = []
    sm = _sched_messages(sched)
    sc = scripts if scripts is not None and len(scripts) else pd.DataFrame(columns=["app_id", "start", "status", "error",
                                                                                    "file", "duration_s", "trigger", "last_line"])
    if "last_line" not in sc:
        sc = sc.assign(last_line="")
    used_scripts = set()
    if te is not None and len(te):
        bad = te[te["Status"].isin(FAILED)]
        for r in bad.itertuples():
            aid = str(getattr(r, "AppId", "") or "").lower()
            err, src, sfile = "", "", ""
            cand = sc[(sc["app_id"] == aid) & (sc["start"] >= r.start - pd.Timedelta(minutes=2))
                      & (sc["start"] <= r.start + pd.Timedelta(minutes=5))]
            if len(cand):
                c = cand.iloc[0]
                used_scripts.add(c["file"])
                sfile = c["file"]
                if c["error"]:
                    err, src = c["error"], "reload log"
                elif c["status"] in ("incomplete", "running") and c["last_line"]:
                    err, src = f"Cut off while running script {c['last_line']}", "reload log"
            fr = str(getattr(r, "FailureReason", "") or "")
            if not err and fr:
                err, src = fr, "task run"
            ex = str(getattr(r, "ExecutionId", "") or "")
            if not err and ex in sm.index:
                err, src = sm[ex], "scheduler"
            if not err and r.Status == "Error":
                near = bad[(bad["Status"] == "Error") & (bad["TaskName"] != r.TaskName)
                           & ((bad["start"] - r.start).abs() <= pd.Timedelta(minutes=2))]
                if len(near):
                    err = (f"The scheduler couldn't start it, and {near['TaskName'].nunique()} other task(s) failed the same way "
                           "within two minutes: points to a shared cause (engine or a service unavailable), not this app")
                    src = "pattern"
            if not err:
                err = {"Aborted": "Aborted (stopped before it finished; no reason logged)",
                       "Error": "The scheduler couldn't run it (no reason logged)",
                       "FinishedFail": "Finished with a failure (no reason logged)"}.get(r.Status, r.Status)
                src = "status only"
            rows.append({"start": r.start, "end": r.stop, "task": r.TaskName, "app": r.AppName or names.get(aid, ""),
                         "app_id": aid, "status": r.Status, "duration_s": r.dur_s, "error": err, "why_source": src,
                         "trigger": "task", "script_file": sfile})
    for c in sc[sc["status"].eq("failed") & ~sc["file"].isin(used_scripts)].itertuples():
        rows.append({"start": c.start, "end": c.start + pd.Timedelta(seconds=c.duration_s or 0), "task": "",
                     "app": names.get(c.app_id, ""), "app_id": c.app_id, "status": "Failed (reload log)",
                     "duration_s": c.duration_s, "error": c.error or "Failed (no error line found)",
                     "why_source": "reload log", "trigger": c.trigger or "", "script_file": c.file})
    out = pd.DataFrame(rows, columns=["start", "end", "task", "app", "app_id", "status", "duration_s", "error",
                                      "why_source", "trigger", "script_file"])
    if len(out):
        out["signature"] = out["error"].map(signature)
        out = out.sort_values("start", ascending=False).reset_index(drop=True)
    else:
        out["signature"] = pd.Series(dtype=str)
    return out


def recurring(f: pd.DataFrame) -> pd.DataFrame:
    """Failures grouped by error, most frequent first."""
    if f is None or f.empty:
        return pd.DataFrame(columns=["signature", "failures", "apps", "tasks", "first", "last", "example"])
    g = f.groupby("signature").agg(failures=("start", "size"), apps=("app", lambda s: ", ".join(sorted(set(filter(None, s))))[:200]),
                                   tasks=("task", lambda s: len(set(filter(None, s)))), first=("start", "min"),
                                   last=("start", "max"), example=("error", "first"))
    return g.sort_values(["failures", "last"], ascending=[False, False]).reset_index()


def task_health(te: pd.DataFrame | None) -> pd.DataFrame:
    """Per task: runs, failures, failure rate, last status, last success, and how many runs in a row have failed."""
    if te is None or te.empty:
        return pd.DataFrame()
    ex = te[te["Status"] != "Skipped"].sort_values("start")
    rows = []
    for task, g in ex.groupby("TaskName"):
        bad = g["Status"].isin(FAILED)
        streak = 0
        for b in bad.iloc[::-1]:
            if not b:
                break
            streak += 1
        streak_start = g["start"].iloc[-streak] if streak else pd.NaT
        ok = g[g["Status"].eq("FinishedSuccess")]
        ab = g[g["Status"].eq("Aborted")]["dur_s"].dropna()
        timeout = ""
        if len(ab) >= 2 and ab.median() >= 30 and (ab.max() - ab.min()) <= max(5, ab.median() * 0.05):
            timeout = f"~{ab.median():.0f}s"
        rows.append({"task": task, "app": g["AppName"].iloc[-1], "app_id": str(g["AppId"].iloc[-1] or "").lower()
                     if "AppId" in g else "", "runs": len(g), "failed": int(bad.sum()),
                     "fail_pct": 100 * bad.mean(), "last_status": g["Status"].iloc[-1], "last_run": g["start"].iloc[-1],
                     "last_success": ok["start"].max() if len(ok) else pd.NaT, "failing_streak": streak,
                     "streak_start": streak_start, "aborts_at": timeout})
    return pd.DataFrame(rows).sort_values(["failing_streak", "failed"], ascending=False).reset_index(drop=True)


def detect(te: pd.DataFrame | None, scripts: pd.DataFrame | None = None, names: dict | None = None) -> list:
    """Events for reloads that keep failing and for runs that are cut off at the same length every time."""
    out = []
    th = task_health(te)
    if len(th):
        for r in th[th["failing_streak"] >= 3].itertuples():
            since = (f"Every run since {r.last_success:%a %d %b %H:%M} has failed" if pd.notna(r.last_success)
                     else "No successful run in the loaded logs")
            out.append(qe._ev("Reload failing", f"{r.task}: last {r.failing_streak} runs failed",
                              r.streak_start, r.last_run, "High",
                              since + ". The data in this app is going stale. Open Reload failures for the error text.",
                              app=r.app, metric=str(r.failing_streak), source="Scheduler task runs",
                              key="streak:" + r.task))
        for r in th[th["aborts_at"].ne("")].itertuples():
            g = te[(te["TaskName"] == r.task) & te["Status"].eq("Aborted")]
            out.append(qe._ev("Reload time-out", f"{r.task}: aborted at {r.aborts_at} every time", g["start"].min(),
                              g["stop"].max(), "Medium",
                              f"{len(g)} runs were stopped after almost exactly the same time ({r.aborts_at}). That "
                              "pattern is a time-out (the task's own limit, or the reload waiting on a database or file "
                              "that doesn't answer), not a script error. Check the task's time-out in the QMC and what "
                              "the reload is waiting for.", app=r.app, metric=r.aborts_at, source="Scheduler task runs",
                              key="timeout:" + r.task))
    if scripts is not None and len(scripts):
        names = {str(k).lower(): v for k, v in (names or {}).items()}
        bad = scripts[scripts["status"].eq("failed")]
        for aid, g in bad.groupby("app_id"):
            if len(g) < 3:
                continue
            last_ok = scripts[(scripts["app_id"] == aid) & scripts["status"].isin(["ok", "warn"])]["start"].max()
            recent = g[g["start"] > last_ok] if pd.notna(last_ok) else g
            if len(recent) < 3:
                continue
            nm = names.get(aid, aid[:8] + "…")
            out.append(qe._ev("Reload failing", f"{nm}: last {len(recent)} reloads failed (reload logs)", recent["start"].min(),
                              recent["start"].max(), "High",
                              f"The app's own reload logs show {len(recent)} failures in a row. Latest error: "
                              f"{recent.sort_values('start')['error'].iloc[-1][:200] or 'not found in the log'}.",
                              app=nm, metric=str(len(recent)), source="Reload script logs", key="script:" + aid))
    return out

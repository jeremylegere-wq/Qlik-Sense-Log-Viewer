"""Reported issues: a register of problems people report, built up over time so it can be trended.

Each report has when it happened (server time), the app or dashboard, who reported it, the symptom and any error
text. Reports are added one at a time (the "Report an issue" button) or in bulk from a CSV. When a report is
investigated, its most likely cause, the confidence and the log coverage are saved with it, so the register keeps
its findings even after the logs have rotated away.

Saved as %USERPROFILE%\\.qlik_log_analyzer\\reported_issues.csv.
"""
from __future__ import annotations

import hashlib
import io
import re

import pandas as pd

import incident_rules as R
import qlik_share as qs

def path():
    return qs.data_dir() / "reported_issues.csv"

FIELDS = ["id", "reported", "started", "app", "app_id", "symptom", "error_text", "reporter", "users_affected",
          "replicated", "ticket", "status", "notes", "source", "created", "likely_cause", "likely_p", "coverage",
          "investigated"]
STATUSES = ["Open", "Investigating", "Resolved", "Closed", "Not a fault"]
_SYN = {  # import header (lower case, spaces collapsed) -> field
    "reported": ["when", "reported", "reported at", "reported time", "date time", "datetime", "timestamp", "time reported",
                 "date/time", "occurred", "when it happened", "incident time"],
    "date": ["date", "day", "reported date"], "time": ["time", "reported time of day", "time of day"],
    "started": ["started", "started around", "start", "start time"],
    "app": ["app", "application", "dashboard", "app name", "qlik app", "report", "dashboard used", "app used"],
    "reporter": ["reported by", "reporter", "who", "user", "caller", "raised by", "name"],
    "symptom": ["symptom", "type", "issue type", "category", "problem", "issue", "what happened", "issue description"],
    "error_text": ["error", "error text", "error message", "message", "error shown"],
    "users_affected": ["users", "users affected", "affected users", "number of users", "no. users", "people affected"],
    "replicated": ["replicated", "reproducible", "could replicate", "repro"],
    "ticket": ["ticket", "incident", "inc", "jira", "servicenow", "reference", "ref"],
    "notes": ["notes", "description", "details", "comment", "comments", "summary"],
    "status": ["status", "state"],
}
_SYMPTOM_WORDS = [  # keyword -> symptom (first match wins)
    (r"log ?in|sign ?in|auth|access denied|password", "Can't log in"),
    (r"reload|refresh(ed)? fail|data (not|didn.t) (update|refresh)|stale", "Reload failed"),
    (r"drop|disconnect|connection lost|kicked|session.*(timed? ?out|expired)", "Session dropped mid-use"),
    (r"blank|empty|error in (the )?sheet|object|visuali[sz]ation|calc", "Blank objects / errors in sheets"),
    (r"slow|lag|hang|spinning|loading forever|perform|tim(e|ed|ing) ?out", "Slow"),
    (r"open|load(ing)? (the )?app|no ?engine|unavailable|can.t (get|access)", "Can't open an app"),
]


def _new_id(*parts) -> str:
    return "i" + hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:9]


def load(path=None) -> pd.DataFrame:
    p = path or globals()["path"]()
    if not p.exists():
        return _empty()
    df = pd.read_csv(p, dtype=str, keep_default_na=False)
    for f in FIELDS:
        if f not in df:
            df[f] = ""
    return _types(df[FIELDS])


def _empty() -> pd.DataFrame:
    return _types(pd.DataFrame(columns=FIELDS))


def _types(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for c in ("reported", "started", "created", "investigated"):
        df[c] = pd.to_datetime(df[c].replace("", pd.NA), errors="coerce")
    for c in ("users_affected", "likely_p", "coverage"):
        df[c] = pd.to_numeric(df[c], errors="coerce")
    for c in FIELDS:
        if df[c].dtype == object or str(df[c].dtype).startswith("string"):
            df[c] = df[c].fillna("").astype(str)
    return df


def save(df: pd.DataFrame, path=None) -> None:
    p = path or globals()["path"]()
    p.parent.mkdir(parents=True, exist_ok=True)
    out = df[FIELDS].copy()
    for c in ("reported", "started", "created", "investigated"):
        out[c] = out[c].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")
    out.to_csv(p, index=False)


def add(df: pd.DataFrame, rec: dict) -> tuple[pd.DataFrame, str]:
    """Add one report. rec: reported (server time) plus any FIELDS. Returns (register, id)."""
    rec = dict(rec)
    rep = pd.Timestamp(rec["reported"])
    rec["id"] = rec.get("id") or _new_id(rep, rec.get("app", ""), rec.get("reporter", ""), pd.Timestamp.now())
    rec.setdefault("status", "Open")
    rec.setdefault("source", "manual")
    rec["created"] = rec.get("created") or pd.Timestamp.now().floor("s")
    row = pd.DataFrame([{f: rec.get(f, "") for f in FIELDS}])
    return _types(pd.concat([df[FIELDS].astype(object), row.astype(object)], ignore_index=True)), rec["id"]


def update(df: pd.DataFrame, rid: str, **fields) -> pd.DataFrame:
    df = df.copy()
    m = df["id"] == rid
    for k, v in fields.items():
        if k in df:
            df.loc[m, k] = v
    return _types(df)


def remove(df: pd.DataFrame, rid: str) -> pd.DataFrame:
    return df[df["id"] != rid].reset_index(drop=True)


def guess_symptom(text: str) -> str:
    t = str(text or "").lower()
    if not t:
        return "Not sure"
    for s in R.SYMPTOMS:
        if t == s.lower():
            return s
    for rx, s in _SYMPTOM_WORDS:
        if re.search(rx, t):
            return s
    return "Not sure"


# ----------------------------------------------------------------------------------------------
# Bulk import
# ----------------------------------------------------------------------------------------------
TEMPLATE_COLUMNS = ["When", "App", "Reported by", "Symptom", "Error", "Users affected", "Replicated", "Ticket", "Notes"]


def template_csv() -> bytes:
    ex = pd.DataFrame([
        {"When": "28/10/2026 09:15", "App": "Sales_Dashboard", "Reported by": "Jane Citizen", "Symptom": "Slow",
         "Error": "", "Users affected": "3", "Replicated": "Yes", "Ticket": "INC0000000", "Notes": "Spinning on the ED tab"},
        {"When": "28/10/2026 10:40", "App": "Activity", "Reported by": "John Smith", "Symptom": "Can't open an app",
         "Error": "ProxyError.OnNoEngineAvailable", "Users affected": "1", "Replicated": "No", "Ticket": "", "Notes": ""},
    ], columns=TEMPLATE_COLUMNS)
    return ex.to_csv(index=False).encode("utf-8-sig")


def _col(df: pd.DataFrame, field: str) -> str | None:
    norm = {re.sub(r"\s+", " ", str(c).strip().lower()): c for c in df.columns}
    for name in [field] + _SYN.get(field, []):
        if name in norm:
            return norm[name]
    return None


def read_bulk(raw: bytes, filename: str = "", to_server=None) -> tuple[pd.DataFrame, list[str]]:
    """A CSV (or Excel) of reports with any sensible column names. Times are day-first (Australian) unless ISO.
    to_server: function converting a typed time to server time. Returns (rows as FIELDS, problems)."""
    if filename.lower().endswith((".xlsx", ".xls")):
        df = pd.read_excel(io.BytesIO(raw), dtype=str).fillna("")
    else:
        text = raw.decode("utf-8-sig", errors="replace")
        sep = "\t" if "\t" in text.split("\n", 1)[0] else ","
        df = pd.read_csv(io.StringIO(text), sep=sep, dtype=str, keep_default_na=False)
    problems = []
    c_when, c_date, c_time = _col(df, "reported"), _col(df, "date"), _col(df, "time")
    if c_when:
        when_txt = df[c_when].astype(str)
    elif c_date:
        when_txt = df[c_date].astype(str) + " " + (df[c_time].astype(str) if c_time else "")
    else:
        raise ValueError("The file needs a When column (or Date and Time columns). Download the template to see the layout.")
    iso = when_txt.str.match(r"^\s*\d{4}-\d{2}-\d{2}")
    when = pd.Series(pd.NaT, index=df.index, dtype="datetime64[ns]")
    when[iso] = pd.to_datetime(when_txt[iso], errors="coerce")
    when[~iso] = pd.to_datetime(when_txt[~iso], dayfirst=True, errors="coerce", format="mixed")
    bad = when.isna()
    if bad.any():
        problems.append(f"{int(bad.sum())} row(s) skipped: the time couldn't be read (e.g. '{when_txt[bad].iloc[0]}').")
    out = pd.DataFrame(index=df.index)
    out["reported"] = when.map(lambda t: to_server(t) if to_server and pd.notna(t) else t)
    c = _col(df, "started")
    out["started"] = pd.to_datetime(df[c], dayfirst=True, errors="coerce", format="mixed") if c else pd.NaT
    if c and to_server:
        out["started"] = out["started"].map(lambda t: to_server(t) if pd.notna(t) else t)
    for f in ("app", "reporter", "error_text", "ticket", "notes", "replicated", "status"):
        c = _col(df, f)
        out[f] = df[c].astype(str).str.strip() if c else ""
    c = _col(df, "symptom")
    raw_sym = df[c].astype(str) if c else pd.Series("", index=df.index)
    out["symptom"] = [next((g for g in (guess_symptom(t) for t in (s_, n_, e_)) if g != "Not sure"), "Not sure")
                      for s_, n_, e_ in zip(raw_sym, out["notes"], out["error_text"])]
    if c is not None:   # keep what was typed if it isn't one of the standard symptoms
        typed = raw_sym.str.strip()
        out["notes"] = [(f"{t_} · {n_}" if n_ else t_) if t_ and t_ not in R.SYMPTOMS else n_
                        for t_, n_ in zip(typed, out["notes"])]
    c = _col(df, "users_affected")
    out["users_affected"] = pd.to_numeric(df[c].astype(str).str.extract(r"(\d+)")[0], errors="coerce") if c else pd.NA
    out["replicated"] = out["replicated"].str.lower().map(lambda v: "Yes" if v in ("yes", "y", "true", "1") else
                                                           "No" if v in ("no", "n", "false", "0") else "Unknown")
    out["status"] = out["status"].map(lambda v: next((s for s in STATUSES if s.lower() == str(v).lower()), "Open"))
    out = out[~bad].copy()
    out["id"] = [_new_id(r.reported.floor("min"), r.app.lower(), r.reporter.lower()) for r in out.itertuples()]
    out["source"] = "import " + (filename or "csv")
    out["created"] = pd.Timestamp.now().floor("s")
    for f in FIELDS:
        if f not in out:
            out[f] = ""
    return _types(out[FIELDS].reset_index(drop=True)), problems


def merge_bulk(df: pd.DataFrame, new: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Add imported rows. A row with the same time (to the minute), app and reporter as one already there is
    skipped, so importing the same file twice changes nothing."""
    have = set(df["id"]) if len(df) else set()
    fresh = new[~new["id"].isin(have)]
    out = _types(pd.concat([df[FIELDS].astype(object), fresh[FIELDS].astype(object)], ignore_index=True)) if len(fresh) else df
    return out, {"added": len(fresh), "skipped": len(new) - len(fresh)}


def migrate_events_store(df: pd.DataFrame, store: dict, key: str = "_reported") -> tuple[pd.DataFrame, int]:
    """Bring issues logged on the Events page in earlier versions into the register (same IDs, so their status,
    owner and notes in the event register still apply)."""
    old = store.get(key) or []
    have = set(df["id"]) if len(df) else set()
    n = 0
    for r in old:
        if r.get("id") in have:
            continue
        df, _ = add(df, {"id": r["id"], "reported": pd.Timestamp(r["start"]), "app": r.get("app", ""),
                         "reporter": r.get("user", ""), "symptom": guess_symptom(r.get("title", "")),
                         "notes": (r.get("title", "") + (" · " + r["detail"] if r.get("detail") else "")).strip(),
                         "source": "Events page (earlier version)", "created": r.get("logged", "")})
        n += 1
    return df, n


def as_events(df: pd.DataFrame) -> pd.DataFrame:
    """Reports as rows for the event register / timeline (category 'Reported issue')."""
    if df is None or df.empty:
        return pd.DataFrame()
    rows = []
    for r in df.itertuples():
        if pd.isna(r.reported):
            continue
        start = r.started if pd.notna(r.started) else r.reported - pd.Timedelta(minutes=20)
        sev = "High" if (pd.notna(r.users_affected) and r.users_affected >= 10) else "Medium"
        title = (r.symptom if r.symptom and r.symptom != "Not sure" else "Reported problem") + (f" · {r.app}" if r.app else "")
        detail = "; ".join(x for x in [f"Error: {r.error_text}" if r.error_text else "", r.notes,
                                       f"Likely: {r.likely_cause} ({r.likely_p:.0f}%)" if r.likely_cause and pd.notna(r.likely_p) else ""] if x)
        rows.append({"id": r.id, "start": start, "end": r.reported, "severity": sev, "category": "Reported issue",
                     "title": title, "app": r.app, "user": r.reporter, "metric": r.ticket or "reported",
                     "detail": detail or "Reported by a user.", "source": f"Reported ({r.source})"})
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------------------------
# Trends
# ----------------------------------------------------------------------------------------------
def trends(df: pd.DataFrame) -> dict:
    x = df.dropna(subset=["reported"])
    if x.empty:
        return {}
    span = (x["reported"].max() - x["reported"].min()).days
    per = "W-MON" if span > 21 else "D"
    by_sym = x.groupby([x["reported"].dt.to_period(per).dt.start_time, "symptom"]).size().unstack(fill_value=0)
    apps = x[x["app"].ne("")].groupby("app").agg(reports=("id", "size"), last=("reported", "max"),
                                                 users=("users_affected", "sum")).sort_values("reports", ascending=False)
    hw = x.groupby([x["reported"].dt.day_of_week, x["reported"].dt.hour]).size().unstack(fill_value=0) \
        .reindex(index=range(7), columns=range(24), fill_value=0)
    err = x[x["error_text"].ne("")]
    errs = err.assign(sig=err["error_text"].str.replace(r"\d+", "#", regex=True).str.slice(0, 120)).groupby("sig") \
        .agg(reports=("id", "size"), apps=("app", lambda s: ", ".join(sorted(set(filter(None, s))))[:120]),
             last=("reported", "max")).sort_values("reports", ascending=False) if len(err) else pd.DataFrame()
    inv = x[x["likely_cause"].ne("")]
    causes = inv.groupby([inv["reported"].dt.to_period("M").dt.start_time, "likely_cause"]).size().unstack(fill_value=0) \
        if len(inv) else pd.DataFrame()
    return {"period": "week" if per != "D" else "day", "by_symptom": by_sym, "apps": apps, "hour_weekday": hw,
            "errors": errs, "causes": causes, "investigated": len(inv), "total": len(x),
            "open": int(x["status"].isin(["Open", "Investigating"]).sum())}


# ----------------------------------------------------------------------------------------------
# Hand-offs: a prompt for Jira Rovo
# ----------------------------------------------------------------------------------------------
def jira_rovo_prompt(rep: dict, ranked: list[dict] | None, coverage_score: float | None, tz_text: str,
                     project: str = "", top: int = 3, restart: dict | None = None) -> str:
    """Text to paste into Jira's Rovo chat to create a Bug with everything the investigation found."""
    when = pd.Timestamp(rep["reported"])
    app = rep.get("app") or "unknown app"
    sym = rep.get("symptom") if rep.get("symptom") and rep.get("symptom") != "Not sure" else "Problem reported"
    users = rep.get("users_affected")
    many = pd.notna(users) and users not in ("", None) and float(users) >= 10
    prio = "High" if many else "Medium"
    lines = [f"Create a Bug in {('Jira project ' + project) if project else 'the Jira project for this system'} with the details below. Use the summary as the title, put the rest "
             "in the description with the headings shown, set the priority and add the labels. Don't change the wording "
             "of the likely causes: they are leads from log analysis, not confirmed causes.", "",
             f"Summary: [Qlik] {sym} – {app} – {when:%d %b %Y %H:%M}", f"Priority: {prio}",
             "Labels: qlik, qlik-sense, reported-issue" + (f", {re.sub(r'[^a-z0-9]+', '-', sym.lower()).strip('-')}" if sym else ""), "",
             "Description:", "h3. What was reported",
             f"* When: {when:%a %d %b %Y %H:%M} ({tz_text})" + (f", started around {pd.Timestamp(rep['started']):%H:%M}"
                                                                   if rep.get("started") is not None and pd.notna(rep.get("started")) else ""),
             f"* App / dashboard: {app}", f"* Symptom: {sym}"]
    if rep.get("reporter"):
        lines.append(f"* Reported by: {rep['reporter']}")
    if pd.notna(users) and users not in ("", None):
        lines.append(f"* Users affected: {int(float(users))}")
    if rep.get("replicated") and rep["replicated"] != "Unknown":
        lines.append(f"* Could be reproduced: {rep['replicated']}")
    if rep.get("error_text"):
        lines.append(f"* Error shown: {{noformat}}{rep['error_text'].strip()[:400]}{{noformat}}")
    if rep.get("ticket"):
        lines.append(f"* Related ticket: {rep['ticket']}")
    if rep.get("notes"):
        lines.append(f"* Notes: {rep['notes'].strip()[:500]}")
    if ranked:
        lines += ["", "h3. Likely causes (heuristic estimate from the Qlik server logs, not proof)"]
        if coverage_score is not None:
            lines.append(f"Log coverage of the time: {coverage_score * 100:.0f}%.")
        main = [r for r in ranked if r.get("role", "cause") == "cause"]
        for i, r in enumerate(main[:top], 1):
            lines.append(f"# {r['title']} – {r['band']} ({r['p'] * 100:.0f}%)")
            for s in r["support"][:3 if not restart or r["id"] != "engine_restart" else 7]:
                lines.append(f"** consistent with: {s['text'].lstrip('· ')}" + (f" ({pd.Timestamp(s['ts']):%H:%M}, {s['source']})"
                                                                                 if s.get("ts") is not None else f" ({s['source']})"))
        if restart:
            sg = restart["sig"]
            lines += ["", f"h3. Engine restart {pd.Timestamp(sg['start']):%H:%M:%S}–{pd.Timestamp(sg['end']):%H:%M:%S}: possible causes "
                          "(ranked by what the logs are consistent with)"]
            for c in restart["ranked"]:
                lines.append(f"# {c['title']} – {c['verdict']}")
                for f_ in c["for"][:3]:
                    lines.append(f"** consistent with: {f_}")
            lines.append(f"*{restart['insufficient']}*")
            up = [u for u in restart.get("upstream", []) if u["seen"]]
            if up:
                lines.append("Possible upstream causes (hour before): " + "; ".join(f"{u['title']} ({u['seen'][0]})" for u in up[:4]))
        lines += ["", "h3. Next checks"]
        seen = set()
        for c in (restart["checks"] if restart else []) + [c for r in main[:2] if not (restart and r["id"] == "engine_restart")
                                                           for c in r["checks"][:2]]:
            if c not in seen:
                seen.add(c)
                lines.append(f"* {c}")
    lines += ["", "h3. Acceptance", "* Cause confirmed (or ruled out) and recorded on this ticket",
              "* Fix or workaround in place, and the reporter told", "",
              "Source: Qlik Server Event Manager (Incident Investigator)."]
    return "\n".join(lines)

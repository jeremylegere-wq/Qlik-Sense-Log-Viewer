"""Incident Investigator: from a reported problem to ranked, evidence-backed likely causes.

    1. coverage()  - which logs cover the investigation window, and where the gaps are (a gap is evidence too)
    2. evidence()  - signals for the window compared with a baseline (same time on earlier days if loaded,
                     otherwise the rest of the context window)
    3. score()     - prior × likelihood per hypothesis, normalised (rules and weights in incident_rules.py)
    4. note()      - a short Markdown incident note for an email or a ticket

Read-only and local. Every conclusion is worded as "likely" / "consistent with": it is a heuristic estimate.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

import incident_rules as R
import site_config
import qlik_events as qe
import qlik_logs as q
import qlik_proxy as qp
import qlik_restart as qrs



def _pc_offset_min() -> int:
    """Minutes east of UTC on this PC right now."""
    import time
    lt = time.localtime()
    return int((lt.tm_gmtoff if hasattr(lt, "tm_gmtoff") and lt.tm_gmtoff is not None else -time.timezone) // 60)


def _utc_text(minutes: int) -> str:
    h, m = divmod(abs(int(minutes)), 60)
    return f"UTC{'+' if minutes >= 0 else '-'}{h}{':%02d' % m if m else ''}"


LOCAL_MIN = site_config.LOCAL_TZ_MIN if site_config.LOCAL_TZ_MIN is not None else _pc_offset_min()
LOCAL_LABEL = f"{site_config.LOCAL_TZ_NAME or 'This PC'} ({_utc_text(LOCAL_MIN)})"
TZ_CHOICES = [LOCAL_LABEL, "Server time", "UTC"]


@dataclass
class Incident:
    reported: pd.Timestamp                 # server local time (converted from what was entered)
    started: pd.Timestamp | None = None
    last_good: pd.Timestamp | None = None
    symptom: str = "Not sure"
    error_text: str = ""
    apps: list = field(default_factory=list)
    users_affected: int = 0
    replicated: str = "Unknown"            # Yes / No / Unknown
    reporter: str = ""
    notes: str = ""
    before_min: int = 20
    after_min: int = 5

    @property
    def window(self) -> tuple[pd.Timestamp, pd.Timestamp]:
        a = self.started if self.started is not None else self.reported - pd.Timedelta(minutes=self.before_min)
        if self.last_good is not None and self.started is None:
            a = max(self.last_good, self.reported - pd.Timedelta(hours=6))
        return a, self.reported + pd.Timedelta(minutes=self.after_min)

    @property
    def context(self) -> tuple[pd.Timestamp, pd.Timestamp]:
        a, b = self.window
        span = max(pd.Timedelta(hours=2), (b - a) * 3)
        pad = (span - (b - a)) / 2
        return a - pad, b + pad


# ----------------------------------------------------------------------------------------------
# Time zones
# ----------------------------------------------------------------------------------------------
def server_offset_min(data: dict) -> int | None:
    """Minutes east of UTC that the server writes in its log timestamps (e.g. +1000 -> 600)."""
    for df in (data or {}).values():
        if df is not None and len(df) and "Timestamp" in df:
            m = re.search(r"([+-])(\d{2}):?(\d{2})\s*$", str(df["Timestamp"].iloc[-1]))
            if m:
                return (1 if m.group(1) == "+" else -1) * (int(m.group(2)) * 60 + int(m.group(3)))
    return None


def to_server_time(ts: pd.Timestamp, tz_choice: str, server_off: int | None) -> pd.Timestamp:
    """Convert a time typed in `tz_choice` to the server's local clock (the clock the logs use)."""
    if ts is None or pd.isna(ts):
        return ts
    srv = LOCAL_MIN if server_off is None else server_off
    entered = {LOCAL_LABEL: LOCAL_MIN, "UTC": 0}.get(tz_choice, srv)
    return pd.Timestamp(ts) + pd.Timedelta(minutes=srv - entered)


def tz_label(server_off: int | None) -> str:
    if server_off is None:
        return f"server time (offset not found in the logs; assumed {_utc_text(LOCAL_MIN)})"
    return f"server time ({_utc_text(server_off)})"


# ----------------------------------------------------------------------------------------------
# 1. Coverage
# ----------------------------------------------------------------------------------------------
SOURCES = [  # (kind, label, weight in the coverage score, periodic?)
    ("performance", "Engine performance (CPU, memory, users)", 0.22, True),
    ("repo_perf", "Server CPU (repository performance)", 0.13, True),
    ("proxy_perf", "Proxy sessions", 0.10, True),
    ("proxy_audit", "Proxy audit (logins, engine routing)", 0.12, False),
    ("system", "Engine system log", 0.13, False),
    ("task_exec", "Scheduler task runs", 0.12, False),
    ("activity", "Engine audit (requests)", 0.08, False),
    ("session", "Engine sessions", 0.05, False),
    ("svc_system", "Scheduler / proxy / repository trace", 0.05, False),
]


def _ts_of(kind: str, df: pd.DataFrame) -> pd.Series:
    if kind == "task_exec" and "start" in df:
        return df["start"]
    return df["ts"]


def coverage(data: dict, inc: Incident) -> dict:
    """Per source: does it cover the window, rows in the window, the largest gap. Plus an overall 0-1 score."""
    a, b = inc.window
    ca, cb = inc.context
    rows, gaps, warnings = [], [], []
    score = 0.0
    total_w = sum(w for *_, w, _ in SOURCES)
    for kind, label, w, periodic in SOURCES:
        df = (data or {}).get(kind)
        if df is None or df.empty:
            rows.append({"source": label, "kind": kind, "status": "Not loaded", "first": pd.NaT, "last": pd.NaT,
                         "in_window": 0, "largest_gap_min": None})
            continue
        ts = _ts_of(kind, df).dropna().sort_values()
        first, last = ts.min(), ts.max()
        inw = ts[(ts >= a) & (ts <= b)]
        status = "Covers"
        frac = 1.0
        gap_min = None
        if last < a:
            status, frac = "Ends before", 0.0
        elif first > b:
            status, frac = "Starts after", 0.0
        elif first > a or last < b:
            status = "Partial"
            frac = max(0.0, (min(last, b) - max(first, a)) / (b - a))
        if periodic and frac > 0:
            step = ts.diff().median()
            seg = ts[(ts >= ca) & (ts <= cb)]
            # from the last sample before the window to the first after it, so a gap that started before is seen whole
            prev_, next_ = seg[seg < a], seg[seg > b]
            p0 = prev_.iloc[-1] if len(prev_) else max(a, first)
            p1 = next_.iloc[0] if len(next_) else min(b, last)
            pts = pd.concat([pd.Series([p0]), seg[(seg >= a) & (seg <= b)], pd.Series([p1])]).sort_values().reset_index(drop=True)
            d_ = pts.diff().dropna()
            if len(d_) and pd.notna(step):
                big = d_.max()
                i = d_.idxmax()
                g_start, g_end = pts.loc[i - 1], pts.loc[i]
                inside = min(g_end, b) - max(g_start, a)
                gap_min = big.total_seconds() / 60
                if big > step * 2.5 and big >= pd.Timedelta(minutes=8) and inside > pd.Timedelta(0):
                    gaps.append({"source": label, "kind": kind, "start": g_start, "end": g_end, "minutes": gap_min})
                    status = "Gap in window"
                    frac = min(frac, max(0.0, 1 - inside / (b - a)))
        score += w * frac
        rows.append({"source": label, "kind": kind, "status": status, "first": first, "last": last,
                     "in_window": int(len(inw)), "largest_gap_min": round(gap_min, 1) if gap_min is not None else None})
    df = pd.DataFrame(rows)
    loaded = df[df["status"] != "Not loaded"]
    if len(loaded) and (loaded["last"] < inc.reported).all():
        warnings.append(f"Every log loaded ends before the reported time (newest {loaded['last'].max():%a %d %b %H:%M}). "
                        "The archived logs may not have rotated yet: fetch newer logs or load the live log folder.")
    elif len(loaded) and (loaded["status"] == "Ends before").any():
        warnings.append("Some logs end before the window: " + ", ".join(loaded.loc[loaded["status"] == "Ends before", "source"]) + ".")
    if loaded.empty:
        warnings.append("No logs are loaded, so nothing in the window can be checked.")
    for g in gaps:
        warnings.append(f"{g['source']}: no samples for {g['minutes']:.0f} min ({g['start']:%H:%M}–{g['end']:%H:%M}). "
                        "A gap like this can mean the engine was busy, restarting or not logging.")
    return {"table": df, "gaps": gaps, "warnings": warnings, "score": score / total_w}


# ----------------------------------------------------------------------------------------------
# 2. Evidence
# ----------------------------------------------------------------------------------------------
def _ev(signal, value, text, ts=None, source="", detail=""):
    return {"signal": signal, "value": float(max(-1.0, min(1.0, value))), "text": text,
            "ts": pd.Timestamp(ts) if ts is not None and pd.notna(ts) else None, "source": source, "detail": detail}


def _slice(df, a, b, col="ts"):
    if df is None or df.empty or col not in df:
        return None
    return df[(df[col] >= a) & (df[col] <= b)]


def _baseline(df: pd.DataFrame, col: str, inc: Incident) -> tuple[pd.Series, str]:
    """Values to compare against: the same time of day on earlier days if loaded, else the rest of the context."""
    a, b = inc.window
    same = []
    for k in range(1, 8):
        x = df[(df["ts"] >= a - pd.Timedelta(days=k)) & (df["ts"] <= b - pd.Timedelta(days=k))][col]
        if len(x):
            same.append(x)
    if same:
        return pd.concat(same).dropna(), f"same time on {len(same)} earlier day(s)"
    ca, cb = inc.context
    x = df[(df["ts"] >= ca) & (df["ts"] <= cb) & ~((df["ts"] >= a) & (df["ts"] <= b))][col].dropna()
    return x, "the 2 hours around the window"


def restart_in_window(data: dict, inc: Incident, sigs: pd.DataFrame | None = None):
    """The strongest engine restart signature in (or shortly before) the investigation window, or None."""
    a, b = inc.window
    if sigs is None:
        P = (data or {}).get("performance")
        if P is None or P.empty:
            return None
        ca, cb = inc.context
        sigs = qrs.find(P[(P["ts"] >= ca - pd.Timedelta(hours=2)) & (P["ts"] <= cb + pd.Timedelta(hours=2))])
    hit = qrs.in_window(sigs, a, b)
    return hit.iloc[0] if len(hit) else None


def restart_finding(data: dict, inc: Incident, events: pd.DataFrame | None = None, settings: dict | None = None,
                    history: pd.DataFrame | None = None) -> dict | None:
    """For a report whose window holds a restart: the restart, its possible causes ranked, and what to check."""
    sig = restart_in_window(data, inc)
    if sig is None:
        return None
    return {"sig": sig, **qrs.causes(sig, data, events, settings, history)}


def evidence(data: dict, inc: Incident, events: pd.DataFrame | None = None, settings: dict | None = None,
             failures: pd.DataFrame | None = None, cov: dict | None = None) -> list[dict]:
    st = {"cpu_warn": 60, "cpu_thr": 80, "ram_gb": site_config.SERVER_RAM_GB, "low_pct": 70, "high_pct": 90, "conc_thr": 10, "storm": 600}
    st.update(settings or {})
    data = data or {}
    a, b = inc.window
    out = []
    P = data.get("performance")
    RP = data.get("repo_perf")
    PX = data.get("proxy_perf")
    Y = data.get("system")

    # --- engine restart signature and gaps -----------------------------------------------------
    sig = restart_in_window(data, inc)
    if sig is not None:
        k = int(sig["n"])
        val = {1: 0.35, 2: 0.75}.get(k, 1.0)
        when = f"{sig['start']:%H:%M:%S}–{sig['end']:%H:%M:%S}"
        if sig["end"] < a:
            when += f" ({(a - sig['end']).total_seconds() / 60:.0f} min before the window)"
        lost = f", {sig['users_lost']:.0f} users lost" if pd.notna(sig["users_lost"]) else ""
        out.append(dict(_ev("restart_signature", val, f"Engine restart signature: {sig['strength'].lower()}, {k} of "
                            f"{len(qrs.SIGNALS)} signals, {when}{lost}", sig["start"], "Engine performance log"), restart_n=k))
        for t in sig["texts"]:
            out.append(dict(_ev("restart_signature", 0.3, "· " + t, sig["start"], "Engine performance log"), restart_n=k))
    elif _slice(P, a, b) is not None and len(_slice(P, a, b)):
        out.append(_ev("restart_signature", -0.6, "No restart signature: same engine process, users and memory steady "
                       "through the window", None, "Engine performance log"))
    msgs = []
    for kind in ("system", "service", "svc_system"):
        df = data.get(kind)
        x = _slice(df, a - pd.Timedelta(minutes=10), b)
        if x is not None and len(x) and "Message" in x:
            msgs.append(x.assign(_src=kind))
    M = pd.concat(msgs, ignore_index=True) if msgs else pd.DataFrame(columns=["ts", "Message", "_src"])
    rst = M[M["Message"].astype(str).str.contains(r"(?i)\b(?:engine|service)\b.*\b(?:start(?:ed|ing)|shut(?:ting)? ?down|stopp(?:ed|ing))\b|"
                                                 r"\b(?:start(?:ed|ing)|shut(?:ting)? ?down|stopp(?:ed|ing))\b.*\b(?:engine|service)\b", regex=True)]
    ab = M[M["Message"].astype(str).str.contains(qrs._ABORT)]
    if len(ab):    # the engine's own restart reason (its watchdog), worded by Qlik
        out.append(_ev("restart", 1.0, f"The engine log states a reason for a restart: {str(ab['Message'].iloc[0])[:120]}", ab["ts"].iloc[0],
                       "Engine system log"))
    elif len(rst):
        out.append(_ev("restart", 0.8, f"Service start/stop message: {str(rst['Message'].iloc[0])[:120]}", rst["ts"].iloc[0],
                       {"system": "Engine system log", "service": "Service log", "svc_system": "Service trace"}.get(rst["_src"].iloc[0], "")))
    if cov:
        for g in cov.get("gaps", []):
            if g["kind"] in ("performance", "repo_perf", "proxy_perf"):
                extra = " (just before the engine restart)" if sig is not None and abs((g["end"] - sig["start"]).total_seconds()) <= 180 else ""
                out.append(_ev("perf_gap", min(1.0, g["minutes"] / 20), f"No {g['source'].lower()} samples for {g['minutes']:.0f} min "
                               f"({g['start']:%H:%M}–{g['end']:%H:%M}){extra}", g["start"], g["source"]))
                break
        else:
            t = cov["table"]
            if len(t[t["kind"].isin(["performance", "repo_perf"]) & t["status"].eq("Covers")]):
                out.append(_ev("perf_gap", -0.4, "Performance samples are continuous through the window", None, "Performance logs"))

    # --- proxy: no engine, repository failures, auth -------------------------------------------
    pc = qp.classify(_slice(data.get("proxy_audit"), a, b))
    if data.get("proxy_audit") is not None and len(data["proxy_audit"]):
        allmsg = pd.concat([pc[["ts", "Message"]] if len(pc) else pd.DataFrame(columns=["ts", "Message"]),
                            M[M["_src"].eq("svc_system")][["ts", "Message"]] if len(M) else pd.DataFrame(columns=["ts", "Message"])])
        ne = allmsg[allmsg["Message"].astype(str).str.contains(r"(?i)no engine|NoEngineAvailable|Retrieved 0 engine|"
                                                               r"failed to connect.*4747|engine.*(?:unavailable|not available)", regex=True)]
        if len(ne):
            out.append(_ev("no_engine", min(1.0, 0.5 + len(ne) / 10), f"{len(ne)} 'no engine available' style messages",
                           ne["ts"].iloc[0], "Proxy logs", str(ne["Message"].iloc[0])[:160]))
        else:
            out.append(_ev("no_engine", -0.3, "The proxy routed users to the engine normally (no 'no engine' messages)", None,
                           "Proxy audit log"))
        k = pc["kind"].value_counts() if len(pc) else pd.Series(dtype=int)
        rf = int(k.get("repo_fail", 0))
        if rf:
            t0 = pc.loc[pc["kind"].eq("repo_fail"), "ts"].iloc[0]
            out.append(_ev("repo_fail", min(1.0, rf / 8), f"Proxy lost its repository connection {rf} time(s)", t0, "Proxy audit log"))
        else:
            out.append(_ev("repo_fail", -0.3, "No proxy-to-repository connection failures", None, "Proxy audit log"))
        bad = int(k.reindex(["ticket_bad", "tls", "denied"]).fillna(0).sum())
        if bad:
            t0 = pc.loc[pc["kind"].isin(["ticket_bad", "tls", "denied"]), "ts"].iloc[0]
            out.append(_ev("auth_problems", min(1.0, bad / 6), f"{bad} login/authentication problem(s) (rejected tickets, TLS, denied)",
                           t0, "Proxy audit log"))
        lt = qp.login_times(qp.classify(_slice(data.get("proxy_audit"), *inc.context)))
        if len(lt) >= 3:
            inw = lt[(lt["ts"] >= a) & (lt["ts"] <= b)]["seconds"]
            base = lt[~((lt["ts"] >= a) & (lt["ts"] <= b))]["seconds"]
            if len(inw) and len(base) and inw.median() > max(20, 2 * base.median()):
                out.append(_ev("slow_logins", min(1.0, inw.median() / 60), f"Logins took a median {inw.median():.0f}s "
                               f"(usually {base.median():.0f}s)", None, "Proxy audit log"))
            elif len(inw):
                out.append(_ev("slow_logins", -0.3, f"Logins normal speed (median {inw.median():.0f}s)", None, "Proxy audit log"))
        sd = pc[pc["kind"].isin(["timeout", "session_deleted", "session_invalid"])] if len(pc) else pc
        if len(sd) >= 10:
            out.append(_ev("session_drop", min(1.0, len(sd) / 40), f"{len(sd)} sessions ended or became invalid in the window",
                           sd["ts"].iloc[0], "Proxy audit log"))

    # --- users: sudden drops -------------------------------------------------------------------
    for df, col, src in ((PX, "ActiveSessions", "Proxy performance log"), (P, "ActiveUsers", "Engine performance log")):
        x = _slice(df, a - pd.Timedelta(minutes=10), b)
        if x is not None and len(x) >= 2 and col in x:
            v = x[col].astype(float)
            drop = (v.shift(1) - v) / v.shift(1).clip(lower=1)
            i = drop.idxmax()
            if sig is not None and sig["start"] - pd.Timedelta(minutes=1) <= x.loc[i, "ts"] <= sig["end"] + pd.Timedelta(minutes=6):
                pass                                    # the restart itself (counted in the restart signature)
            elif drop.max() >= 0.3 and v.shift(1).loc[i] >= 5:
                out.append(_ev("session_drop", min(1.0, drop.max() * 1.5), f"Users connected fell {drop.max() * 100:.0f}% "
                               f"({v.shift(1).loc[i]:.0f} → {v.loc[i]:.0f})", x.loc[i, "ts"], src))
            else:
                out.append(_ev("session_drop", -0.3, f"No sudden drop in users connected ({v.min():.0f}–{v.max():.0f})", None, src))
            break

    # --- CPU ---------------------------------------------------------------------------------
    cpu_src = [(RP, "machine_cpu", "Server CPU", "Repository performance log"), (P, "CPULoad", "Engine CPU", "Engine performance log")]
    peaks = {}
    for df, col, label, src in cpu_src:
        x = _slice(df, a, b)
        if x is None or x.empty or col not in x:
            continue
        pk = float(x[col].max())
        peaks[label] = pk
        base, bdesc = _baseline(df, col, inc)
        p90 = float(base.quantile(.9)) if len(base) else None
        if pk >= st["cpu_thr"]:
            val = 1.0
        elif pk >= st["cpu_warn"]:
            val = 0.5
        else:
            val = -0.7 if (p90 is None or pk <= p90 + 10) else 0.1
        if val > 0 and p90 is not None and pk <= p90 + 5:
            val *= 0.5      # high, but normal for this server at this time
        txt = f"{label} peaked at {pk:.0f}% (warning {st['cpu_warn']}%, alert {st['cpu_thr']}%)"
        if p90 is not None:
            txt += f"; usually up to {p90:.0f}% ({bdesc})"
        out.append(_ev("cpu_high", val, txt, x.loc[x[col].idxmax(), "ts"], src))
        break
    if "Server CPU" in peaks or (RP is not None and P is not None):
        xs, xe = _slice(RP, a, b), _slice(P, a, b)
        if xs is not None and xe is not None and len(xs) and len(xe):
            s_, e_ = float(xs["machine_cpu"].max()), float(xe["CPULoad"].max())
            if s_ >= st["cpu_warn"] and s_ - e_ >= 30:
                out.append(_ev("cpu_not_qlik", min(1.0, (s_ - e_) / 50), f"Server CPU {s_:.0f}% but the Qlik engine only {e_:.0f}%: "
                               "the difference is something else on the server", None, "Performance logs"))
            elif s_ >= st["cpu_warn"]:
                out.append(_ev("cpu_not_qlik", -0.5, f"Server and engine CPU moved together ({s_:.0f}% / {e_:.0f}%)", None,
                               "Performance logs"))

    # --- memory and cache ----------------------------------------------------------------------
    x = _slice(P, a - pd.Timedelta(minutes=10), b)
    if x is not None and len(x) and "VM_GB" in x:
        low, high = st["ram_gb"] * st["low_pct"] / 100, st["ram_gb"] * st["high_pct"] / 100
        pk = float(x["VM_GB"].max())
        if pk >= high:
            out.append(_ev("memory_high", 1, f"Engine memory {pk:.0f} GB, above the high limit ({high:.0f} GB)",
                           x.loc[x["VM_GB"].idxmax(), "ts"], "Engine performance log"))
        elif pk >= low:
            out.append(_ev("memory_high", 0.6, f"Engine memory {pk:.0f} GB, above the low limit ({low:.0f} GB)",
                           x.loc[x["VM_GB"].idxmax(), "ts"], "Engine performance log"))
        else:
            out.append(_ev("memory_high", -0.6, f"Engine memory {pk:.0f} GB, well under the low limit ({low:.0f} GB)", None,
                           "Engine performance log"))
        v = x["VM_GB"].astype(float)
        dr = (v.shift(1) - v) / v.shift(1).clip(lower=1)
        i = dr.idxmax() if dr.notna().any() else None
        if i is not None and sig is not None and sig["start"] - pd.Timedelta(minutes=1) <= x.loc[i, "ts"] <= sig["end"] + pd.Timedelta(minutes=6):
            pass                                        # the restart itself, not a cache purge
        elif dr.max() >= 0.25:
            out.append(_ev("memory_drop", min(1.0, dr.max() * 2), f"Engine memory dropped {dr.max() * 100:.0f}% in one sample "
                           f"({v.shift(1).loc[i]:.0f} → {v.loc[i]:.0f} GB): a cache purge or restart", x.loc[i, "ts"],
                           "Engine performance log"))
        if "cache_hit_pct" in x and x["cache_hit_pct"].notna().any():
            base, bdesc = _baseline(P.dropna(subset=["cache_hit_pct"]), "cache_hit_pct", inc)
            mn = float(x["cache_hit_pct"].min())
            if len(base) and mn < base.median() - 20:
                out.append(_ev("cache_dip", min(1.0, (base.median() - mn) / 40), f"Cache hit rate fell to {mn:.0f}% "
                               f"(usually {base.median():.0f}%)", x.loc[x["cache_hit_pct"].idxmin(), "ts"], "Engine performance log"))
    if Y is not None and len(Y):
        mw = _slice(Y, a, b)
        if mw is not None and len(mw):
            mem = mw[mw["Message"].astype(str).str.contains(r"(?i)working set|out of memory|memory limit", regex=True)]
            if len(mem):
                out.append(_ev("memory_high", 0.8, f"{len(mem)} engine memory warning(s)", mem["ts"].iloc[0], "Engine system log",
                               str(mem["Message"].iloc[0])[:160]))

    # --- reloads -------------------------------------------------------------------------------
    TE = data.get("task_exec")
    if TE is not None and len(TE):
        conc = qe.reload_concurrency(TE)
        cw = conc[(conc.index >= a) & (conc.index <= b)]
        if len(cw):
            base = conc[(conc.index < a) | (conc.index > b)]
            mx = float(cw.max())
            usual = float(base.quantile(.9)) if len(base) else 0
            if mx >= st["conc_thr"]:
                out.append(_ev("reload_pileup", min(1.0, mx / (2 * st["conc_thr"]) + 0.4), f"Up to {mx:.0f} reloads running at once "
                               f"(usually up to {usual:.0f})", cw.idxmax(), "Scheduler task runs"))
            elif mx <= max(3, usual):
                out.append(_ev("reload_pileup", -0.5, f"Reloads normal: at most {mx:.0f} at once", None, "Scheduler task runs"))
        ex = TE[(TE["Status"] != "Skipped") & (TE["start"] < b) & (TE["stop"] > a)].copy()
        if len(ex):
            med = TE[TE["Status"] != "Skipped"].groupby("TaskName")["dur_s"].median()
            ex["med"] = ex["TaskName"].map(med)
            long = ex[(ex["dur_s"] >= np.maximum(300, 5 * ex["med"]))]
            if len(long):
                r0 = long.sort_values("dur_s").iloc[-1]
                out.append(_ev("reload_long", min(1.0, 0.4 + len(long) / 5), f"{len(long)} unusually long reload(s) over the window, "
                               f"longest {r0['TaskName']} ({r0['dur_s'] / 60:.0f} min, usually {r0['med']:.0f}s)", r0["start"],
                               "Scheduler task runs"))
    if failures is not None and len(failures):
        fw = failures[(failures["start"] >= a - pd.Timedelta(minutes=30)) & (failures["start"] <= b)]
        if len(fw):
            apps_ = ", ".join(sorted({x for x in fw["app"] if x})[:4])
            out.append(_ev("reload_failed", min(1.0, 0.5 + len(fw) / 6), f"{len(fw)} failed reload(s) around the time ({apps_})",
                           fw["start"].min(), "Scheduler / reload logs", str(fw["error"].iloc[0])[:160]))

    # --- requests, suspends, security lookups --------------------------------------------------
    R_ = qe.engine_requests({k: _slice(v, *inc.context) for k, v in data.items() if v is not None and "ts" in v})
    if R_ is not None and len(R_):
        rw = R_[(R_["ts"] >= a) & (R_["ts"] <= b)]
        if len(rw):
            storms = qe.session_storms(rw, st["storm"])
            if len(storms):
                s0 = storms.iloc[0]
                out.append(_ev("storm", 1, f"Request storm: {s0['user']} on {s0['app']} (up to {s0['peak_per_s'] * 60:,.0f} "
                               f"requests a minute, {int(s0['requests']):,} in all)", s0["start"], "Engine audit log"))
            else:
                pm = rw.set_index("ts").resample("1min").size()
                out.append(_ev("storm", -0.4, f"No request storm (peak {int(pm.max()):,} requests a minute)", None, "Engine audit log"))
    if Y is not None and len(Y):
        yw = _slice(Y, a, b)
        if yw is not None and len(yw):
            win_min = max((b - a).total_seconds() / 60, 1)
            sus = yw["Message"].astype(str).str.contains("suspend", case=False, regex=False).sum() / win_min
            base_y = Y[(Y["ts"] >= inc.context[0]) & (Y["ts"] <= inc.context[1]) & ~((Y["ts"] >= a) & (Y["ts"] <= b))]
            bmin = max((inc.context[1] - inc.context[0] - (b - a)).total_seconds() / 60, 1)
            bsus = base_y["Message"].astype(str).str.contains("suspend", case=False, regex=False).sum() / bmin
            if sus >= 1 and sus >= 2 * max(bsus, 0.2):
                out.append(_ev("suspends", min(1.0, sus / max(bsus, 0.5) / 4), f"{sus:.1f} app suspends a minute (usually {bsus:.1f})",
                               None, "Engine system log"))
            qrs_n = yw["Message"].astype(str).str.startswith("QrsSecurityManagement").sum() / win_min
            bq = base_y["Message"].astype(str).str.startswith("QrsSecurityManagement").sum() / bmin
            if qrs_n >= 5 and qrs_n >= 2 * max(bq, 1):
                out.append(_ev("security_lookups", min(1.0, qrs_n / max(bq, 1) / 4), f"{qrs_n:.0f} security-rule lookups a minute "
                               f"(usually {bq:.0f})", None, "Engine system log"))

    # --- one app -----------------------------------------------------------------------------
    S = data.get("session")
    sw = _slice(S, a, b)
    if sw is not None and len(sw) and sw["cpu_s"].sum() > 0:
        by = sw.groupby("app")["cpu_s"].sum().sort_values(ascending=False)
        share = by.iloc[0] / by.sum()
        if share >= 0.6 and len(by) >= 2:
            out.append(_ev("one_app", min(1.0, share), f"{by.index[0]} used {share * 100:.0f}% of session CPU in the window", None,
                           "Engine session log"))
    if inc.apps and failures is not None and len(failures):
        hit = failures[failures["app"].str.lower().isin([x.lower() for x in inc.apps])]
        if len(hit):
            out.append(_ev("one_app", 0.8, f"The affected app has {len(hit)} failed reload(s) in the logs read", hit["start"].max(),
                           "Scheduler / reload logs", str(hit["error"].iloc[0])[:160]))

    # --- events already detected (unless the same thing was measured directly above) -----------
    measured = {e["signal"] for e in out}
    if events is not None and len(events):
        ov = qe.overlapping(events, a, b, 10)
        ov = ov[(ov["end"] - ov["start"]) <= pd.Timedelta(days=1)] if len(ov) else ov
        for _, e in ov.head(12).iterrows():
            if any(sg in measured for sg in R.EVENT_DUPLICATES.get(e["category"], [])):
                continue
            if e["category"] in R.EVENT_MAP:
                out.append(dict(_ev("events", 1, f"Event: {e['title']}", e["start"], e.get("source", "")), category=e["category"]))

    # --- what the reporter told us ------------------------------------------------------------
    if inc.replicated == "Yes":
        out.append(_ev("replicated", 1, "The problem could be reproduced", None, "Report"))
    elif inc.replicated == "No":
        out.append(_ev("replicated", -1, "The problem could not be reproduced (transient)", None, "Report"))
    if inc.users_affected >= 5:
        out.append(_ev("many_users", min(1.0, inc.users_affected / 20 + 0.3), f"{inc.users_affected} users affected", None, "Report"))
    elif inc.users_affected == 1:
        out.append(_ev("many_users", -0.6, "One user affected", None, "Report"))

    # --- coverage and 'nothing found' ---------------------------------------------------------
    if cov is not None:
        c = cov["score"]
        out.append(_ev("coverage_poor", 1 - 2 * c if c < 0.5 else -(c - 0.5) * 1.2,
                       f"Log coverage of the window: {c * 100:.0f}%", None, "Coverage check"))
    if not any(e["value"] > 0.3 for e in out if e["signal"] not in ("coverage_poor", "replicated", "many_users")):
        out.append(_ev("nothing_abnormal", 1, "Nothing abnormal found in the loaded logs for this window", None, "All logs"))
    return out


# ----------------------------------------------------------------------------------------------
# 3. Scoring
# ----------------------------------------------------------------------------------------------
def score(ev: list[dict], inc: Incident, coverage_score: float | None = None) -> list[dict]:
    """Ranked hypotheses: probability (heuristic), band, supporting / contradicting evidence, factor breakdown.

    Per hypothesis, each signal counts once (its strongest supporting and strongest contradicting item; detected
    events count once per category). The evidence sum is softened by R.TEMPERATURE and, for everything except
    'not enough data', by how well the logs cover the window."""
    cov_k = 1.0 if coverage_score is None else (R.COVERAGE_FLOOR + (1 - R.COVERAGE_FLOOR) * max(0.0, min(1.0, coverage_score)))
    sym = R.SYMPTOM_PRIORS.get(inc.symptom, {})
    err_hits = [(rx, mult, why) for rx, mult, why in R.ERROR_TEXT if inc.error_text and re.search(rx, inc.error_text, re.I)]
    res = []
    for h in R.HYPOTHESES:
        hid = h["id"]
        prior = h["prior"]
        m_sym = sym.get(hid, 1.0)
        m_err = math.prod(mult.get(hid, 1.0) for _, mult, _ in err_hits) if err_hits else 1.0
        sup, con = [], []
        best_pos, best_neg = {}, {}
        for e in ev:
            if e["signal"] == "events":
                w = R.EVENT_MAP.get(e.get("category", ""), {}).get(hid, 0.0)
                grp = "events:" + e.get("category", "")
            else:
                w = R.WEIGHTS.get(e["signal"], {}).get(hid, 0.0)
                grp = e["signal"]
            if not w or not e["value"]:
                continue
            c = w * e["value"]
            item = dict(e, weight=w, contribution=c)
            (sup if c > 0 else con).append(item)
            if c > 0:
                best_pos[grp] = max(best_pos.get(grp, 0.0), c)
            else:
                best_neg[grp] = min(best_neg.get(grp, 0.0), c)
        ev_pos = sum(best_pos.get(k, 0.0) for k in best_pos if k.startswith("events:"))
        logit = sum(v for k, v in best_pos.items() if not k.startswith("events:")) + min(ev_pos, R.EVENTS_CAP) \
            + sum(best_neg.values())
        logit *= R.TEMPERATURE * (1.0 if hid == "no_data" else cov_k)
        raw = prior * m_sym * m_err * math.exp(max(-8.0, min(8.0, logit)))
        res.append({"id": hid, "title": h["title"], "prior": prior, "symptom_x": m_sym, "error_x": m_err, "evidence_sum": logit,
                    "raw": raw, "support": sorted(sup, key=lambda x: -x["contribution"]),
                    "contra": sorted(con, key=lambda x: x["contribution"]), "checks": h["checks"], "raise": h["raise"],
                    "lower": h["lower"], "error_why": [why for _, mult, why in err_hits if hid in mult]})
    tot = sum(r["raw"] for r in res) or 1.0
    for r in res:
        r["p"] = r["raw"] / tot
        r["role"] = "cause"
    # an engine restart seen in the data: it gets at least RESTART_FLOOR, and what may have led to it is shown as
    # an upstream cause of the restart instead of competing with it
    sig_n = max((int(e.get("restart_n", 0)) for e in ev if e["signal"] == "restart_signature" and e["value"] > 0), default=0)
    if sig_n >= R.RESTART["event_min_signals"]:
        floor = R.RESTART_FLOOR.get(min(sig_n, max(R.RESTART_FLOOR)), 0.0)
        rr = next(r for r in res if r["id"] == "engine_restart")
        if rr["p"] < floor:
            rest = 1 - rr["p"]
            for r in res:
                r["p"] = floor if r is rr else r["p"] * (1 - floor) / rest if rest else 0.0
            rr["floor"] = floor
        for r in res:
            if r["id"] in R.RESTART_UPSTREAM:
                r["role"] = "upstream"
    for r in res:
        r["band"] = "High" if r["p"] >= R.BANDS["High"] else "Medium" if r["p"] >= R.BANDS["Medium"] else "Low"
        thin = coverage_score is not None and coverage_score < R.HIGH_NEEDS_COVERAGE
        direct = r["id"] == "engine_restart" and sig_n >= R.RESTART["strong_signals"]
        if r["band"] == "High" and thin and r["id"] != "no_data" and not direct:
            r["band"] = "Medium"          # never 'High' on thin data (a strong restart signature is read from the data itself)
    return sorted(res, key=lambda r: -r["p"])


# ----------------------------------------------------------------------------------------------
# 4. Incident note
# ----------------------------------------------------------------------------------------------
def note(inc: Incident, cov: dict, ranked: list[dict], tz_text: str, top: int = 3, restart: dict | None = None) -> str:
    a, b = inc.window
    lines = [f"**Incident note: {inc.symptom if inc.symptom != 'Not sure' else 'reported problem'}"
             + (f" in {', '.join(inc.apps)}" if inc.apps else "") + "**", "",
             f"- Reported: {inc.reported:%a %d %b %Y %H:%M} ({tz_text})" + (f" by {inc.reporter}" if inc.reporter else ""),
             f"- Investigated: {a:%H:%M} – {b:%H:%M}" + (f" (started around {inc.started:%H:%M})" if inc.started is not None else "")]
    if inc.error_text:
        lines.append(f"- Error shown: `{inc.error_text.strip()[:200]}`")
    if inc.users_affected:
        lines.append(f"- Users affected: {inc.users_affected}; reproducible: {inc.replicated.lower()}")
    lines.append(f"- Log coverage: {cov['score'] * 100:.0f}%" + (" — " + "; ".join(cov["warnings"][:2]) if cov["warnings"] else ""))
    lines += ["", "**Likely causes (heuristic estimate from the logs, not a confirmed cause):**"]
    main = [r for r in ranked if r.get("role", "cause") == "cause"]
    for i, r in enumerate(main[:top], 1):
        lines.append(f"{i}. {r['title']} — {r['band']} ({r['p'] * 100:.0f}%)")
        for s in r["support"][:3 if not restart or r["id"] != "engine_restart" else 7]:
            lines.append(f"   - consistent with: {s['text'].lstrip('· ')}" + (f" ({s['ts']:%H:%M}, {s['source']})" if s["ts"] is not None else f" ({s['source']})"))
        for s in r["contra"][:1]:
            lines.append(f"   - against: {s['text']}")
    if restart:
        sg = restart["sig"]
        lines += ["", f"**Engine restart {sg['start']:%H:%M:%S}–{sg['end']:%H:%M:%S}: what may have caused it** "
                      "(ranked by what the logs are consistent with):"]
        for i, c in enumerate(restart["ranked"], 1):
            lines.append(f"{i}. {c['title']} — {c['verdict']}")
            for f_ in c["for"][:3]:
                lines.append(f"   - consistent with: {f_}")
        lines.append(f"- {restart['insufficient']}")
        up = [u for u in restart.get("upstream", []) if u["seen"]]
        if up:
            lines.append("- Possible upstream causes, from the hour before (what may have led to the restart, not "
                         "alternatives to it): " + "; ".join(f"{u['title']} ({u['seen'][0]})" for u in up[:4]) + ".")
    lines += ["", "**Recommended checks:**"]
    seen = set()
    first = restart["checks"] if restart else []
    for c in first + [c for r in main[:2] if not (restart and r["id"] == "engine_restart") for c in r["checks"][:2]]:
        if c not in seen:
            seen.add(c)
            lines.append(f"- {c}")
    if inc.notes:
        lines += ["", f"Notes: {inc.notes.strip()[:400]}"]
    lines += ["", "_From the Qlik Server Event Manager's Incident Investigator: a lead to follow, not proof._"]
    return "\n".join(lines)

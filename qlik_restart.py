"""Engine restart signature: where the Qlik engine went down and came back, read from its performance log.

A restart shows as several things at once (within a couple of minutes, or the next sample when the log samples every
5 minutes):

    collapse  engine CPU and active users / document sessions fall to near zero from a real load
    memory    engine memory falls by more than ~70% (or to near zero) and then builds up again
    cache     the cache hit rate jumps to ~100% straight after (seen on a real restart; Qlik defines a hit as a lookup that found
              something already cached, so why a fresh engine reads 100% isn't documented)
    gap       the performance log went quiet for more than a few minutes just before (the engine may have stalled)
    process   a new engine process (ProcessId or 'Server Started' changed), when the log has those columns

The more of these hold, the stronger the finding; one alone is weak. A partial memory drop with no drop in users is a
cache purge, not a restart, and is not picked up. Thresholds live in incident_rules.RESTART.

The performance log shows *that* the engine restarted, not *why*. causes() ranks the possible causes by what else the
loaded logs show and says, for each, what would confirm it. Read-only; no Streamlit code here.
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd

import incident_rules as R
import site_config

SIGNALS = {   # key -> short label (in the order they're shown)
    "collapse": "CPU and users to zero",
    "memory": "Memory fell and rebuilt",
    "cache": "Cache hit ~100% after",
    "gap": "Data gap just before",
    "process": "New engine process",
}
COLS = ["id", "host", "start", "end", "n", "strength", "signals", "texts", "users_before", "users_after", "users_lost",
        "docs_before", "cpu_before", "cpu_after", "vm_before", "vm_low", "vm_settled", "rebuilt", "cache_after",
        "gap_start", "gap_end", "gap_min", "pid_before", "pid_after", "engine_started", "old_started", "entry_types",
        "recovered_at", "recovery_min"]

# detected event categories that count as load building up before a restart -> the upstream hypothesis they support
LOAD_CATEGORIES = {"Request storm": "engine_overload", "App refresh churn": "engine_overload", "Request volume": "engine_overload",
                   "Reload pile-up": "reload_pileup", "Reload overlap": "reload_pileup", "Slow reload": "reload_pileup",
                   "Reload load": "reload_pileup", "Engine CPU": "cpu", "Server CPU": "cpu", "Memory": "memory"}
_SHUTDOWN = re.compile(r"(?i)shutting down|\bshut ?down\b|stopping (?:the )?(?:engine|service|server)|"
                       r"(?:engine|service|server) (?:is )?stopp(?:ing|ed)|received (?:a )?stop|\bexiting\b")
_STARTUP = re.compile(r"(?i)(?:engine|service|server)\b.{0,40}\b(?:starting|started|start-?up|initiali[sz]|ready)|"
                      r"\b(?:starting|started)\b.{0,40}\b(?:engine|service|server)\b|listening on")
_NO_ENGINE = re.compile(r"(?i)no engine|NoEngineAvailable|Retrieved 0 engine|engine.{0,30}(?:unavailable|not available|"
                        r"not respond|unreachable|timed? ?out)|failed to connect.{0,40}4747")
_SVC_RESTART = re.compile(r"(?i)engine.{0,60}(?:restart|re-start|recover|not respond|stopped unexpectedly)|"
                          r"(?:restart|recover)\w*.{0,60}engine")
# Qlik's own words. The engine writes these itself when its watchdog restarts a hung engine, or when it restarts after an
# internal error (Qlik Community threads 1836385 and 133260 quote them from System.Engine.Engine). Not in Qlik's help pages.
_ABORT = re.compile(r"(?i)Reason for restart|Phoenix detected|Server Watchdog|Server aborted|trying to recover by restart")
_ABORT_HANG = re.compile(r"(?i)watchdog|hung|stuck|not respond|performance monitor|document purger")
_ABORT_ERROR = re.compile(r"(?i)inconsisten|general exception|internal error")
_STUCK = re.compile(r"(?i)Request stuck report|Waiting on monitor|stall detected")
_DUMP = re.compile(r"(?i)core ?dump|crash ?dump|\.dmp\b")
_WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def cfg(overrides: dict | None = None) -> dict:
    return {**R.RESTART, **(overrides or {})}


def _num(g: pd.DataFrame, col: str) -> np.ndarray:
    if col not in g:
        return np.full(len(g), np.nan)
    return pd.to_numeric(g[col], errors="coerce").to_numpy(dtype=float)


def _nanmax(*xs) -> float:
    v = [x for x in xs if x is not None and not np.isnan(x)]
    return max(v) if v else np.nan


def _fmt_gb(x) -> str:
    return "?" if x is None or pd.isna(x) else (f"{x:.1f}" if x < 10 else f"{x:.0f}")


# ----------------------------------------------------------------------------------------------
# Finding restarts
# ----------------------------------------------------------------------------------------------
def find(P: pd.DataFrame | None, overrides: dict | None = None) -> pd.DataFrame:
    """Every restart signature in an engine performance frame (qlik_logs.prep_performance), weak ones included.
    One row per restart: when, which signals held (and the numbers behind them), users lost and recovery time."""
    c = cfg(overrides)
    if P is None or P.empty or "ts" not in P:
        return pd.DataFrame(columns=COLS)
    rows = []
    hosts = P.groupby("Hostname", dropna=False) if "Hostname" in P and P["Hostname"].notna().any() else [("", P)]
    for host, g in hosts:
        g = g.dropna(subset=["ts"]).sort_values("ts").reset_index(drop=True)
        if len(g) < 2:
            continue
        rows += _find_host(str(host or ""), g, c)
    out = pd.DataFrame(rows, columns=COLS)
    return out.sort_values("start").reset_index(drop=True) if len(out) else out


def _find_host(host: str, g: pd.DataFrame, c: dict) -> list[dict]:
    n = len(g)
    ts = g["ts"].reset_index(drop=True)
    tsv = ts.to_numpy()
    cpu, users, docs = _num(g, "CPULoad"), _num(g, "ActiveUsers"), _num(g, "ActiveDocSessions")
    vm, cache = _num(g, "VM_GB"), _num(g, "cache_hit_pct")
    load = np.fmax(users, docs)                        # whichever of users / document sessions the log has
    step = ts.diff().median()
    step = step if pd.notna(step) and step > pd.Timedelta(0) else pd.Timedelta(minutes=5)
    pid = g["ProcessId"].astype(str).str.strip().replace({"nan": "", "None": ""}).to_numpy() if "ProcessId" in g else None
    started = g["server_started"].to_numpy() if "server_started" in g else None
    etype = g["Entry Type"].astype(str).to_numpy() if "Entry Type" in g else None

    def proc_changed(i: int) -> bool:
        if pid is not None and pid[i] and pid[i - 1] and pid[i] != pid[i - 1]:
            return True
        if started is not None and not pd.isna(started[i]) and not pd.isna(started[i - 1]) and started[i] != started[i - 1]:
            return True
        return False

    def collapse_at(i: int) -> bool:
        prev, cur = load[i - 1], load[i]
        if np.isnan(prev) or np.isnan(cur) or prev < c["min_users_before"]:
            return False
        if cur > max(c["near_zero_users"], 0.1 * prev):
            return False
        return not (cpu[i] > c["near_zero_cpu"])          # NaN CPU doesn't rule it out

    def mem_drop_at(i: int) -> bool:
        vb = np.nanmax(vm[max(0, i - 2):i]) if i > 0 and not np.all(np.isnan(vm[max(0, i - 2):i])) else np.nan
        if np.isnan(vb) or np.isnan(vm[i]) or vb < c["vm_min_before_gb"]:
            return False
        if not np.isnan(vm[i - 1]) and vm[i] >= 0.9 * vm[i - 1]:
            return False                                   # the fall happened earlier, not at this sample
        return vm[i] <= vb * (1 - c["vm_drop_pct"] / 100) or vm[i] <= c["vm_near_zero_gb"]

    anchors = [i for i in range(1, n) if collapse_at(i) or mem_drop_at(i) or proc_changed(i)]
    if not anchors:
        return []
    clusters, cur_ = [], [anchors[0]]
    for i in anchors[1:]:
        if ts[i] - ts[cur_[-1]] <= pd.Timedelta(minutes=c["pair_within_min"]):
            cur_.append(i)
        else:
            clusters.append(cur_)
            cur_ = [i]
    clusters.append(cur_)

    out = []
    for cl in clusters:
        i0, i1 = cl[0], cl[-1]
        before, after = i0 - 1, i1
        look = min(n, i1 + 2)                          # the drop can show in the sample after the first sign
        sig, texts = [], []
        t_before, t_after = ts[before], ts[after]
        # users before: the most in the 20 minutes up to the last sample before the drop
        recent = (tsv >= np.datetime64(t_before - pd.Timedelta(minutes=20))) & (tsv <= np.datetime64(t_before))
        u_before = float(np.nanmax(load[recent])) if np.any(~np.isnan(load[recent])) else np.nan
        u_users_before = float(np.nanmax(users[recent])) if np.any(~np.isnan(users[recent])) else u_before
        d_before = float(np.nanmax(docs[recent])) if np.any(~np.isnan(docs[recent])) else np.nan
        seg = slice(i0, look)
        u_after = float(np.nanmin(load[seg])) if np.any(~np.isnan(load[seg])) else np.nan
        uu_after = float(np.nanmin(users[seg])) if np.any(~np.isnan(users[seg])) else u_after
        cpu_after = float(np.nanmin(cpu[seg])) if np.any(~np.isnan(cpu[seg])) else np.nan
        cpu_before = float(np.nanmax(cpu[max(0, before - 2):before + 1])) if np.any(~np.isnan(cpu[max(0, before - 2):before + 1])) else np.nan
        # 1. collapse
        if (not np.isnan(u_before) and u_before >= c["min_users_before"] and not np.isnan(u_after)
                and u_after <= max(c["near_zero_users"], 0.1 * u_before) and not (cpu_after > c["near_zero_cpu"])):
            sig.append("collapse")
            who = (f"active users {u_users_before:.0f} → {uu_after:.0f}" if not np.isnan(u_users_before) and not np.isnan(uu_after)
                   else f"users {u_before:.0f} → {u_after:.0f}")
            if not np.isnan(d_before):
                d_after = float(np.nanmin(docs[seg])) if np.any(~np.isnan(docs[seg])) else np.nan
                if not np.isnan(d_after):
                    who += f", document sessions {d_before:.0f} → {d_after:.0f}"
            cpu_txt = f", engine CPU {cpu_before:.0f}% → {cpu_after:.0f}%" if not np.isnan(cpu_after) and not np.isnan(cpu_before) else ""
            texts.append(f"Fell to near zero together: {who}{cpu_txt} ({t_before:%H:%M:%S} → {t_after:%H:%M:%S})")
        # 2. memory fell and rebuilt
        vwin = vm[max(0, before - 2):before + 1]
        vb = float(np.nanmax(vwin)) if np.any(~np.isnan(vwin)) else np.nan
        vlow = float(np.nanmin(vm[seg])) if np.any(~np.isnan(vm[seg])) else np.nan
        later = (tsv > np.datetime64(t_after)) & (tsv <= np.datetime64(t_after + pd.Timedelta(minutes=c["rebuild_within_min"])))
        vlater = vm[later]
        rebuilt = bool(len(vlater) and np.any(~np.isnan(vlater)) and not np.isnan(vlow)
                       and np.nanmax(vlater) >= max(vlow * 2, vlow + 5, 0.2 * vb if not np.isnan(vb) else 0))
        settle = (tsv >= np.datetime64(t_after + pd.Timedelta(minutes=30))) & (tsv <= np.datetime64(t_after + pd.Timedelta(minutes=60)))
        vset = float(np.nanmedian(vm[settle])) if np.any(~np.isnan(vm[settle])) else (
            float(vlater[~np.isnan(vlater)][-1]) if len(vlater) and np.any(~np.isnan(vlater)) else np.nan)
        if (not np.isnan(vb) and not np.isnan(vlow) and vb >= c["vm_min_before_gb"]
                and (vlow <= vb * (1 - c["vm_drop_pct"] / 100) or vlow <= c["vm_near_zero_gb"])):
            sig.append("memory")
            drop = (1 - vlow / vb) * 100
            texts.append(f"Engine memory fell {drop:.0f}% ({_fmt_gb(vb)} → {_fmt_gb(vlow)} GB)"
                         + (f" and built up again to about {_fmt_gb(vset)} GB" if rebuilt else
                            " (no later samples to show it building up again)" if not len(vlater) else " and stayed low"))
        # 3. cache hit ~100% straight after, from a lower level before
        ca = cache[after:min(n, after + 2)]
        c_after = float(np.nanmax(ca)) if np.any(~np.isnan(ca)) else np.nan
        cb_win = cache[max(0, before - 6):before + 1]
        c_before = float(np.nanmedian(cb_win)) if np.any(~np.isnan(cb_win)) else np.nan
        if not np.isnan(c_after) and c_after >= c["cache_full_pct"] and (np.isnan(c_before) or c_before < c["cache_full_pct"] - 2):
            sig.append("cache")
            texts.append(f"Cache hit rate {c_after:.0f}% straight after" + (f" (about {c_before:.0f}% before)" if not np.isnan(c_before) else "")
                         + ": what a freshly started engine has shown")
        # 4. data gap just before (the interval into the last sample before, or across the drop itself)
        gap_s = gap_e = None
        gap_m = 0.0
        for k in (before, after):
            if k >= 1:
                dt = ts[k] - ts[k - 1]
                if dt >= pd.Timedelta(minutes=c["gap_min"]) and dt >= step * 1.8 and dt.total_seconds() / 60 > gap_m:
                    gap_s, gap_e, gap_m = ts[k - 1], ts[k], dt.total_seconds() / 60
        if gap_s is not None:
            sig.append("gap")
            texts.append(f"No performance samples for {gap_m:.0f} min just before ({gap_s:%H:%M}–{gap_e:%H:%M}): the engine may have stalled")
        # 5. new engine process
        pchg = any(proc_changed(i) for i in range(i0, look) if i >= 1)
        p_before = pid[before] if pid is not None else ""
        p_after = pid[after] if pid is not None else ""
        e_started = pd.Timestamp(started[after]) if started is not None and not pd.isna(started[after]) else pd.NaT
        o_started = pd.Timestamp(started[before]) if started is not None and not pd.isna(started[before]) else pd.NaT
        if pchg:
            sig.append("process")
            bits = []
            if p_before and p_after and p_before != p_after:
                bits.append(f"process {p_before} → {p_after}")
            if pd.notna(e_started):
                bits.append(f"new engine started {e_started:%H:%M:%S}")
            if pd.notna(o_started) and o_started != e_started:
                up = (t_before - o_started).total_seconds() / 86400
                bits.append(f"the old one had run since {o_started:%a %d %b %H:%M} ({up:.1f} days)")
            texts.append("New engine process" + (f" ({', '.join(bits)})" if bits else ""))
        if not sig:
            continue
        # entry types other than Normal around the drop (Qlik can write start / stop entries)
        et = []
        if etype is not None:
            et = sorted({x for x in etype[max(0, before - 1):look] if x and x.lower() not in ("normal", "nan", "")})
        # recovery: users back to half of what was there
        rec_at, rec_min = pd.NaT, np.nan
        if not np.isnan(u_before) and u_before >= 2:
            back = (tsv > np.datetime64(t_after)) & (load >= max(1.0, 0.5 * u_before))
            if back.any():
                rec_at = ts[int(np.argmax(back))]
                rec_min = (rec_at - t_after).total_seconds() / 60
        k = len(sig)
        strength = "Strong" if k >= c["strong_signals"] else "Probable" if k >= c["event_min_signals"] else "Weak"
        lost = (u_users_before - uu_after) if not (np.isnan(u_users_before) or np.isnan(uu_after)) else np.nan
        out.append({
            "id": f"{host}|{t_before:%Y%m%d%H%M%S}", "host": host, "start": t_before, "end": t_after, "n": k,
            "strength": strength, "signals": sig, "texts": texts, "users_before": u_users_before, "users_after": uu_after,
            "users_lost": max(0.0, lost) if not np.isnan(lost) else np.nan, "docs_before": d_before,
            "cpu_before": cpu_before, "cpu_after": cpu_after, "vm_before": vb, "vm_low": vlow, "vm_settled": vset,
            "rebuilt": rebuilt, "cache_after": c_after, "gap_start": gap_s, "gap_end": gap_e, "gap_min": gap_m or np.nan,
            "pid_before": p_before, "pid_after": p_after, "engine_started": e_started, "old_started": o_started,
            "entry_types": et,
            "recovered_at": rec_at, "recovery_min": rec_min})
    return out


def restarts(sigs: pd.DataFrame, min_signals: int | None = None) -> pd.DataFrame:
    """Only the probable and strong ones (what gets raised as an event)."""
    k = R.RESTART["event_min_signals"] if min_signals is None else min_signals
    return sigs[sigs["n"] >= k] if sigs is not None and len(sigs) else pd.DataFrame(columns=COLS)


def engine_starts(P: pd.DataFrame | None) -> pd.DataFrame:
    """Every engine start the log records in its 'Server Started' column (one per engine process), with the first and
    last sample seen from it. This catches restarts even where the samples around them weren't loaded."""
    cols = ["host", "started", "pid", "first_seen", "last_seen"]
    if P is None or P.empty or "server_started" not in P:
        return pd.DataFrame(columns=cols)
    g = P.dropna(subset=["server_started"]).copy()
    if g.empty:
        return pd.DataFrame(columns=cols)
    g["host"] = g["Hostname"].astype(str) if "Hostname" in g else ""
    g["pid"] = g["ProcessId"].astype(str) if "ProcessId" in g else ""
    out = g.groupby(["host", "server_started"], as_index=False).agg(pid=("pid", "first"), first_seen=("ts", "min"),
                                                                   last_seen=("ts", "max"))
    return out.rename(columns={"server_started": "started"})[cols].sort_values("started").reset_index(drop=True)


def usual_slot(starts: pd.DataFrame, exclude=None, tol_min: int = 20) -> dict | None:
    """The weekday and time the engine usually starts at (2+ starts within tol_min of each other on the same weekday),
    leaving out `exclude` (the restart being looked at). None when there's no such slot."""
    if starts is None or starts.empty:
        return None
    t = starts["started"]
    if exclude is not None and pd.notna(exclude):
        t = t[(t - pd.Timestamp(exclude)).abs() > pd.Timedelta(minutes=10)]
    best = None
    for x in t:
        m = x.hour * 60 + x.minute
        same = t[(t.dt.day_of_week == x.day_of_week)
                 & ((t.dt.hour * 60 + t.dt.minute - m).abs() <= tol_min)]
        if len(same) >= 2 and (best is None or len(same) > best["count"]):
            best = {"weekday": _WEEKDAYS[x.day_of_week], "time": f"{x:%H:%M}", "count": len(same),
                    "dates": [f"{d:%d %b}" for d in same]}
    return best


def in_slot(ts_, slot: dict | None, tol_min: int = 20) -> bool:
    if not slot or ts_ is None or pd.isna(ts_):
        return False
    t = pd.Timestamp(ts_)
    h, m = map(int, slot["time"].split(":"))
    return _WEEKDAYS[t.day_of_week] == slot["weekday"] and abs(t.hour * 60 + t.minute - (h * 60 + m)) <= tol_min


def in_window(sigs: pd.DataFrame, a, b, lookback_min: int | None = None) -> pd.DataFrame:
    """Restarts overlapping [a - lookback, b] (a restart shortly before the window still explains a later report),
    strongest first."""
    if sigs is None or sigs.empty:
        return pd.DataFrame(columns=COLS)
    lb = pd.Timedelta(minutes=R.RESTART["lookback_min"] if lookback_min is None else lookback_min)
    hit = sigs[(sigs["end"] >= pd.Timestamp(a) - lb) & (sigs["start"] <= pd.Timestamp(b))]
    return hit.sort_values(["n", "start"], ascending=[False, True]).reset_index(drop=True)


def headline(s) -> str:
    users = f"{s['users_lost']:.0f} users lost" if pd.notna(s["users_lost"]) else "users not in the log"
    return (f"Engine restart {s['start']:%a %d %b %H:%M:%S}–{s['end']:%H:%M:%S} · {users} · "
            f"{s['strength'].lower()} signature ({s['n']} of {len(SIGNALS)} signals)")


def recovery_text(s) -> str:
    if pd.notna(s["recovery_min"]):
        return f"users back to half ({0.5 * s['users_before']:.0f}) by {s['recovered_at']:%H:%M} ({s['recovery_min']:.0f} min)"
    if pd.notna(s["users_before"]) and s["users_before"] >= 2:
        return "users not back to half in the loaded data"
    return "no users on before"


# ----------------------------------------------------------------------------------------------
# What led to it: possible causes, ranked by what the loaded logs show
# ----------------------------------------------------------------------------------------------
def _slice(df, a, b, col="ts"):
    if df is None or df.empty or col not in df:
        return None
    return df[(df[col] >= a) & (df[col] <= b)]


def context(s, data: dict, events: pd.DataFrame | None = None, settings: dict | None = None,
            history: pd.DataFrame | None = None) -> dict:
    """Facts around one restart that bear on its cause."""
    st = {"cpu_warn": 60, "ram_gb": site_config.SERVER_RAM_GB, "low_pct": 70}
    st.update(settings or {})
    c = cfg()
    data = data or {}
    start, end = pd.Timestamp(s["start"]), pd.Timestamp(s["end"])
    pre_a = start - pd.Timedelta(minutes=60)
    load = []                                           # (text, ts, source, upstream hypothesis id)
    P = data.get("performance")
    x = _slice(P, pre_a, start)
    if x is not None and len(x) and "CPULoad" in x and x["CPULoad"].notna().any():
        pk = float(x["CPULoad"].max())
        if pk >= st["cpu_warn"]:
            load.append((f"Engine CPU up to {pk:.0f}% in the hour before", x.loc[x["CPULoad"].idxmax(), "ts"], "Engine performance log", "cpu"))
    low = st["ram_gb"] * st["low_pct"] / 100
    if x is not None and len(x) and "VM_GB" in x and x["VM_GB"].notna().any():
        vm = float(x["VM_GB"].max())
        if vm >= 0.85 * low:
            word = "above" if vm > low else "near"
            load.append((f"Engine memory {vm:.0f} GB, {word} the low working-set limit ({low:.0f} GB)",
                         x.loc[x["VM_GB"].idxmax(), "ts"], "Engine performance log", "memory"))
    rp = _slice(data.get("repo_perf"), pre_a, start)
    if rp is not None and len(rp) and "machine_cpu" in rp and rp["machine_cpu"].notna().any():
        pk = float(rp["machine_cpu"].max())
        if pk >= st["cpu_warn"]:
            load.append((f"Server CPU up to {pk:.0f}% in the hour before", rp.loc[rp["machine_cpu"].idxmax(), "ts"],
                         "Repository performance log", "cpu"))
    ev_load = pd.DataFrame()
    if events is not None and len(events):
        e = events[(events["start"] <= end) & (events["end"] >= pre_a) & events["category"].isin(list(LOAD_CATEGORIES))]
        e = e[(e["end"] - e["start"]) <= pd.Timedelta(days=1)]
        ev_load = e.sort_values("start")
        seen = set()
        for _, r in ev_load.iterrows():
            if r["category"] in seen or r["category"] in ("Engine CPU", "Server CPU") and any(h == "cpu" for *_, h in load):
                continue
            if r["category"] == "Memory" and any(h == "memory" for *_, h in load):
                continue
            seen.add(r["category"])
            load.append((f"{r['title']} ({r['start']:%H:%M}–{r['end']:%H:%M})", r["start"], r.get("source", "") or "Events",
                         LOAD_CATEGORIES[r["category"]]))
    # engine system log: shutdown / start-up / error lines around the restart
    Y = data.get("system")
    sys_covers = bool(Y is not None and len(Y) and Y["ts"].min() <= start - pd.Timedelta(minutes=10) and Y["ts"].max() >= end)
    yw = _slice(Y, start - pd.Timedelta(minutes=15), end + pd.Timedelta(minutes=10))
    msg = yw["Message"].astype(str) if yw is not None and len(yw) and "Message" in yw else pd.Series(dtype=str)
    shutdown = yw[msg.str.contains(_SHUTDOWN)] if len(msg) else pd.DataFrame()
    startup = yw[msg.str.contains(_STARTUP) & (yw["ts"] >= start)] if len(msg) else pd.DataFrame()
    errors = yw[(yw["Level"].astype(str).str.upper().isin(["ERROR", "FATAL"])) & (yw["ts"] <= end)] \
        if len(msg) and "Level" in yw else pd.DataFrame()
    # proxy / other services: 'no engine', engine restart messages
    no_eng, svc = [], []
    for kind in ("proxy_audit", "svc_system", "service"):
        z = _slice(data.get(kind), start - pd.Timedelta(minutes=20), end + pd.Timedelta(minutes=5))
        if z is not None and len(z) and "Message" in z:
            m = z["Message"].astype(str)
            no_eng.append(z[m.str.contains(_NO_ENGINE)])
            if kind == "svc_system":
                svc.append(z[m.str.contains(_SVC_RESTART)])
    no_eng = pd.concat(no_eng) if no_eng else pd.DataFrame()
    svc = pd.concat(svc) if svc else pd.DataFrame()
    stop_entry = [x for x in (s.get("entry_types") or []) if re.search(r"(?i)stop|shut", x)]
    # the engine's own restart reason, any core dump it wrote, and 'stuck request' lines in the half hour before
    y2 = _slice(Y, start - pd.Timedelta(minutes=30), end + pd.Timedelta(minutes=10))
    m2 = y2["Message"].astype(str) if y2 is not None and len(y2) and "Message" in y2 else pd.Series(dtype=str)
    abort = y2[m2.str.contains(_ABORT)] if len(m2) else pd.DataFrame()
    dump = y2[m2.str.contains(_DUMP)] if len(m2) else pd.DataFrame()
    stuck = y2[m2.str.contains(_STUCK)] if len(m2) else pd.DataFrame()
    # time of day
    wd = start.weekday()
    bh = c["business_hours"]
    business = wd < 5 and bh[0] <= start.hour < bh[1]
    op = c["off_peak_hours"]
    off_peak = (start.hour >= op[0] or start.hour < op[1]) if op[0] > op[1] else (op[0] <= start.hour < op[1])
    maint = False
    for day, t1, t2 in c.get("maintenance") or []:
        if day and _WEEKDAYS.index(day[:3].title()) != wd:
            continue
        h1, h2 = pd.Timestamp(f"2000-01-01 {t1}").time(), pd.Timestamp(f"2000-01-01 {t2}").time()
        if h1 <= start.time() <= h2:
            maint = True
    # same time of day on other days (a schedule?)
    starts = engine_starts(P)
    this_start = s.get("engine_started") if pd.notna(s.get("engine_started")) else end
    slot = usual_slot(starts, exclude=this_start)
    recurring = 0
    if history is not None and len(history):
        hs = history[(history["n"] >= c["event_min_signals"]) & (history["start"].dt.date != start.date())]
        mins = start.hour * 60 + start.minute
        dm = (hs["start"].dt.hour * 60 + hs["start"].dt.minute - mins).abs()
        recurring = int((np.minimum(dm, 1440 - dm) <= 20).sum())
    if slot and in_slot(this_start, slot):
        recurring = max(recurring, slot["count"])
    return {"slot": slot, "starts": starts, "in_slot": in_slot(this_start, slot),
            "load": load, "events": ev_load, "sys_covers": sys_covers, "shutdown": shutdown, "startup": startup,
            "errors": errors, "no_engine": no_eng, "svc": svc, "stop_entry": stop_entry, "abort": abort, "dump": dump, "stuck": stuck, "business": business,
            "off_peak": off_peak, "maintenance": maint, "recurring": recurring, "low_limit": low}


def causes(s, data: dict, events: pd.DataFrame | None = None, settings: dict | None = None,
           history: pd.DataFrame | None = None) -> dict:
    """The four possible causes of one restart, ranked by simple points from what the loaded logs show.

    Each has: points, a verdict ("Plausible - not confirmed", "Possible", "Unlikely", "Can't tell from these logs"),
    the evidence for and against, and what it would take to confirm it. Nothing here can confirm a cause: the
    performance log shows that the engine restarted, not why."""
    cx = context(s, data, events, settings, history)
    c = cfg()
    gap = pd.notna(s.get("gap_min")) and s.get("gap_min", 0) > 0
    gap_txt = (f"The performance log went quiet for {s['gap_min']:.0f} min just before ({s['gap_start']:%H:%M}–{s['gap_end']:%H:%M})"
               if gap else "")
    n_load = len(cx["load"])
    ne = len(cx["no_engine"])
    clean = len(cx["shutdown"]) > 0 or bool(cx["stop_entry"])
    many = pd.notna(s.get("users_before")) and s["users_before"] >= c["min_users_before"]
    out = []
    ab = cx["abort"]
    ab_txt = str(ab["Message"].iloc[0])[:140] if len(ab) else ""
    ab_hang = bool(len(ab)) and bool(_ABORT_HANG.search(" ".join(ab["Message"].astype(str))))
    ab_err = bool(len(ab)) and bool(_ABORT_ERROR.search(" ".join(ab["Message"].astype(str))))
    STATED = "Stated in the engine log"

    # (a) stall or overload before the restart
    pts, f_, a_ = 0.0, [], []
    if ab_hang:
        pts += 3
        f_.append(f"The engine log itself gives a hang as the reason for the restart: \"{ab_txt}\"")
    if len(cx["stuck"]):
        pts += 1
        f_.append(f"{len(cx['stuck'])} 'stuck request' / 'waiting on monitor' line(s) in the engine log before it: "
                  f"{str(cx['stuck']['Message'].iloc[0])[:100]}")
    if gap:
        pts += 2
        f_.append(gap_txt + ": consistent with the engine stalling")
    for t, *_ in cx["load"][:6]:
        f_.append(t)
    pts += min(3, n_load)
    if ne:
        pts += 1
        f_.append(f"{ne} 'no engine available' style message(s) around it: the engine wasn't answering")
    if not gap and not n_load:
        a_.append("Samples were regular and no load build-up was found in the hour before")
    out.append({"id": "stall", "title": "Stall or overload before the restart (the engine hung under load, then went down)",
                "short": "Stall / overload before", "points": pts, "for": f_, "against": a_,
                "verdict": STATED if ab_hang else "Plausible – not confirmed" if pts >= 3 else "Possible" if pts >= 1 else "No sign in these logs",
                "determinable": "Partly. The logs show the silence and the load before; they can't show that these brought "
                                "the engine down. The Windows Application log (the engine reported as hung or not responding) "
                                "and the System_Engine log before the restart would."})

    # (b) crash
    pts, f_, a_ = 0.0, [], []
    if cx["sys_covers"] and not len(cx["shutdown"]):
        pts += 1
        f_.append("No shutdown lines in the engine system log around it (an orderly stop usually writes some)")
    if len(cx["errors"]):
        pts += 1
        f_.append(f"{len(cx['errors'])} ERROR line(s) in the engine system log just before: "
                  f"{str(cx['errors']['Message'].iloc[-1])[:110]}")
    if many and not clean:
        pts += 0.5
        f_.append(f"It stopped with {s['users_before']:.0f} users on and no stop entry in the performance log (abrupt)")
    if len(cx["dump"]):
        pts += 2
        f_.append(f"A core / crash dump was written: {str(cx['dump']['Message'].iloc[0])[:110]}")
    if ab_err:
        pts += 2
        f_.append(f"The engine log gives an internal error as the reason for the restart: \"{ab_txt}\"")
    if clean:
        pts -= 2
        a_.append("Shutdown lines or a stop entry were logged: that looks like an orderly stop")
    if not cx["sys_covers"]:
        a_.append("The engine system log isn't loaded for this time, so shutdown and error lines can't be checked")
    verdict = (STATED if ab_err else
               "Can't tell from these logs" if not cx["sys_covers"] and pts < 1.5 else
               "Plausible – not confirmed" if pts >= 2 else "Possible" if pts >= 0.5 else "Unlikely")
    out.append({"id": "crash", "title": "Crash (the engine process stopped abruptly)", "short": "Crash", "points": pts,
                "for": f_, "against": a_, "verdict": verdict,
                "determinable": "No. A crash shows in the Windows Application log (Application Error 1000 / Windows Error "
                                "Reporting 1001 / .NET Runtime 1026 for the engine), the System log (7031 / 7034: the "
                                "service terminated unexpectedly) and a dump file (the engine writes its own under "
                                "C:\\ProgramData\\Qlik\\Sense\\Engine\\CrashDumps)."})

    # (c) manual or scheduled restart
    pts, f_, a_ = 0.0, [], []
    if len(cx["shutdown"]):
        pts += 2
        f_.append(f"Shutdown line(s) in the engine system log: {str(cx['shutdown']['Message'].iloc[0])[:110]}")
    if cx["stop_entry"]:
        pts += 2
        f_.append("Stop entry in the performance log: " + ", ".join(cx["stop_entry"]))
    if cx["maintenance"]:
        pts += 2
        f_.append("Inside a planned maintenance window")
    elif cx["off_peak"]:
        pts += 1
        f_.append(f"Off-peak time ({pd.Timestamp(s['start']):%a %H:%M})")
    if not many:
        pts += 1
        f_.append("Few or no users were on")
    if cx["recurring"]:
        pts += 2
        f_.append(f"{cx['recurring']} other restart(s) at about the same time of day in the history: looks scheduled")
    if len(ab):
        pts -= 2
        a_.append(f"The engine log says it restarted itself: \"{ab_txt}\"")
    if cx["slot"] and not cx["in_slot"]:
        pts -= 1
        a_.append(f"The engine usually restarts on {cx['slot']['weekday']} at about {cx['slot']['time']} "
                  f"({cx['slot']['count']} times in the data); this one is outside that, so it isn't the usual scheduled restart")
    if cx["business"] and many:
        pts -= 1
        a_.append(f"Business hours ({pd.Timestamp(s['start']):%a %H:%M}) with {s['users_before']:.0f} users on: "
                  "unlikely to be planned, though someone restarting a hung engine by hand would look the same")
    if not len(cx["shutdown"]) and cx["sys_covers"]:
        a_.append("No shutdown lines in the engine system log")
    out.append({"id": "manual", "title": "Manual or scheduled restart (someone or something stopped and started it)",
                "short": "Manual / scheduled", "points": pts, "for": f_, "against": a_,
                "verdict": "Plausible – not confirmed" if pts >= 3 else "Possible" if pts >= 1 else "Unlikely",
                "determinable": "No. Needs the change / maintenance calendar, the server team, and the Windows System "
                                "log (7036 'stopped' then 'running' without a 7031 / 7034 means it was stopped on purpose)."})

    # (d) restarted automatically after it stopped responding
    pts, f_, a_ = 0.0, [], []
    if len(ab):
        pts += 3
        f_.append(f"The engine log states it restarted itself: \"{ab_txt}\"")
    if gap:
        pts += 1
        f_.append(gap_txt + " (unresponsive before it came back)")
    if ne:
        pts += 1
        f_.append(f"{ne} 'no engine available' style message(s): other Qlik services couldn't reach it")
    if len(cx["svc"]):
        pts += 2
        f_.append(f"Qlik service log mentions the engine: {str(cx['svc']['Message'].iloc[0])[:110]}")
    if cx["sys_covers"] and not clean:
        pts += 0.5
        f_.append("No orderly shutdown logged")
    if clean:
        a_.append("An orderly shutdown was logged")
    verdict = (STATED if len(ab) else "Can't tell from these logs" if pts < 1 else
               "Plausible – not confirmed" if pts >= 3 else "Possible")
    out.append({"id": "auto", "title": "Restarted automatically after it stopped responding (Qlik or Windows service recovery)",
                "short": "Auto-restart after hang", "points": pts, "for": f_, "against": a_, "verdict": verdict,
                "determinable": "Partly. If the engine log has a 'Reason for restart' line (the engine's own watchdog), that "
                                "is Qlik's own record. Otherwise it needs the Windows System log (7031 / 7034 followed by "
                                "the service starting again on its own, which is Windows service recovery) and the "
                                "Service Dispatcher log."})

    order = {"stall": 0, "crash": 1, "auto": 2, "manual": 3}
    out.sort(key=lambda r: (-r["points"], order[r["id"]]))
    return {"ranked": out, "context": cx, "confirmed": False, "upstream": upstream(s, cx),
            "insufficient": ("Insufficient data to confirm the cause. The engine log states a reason for the restart "
                             "(shown below). That is Qlik's own record, but confirm it with the Windows System log and any "
                             "dump file." if len(ab) else
                             "Insufficient data to confirm the cause. The performance log shows that the engine restarted, "
                             "not why. The ranking below says what the loaded logs are consistent with; the checks "
                             "underneath are what would confirm it."),
            "checks": checks(s)}


def upstream(s, cx: dict) -> list[dict]:
    """What may have led to the restart, from the hour before it: the investigator's load hypotheses (request storm,
    reload pile-up, CPU, memory, a stall) with what was seen for each. Shown under the restart, not as rivals to it."""
    titles = {h["id"]: h["title"] for h in R.HYPOTHESES}
    got: dict[str, list[str]] = {}
    for t, _ts, _src, hid in cx["load"]:
        got.setdefault(hid, []).append(t)
    if pd.notna(s.get("gap_min")) and s.get("gap_min", 0) > 0:
        got.setdefault("engine_down", []).append(f"No performance samples for {s['gap_min']:.0f} min just before "
                                                 f"({s['gap_start']:%H:%M}–{s['gap_end']:%H:%M})")
    if len(cx["no_engine"]):
        got.setdefault("engine_down", []).append(f"{len(cx['no_engine'])} 'no engine available' style message(s)")
    out = [{"id": h, "title": titles.get(h, h), "seen": got.get(h, [])} for h in R.RESTART_UPSTREAM]
    return sorted(out, key=lambda r: (-len(r["seen"]), R.RESTART_UPSTREAM.index(r["id"])))


def checks(s, host_hint: str = "") -> list[str]:
    """What to look at next for one restart, with its times filled in."""
    a = pd.Timestamp(s["start"]) - pd.Timedelta(minutes=10)
    b = pd.Timestamp(s["end"]) + pd.Timedelta(minutes=10)
    host = s.get("host") or host_hint or "the Qlik server"
    when = f"{a:%a %d %b} {a:%H:%M}–{b:%H:%M}"
    return [
        f"Engine\\Trace\\*_System_Engine for {a:%d %b}: search for 'Reason for restart', 'Phoenix detected' or 'Server "
        "Watchdog is hung'. The engine writes these itself when its watchdog restarts a hung engine (seen in Qlik Community "
        "threads, not in Qlik's help pages). Also 'stuck request' lines before it.",
        f"Windows Event Viewer › System log on {host}, {when}: Service Control Manager 7031 / 7034 (Qlik Sense Engine "
        "Service terminated unexpectedly) and 7036 (the service entered the stopped / running state), and 'Windows "
        "successfully diagnosed a low virtual memory condition' (Qlik Support links a stalled engine to high memory).",
        f"Windows Event Viewer › Application log, {when}: crash entries for the engine (Application Error 1000, "
        "Windows Error Reporting 1001, .NET Runtime 1026).",
        f"Engine\\Trace\\*_System_Engine for {a:%d %b}: shutdown lines before {pd.Timestamp(s['start']):%H:%M} and start-up "
        f"lines after {pd.Timestamp(s['end']):%H:%M} (an orderly shutdown points to a deliberate stop; none points to a crash or hang).",
        "The Service Dispatcher log (under C:\\ProgramData\\Qlik\\Sense\\Log; the folder name varies, so confirm it on the "
        "server) and Repository\\Trace\\*_System_Repository: the engine service stopping, starting or being restarted.",
        "Dump files (.dmp) created then: the engine's own C:\\ProgramData\\Qlik\\Sense\\Engine\\CrashDumps, Windows Error "
        "Reporting (C:\\ProgramData\\Microsoft\\Windows\\WER) and the Qlik Sense log folders.",
        f"The change / maintenance calendar and the server team: a planned restart, patching, or someone restarting the "
        f"service by hand at about {pd.Timestamp(s['start']):%H:%M}.",
        "Restart history page: search the full history for other restart signatures (Scan further back) to see whether "
        "this is a one-off or a pattern.",
    ]


# ----------------------------------------------------------------------------------------------
# History: one-off or pattern?
# ----------------------------------------------------------------------------------------------
def pattern(sigs: pd.DataFrame, span: tuple | None = None) -> str:
    """One plain sentence on whether the probable / strong restarts look like a one-off or a pattern."""
    r = restarts(sigs)
    days = ""
    if span and span[0] is not None and pd.notna(span[0]):
        d = max(1, round((pd.Timestamp(span[1]) - pd.Timestamp(span[0])).total_seconds() / 86400))
        days = f" in {d} day(s) of engine performance data"
    if r.empty:
        return f"No engine restarts found{days}."
    if len(r) == 1:
        return f"One restart{days} ({r['start'].iloc[0]:%a %d %b %H:%M}): a one-off so far. Scan further back to be sure."
    mins = (r["start"].dt.hour * 60 + r["start"].dt.minute).to_numpy()
    same = 0
    for i, m in enumerate(mins):
        dm = np.abs(mins - m)
        same = max(same, int((np.minimum(dm, 1440 - dm) <= 20).sum()))
    gaps = r["start"].sort_values().diff().dropna()
    txt = f"{len(r)} restarts{days}"
    if same >= 2:
        txt += f"; {same} of them at about the same time of day, which looks scheduled"
    bh = r[(r["start"].dt.day_of_week < 5) & r["start"].dt.hour.between(R.RESTART['business_hours'][0], R.RESTART['business_hours'][1] - 1)]
    if len(bh):
        txt += f"; {len(bh)} in business hours"
    if len(gaps):
        txt += f"; typically {gaps.median().total_seconds() / 86400:.1f} days apart"
    return txt + ". A pattern: worth raising with the server team."


def read_archive_performance(files: pd.DataFrame, days: float, reader, progress=None) -> pd.DataFrame:
    """Engine performance samples from the archive's Performance_Engine files of the last `days` days (they're small),
    for a restart history further back than what's loaded. `reader(path) -> bytes`."""
    import qlik_logs as q
    if files is None or files.empty:
        return pd.DataFrame()
    f = files[files["type"].eq("Performance_Engine")].sort_values("mtime")
    if len(f):
        f = f[f["mtime"] >= f["mtime"].max() - pd.Timedelta(days=days)]
    parts = []
    keep = ["ts", "Hostname", "ProcessId", "server_started", "Entry Type", "CPULoad", "ActiveUsers", "ActiveDocSessions",
            "VM_GB", "cache_hit_pct", "Timestamp"]
    for i, r in enumerate(f.itertuples()):
        if progress:
            progress(i / max(1, len(f)), f"Reading {r.name}")
        try:
            kind, df, _ = q.parse_log(r.name, reader(r.path))
        except Exception:  # noqa: BLE001 - one unreadable file shouldn't stop the history
            continue
        if kind == "performance" and df is not None and len(df):
            parts.append(df[[c_ for c_ in keep if c_ in df]])
    if progress:
        progress(1.0, "Done")
    if not parts:
        return pd.DataFrame()
    P = pd.concat(parts, ignore_index=True)
    return P.drop_duplicates(subset=[c_ for c_ in ("Timestamp", "Hostname") if c_ in P]).sort_values("ts").reset_index(drop=True)

"""Logins and the proxy: who logged in, how long it took, what failed, and what is hammering the proxy.

Reads the proxy's audit log (Proxy\\Audit\\*_Audit_Proxy), its trace (Proxy\\Trace\\*_System_Proxy) and its
performance counters (Proxy\\Trace\\*_Performance_Proxy). Each audit message is sorted into a kind (login, login
page shown, ticket problem, session timed out, repository connection failure, malformed request ...).
"""
from __future__ import annotations

import re

import pandas as pd

import site_config

import qlik_events as qe

KINDS = [  # (kind, label, regex on the message)
    ("login", "Logged in", r"^User '(?P<user>[^']+)' used '(?P<method>[^']+)' authentication, got session"),
    ("login_page", "Sent to the login page", r"^Authentication required, redirecting"),
    ("ticket_bad", "Ticket invalid or expired", r"^Ticket '.*' is invalid"),
    ("ticket_issued", "Ticket issued", r"^Issued ticket"),
    ("ticket_claimed", "Ticket claimed", r"^User claimed ticket"),
    ("timeout", "Session timed out", r"deleted due to inactivity"),
    ("session_invalid", "Session no longer valid", r"^Session '.*' is invalid"),
    ("session_deleted", "Session closed", r"^Session id = .* have been deleted"),
    ("logout", "Logged out", r"(?i)\blogged out\b|logout"),
    ("app_open", "App opened (engine connection)", r"^New target uri chosen: wss://"),
    ("hub", "Hub opened", r"^New target uri chosen: https://.*app: __hub"),
    ("repo_fail", "Proxy couldn't reach the repository", r"already opened client to target failed to connect"),
    ("tls", "Secure connection failed", r"Error during stream authentication"),
    ("denied", "Access denied", r"(?i)access denied|not authori[sz]ed|forbidden"),
    ("probe", "Malformed request (health check?)", r"^Bad request, malformed"),
    ("attr_sync", "User attributes synced", r"^Syncing user attributes"),
]
LABEL = {k: lab for k, lab, _ in KINDS} | {"other": "Other"}
PROBLEM = ["ticket_bad", "repo_fail", "tls", "denied"]           # counted as login problems
NOTABLE = PROBLEM + ["session_invalid"]                          # shown in the problems table
_RX = [(k, re.compile(rx)) for k, _, rx in KINDS]
_RXC = [(k, re.compile(re.sub(r"\(\?P<\w+>", "(?:", rx))) for k, _, rx in KINDS]   # same, without capture groups


def classify(pa: pd.DataFrame) -> pd.DataFrame:
    """Adds kind, user (for logins) and method to proxy audit rows."""
    if pa is None or pa.empty:
        return pd.DataFrame(columns=["ts", "kind", "user", "method", "ip", "app_id", "Message"])
    out = pa.copy()
    msg = out["Message"].astype(str)
    out["kind"] = "other"
    for k, rx in reversed(_RXC):          # first pattern in KINDS wins
        out.loc[msg.str.contains(rx, regex=True), "kind"] = k
    lg = msg.str.extract(_RX[0][1])
    out["user"] = lg["user"].fillna(out.get("ActiveUserId", pd.Series("", index=out.index)).fillna("")).astype(str)
    out["method"] = lg["method"].fillna("")
    out["ip"] = out.get("IpAddress", pd.Series("", index=out.index)).fillna("").astype(str).str.replace("::ffff:", "", regex=False)
    out["app_id"] = out.get("AppId", pd.Series("", index=out.index)).fillna("").astype(str).str.lower()
    return out


def per_hour(c: pd.DataFrame, kinds=None, freq="60min") -> pd.DataFrame:
    """Counts per hour by kind (columns are kinds)."""
    if c.empty:
        return pd.DataFrame()
    x = c[c["kind"].isin(kinds)] if kinds else c
    if x.empty:
        return pd.DataFrame()
    return x.groupby([x["ts"].dt.floor(freq), "kind"]).size().unstack(fill_value=0)


def login_times(c: pd.DataFrame, within_s: int = 300) -> pd.DataFrame:
    """Seconds from being sent to the login page to having a session, matched by IP address.

    This is the user's wait at the login screen plus the round trip to the login service; the proxy only
    logs both ends."""
    if c.empty:
        return pd.DataFrame(columns=["ts", "user", "ip", "seconds"])
    pg = c[c["kind"].eq("login_page") & c["ip"].ne("")][["ts", "ip"]].sort_values("ts")
    lg = c[c["kind"].eq("login") & c["ip"].ne("")][["ts", "ip", "user"]].sort_values("ts")
    if pg.empty or lg.empty:
        return pd.DataFrame(columns=["ts", "user", "ip", "seconds"])
    m = pd.merge_asof(lg, pg.rename(columns={"ts": "page_ts"}), left_on="ts", right_on="page_ts", by="ip",
                      direction="backward", tolerance=pd.Timedelta(seconds=within_s))
    m = m.dropna(subset=["page_ts"])
    m["seconds"] = (m["ts"] - m["page_ts"]).dt.total_seconds()
    return m[["ts", "user", "ip", "seconds"]]


def users(c: pd.DataFrame) -> pd.DataFrame:
    """Per user: logins, first and last login, addresses, apps opened, problems seen."""
    if c.empty:
        return pd.DataFrame()
    lg = c[c["kind"].eq("login")]
    if lg.empty:
        return pd.DataFrame()
    g = lg.groupby("user").agg(logins=("ts", "size"), first=("ts", "min"), last=("ts", "max"),
                               addresses=("ip", "nunique"), method=("method", lambda s: ", ".join(sorted(set(s)))))
    ao = c[c["kind"].eq("app_open") & c["user"].ne("")].groupby("user")["app_id"].nunique().rename("apps_opened")
    to = c[c["kind"].eq("timeout") & c["user"].ne("")].groupby("user").size().rename("timeouts")
    out = g.join(ao).join(to).fillna({"apps_opened": 0, "timeouts": 0})
    return out.sort_values("logins", ascending=False).reset_index()


def apps_opened(c: pd.DataFrame, names: dict | None = None) -> pd.DataFrame:
    names = {str(k).lower(): v for k, v in (names or {}).items()}
    x = c[c["kind"].eq("app_open") & c["app_id"].ne("")]
    if x.empty:
        return pd.DataFrame()
    g = x.groupby("app_id").agg(opens=("ts", "size"), users=("user", "nunique"), last=("ts", "max")).reset_index()
    g["app"] = g["app_id"].map(names).fillna("")
    return g.sort_values("opens", ascending=False)


def trace_problems(sy: pd.DataFrame) -> pd.DataFrame:
    """Warnings and errors from the proxy's own trace log, grouped by message."""
    if sy is None or sy.empty or "service" not in sy:
        return pd.DataFrame()
    x = sy[sy["service"].eq("Proxy") & sy["Level"].isin(["WARN", "ERROR", "FATAL"])]
    if x.empty:
        return pd.DataFrame()
    msg = x["Message"].astype(str).str.replace(r"[0-9a-f-]{36}", "<id>", regex=True).str.replace(r"\d+", "#", regex=True)
    ex = x["Exception"].astype(str) if "Exception" in x else ""
    g = pd.DataFrame({"ts": x["ts"], "level": x["Level"], "message": msg.str[:160], "detail": ex.str[:200] if len(ex) else ""})
    return g.groupby(["level", "message"]).agg(count=("ts", "size"), first=("ts", "min"), last=("ts", "max"),
                                               example=("detail", "first")).sort_values("count", ascending=False).reset_index()


def summary(c: pd.DataFrame, px: pd.DataFrame | None = None) -> dict:
    hrs = max((c["ts"].max() - c["ts"].min()).total_seconds() / 3600, 1 / 60) if len(c) else 0
    k = c["kind"].value_counts() if len(c) else pd.Series(dtype=int)
    lt = login_times(c)
    out = {"hours": hrs, "logins": int(k.get("login", 0)), "users": int(c.loc[c["kind"].eq("login"), "user"].nunique()) if len(c) else 0,
           "problems": int(k.reindex(PROBLEM).fillna(0).sum()), "probe": int(k.get("probe", 0)),
           "timeouts": int(k.get("timeout", 0)), "login_median_s": float(lt["seconds"].median()) if len(lt) else None,
           "login_p90_s": float(lt["seconds"].quantile(.9)) if len(lt) else None, "rows": len(c),
           "probe_share": float(k.get("probe", 0) / len(c)) if len(c) else 0.0}
    if px is not None and len(px):
        out["peak_sessions"] = float(px["ActiveSessions"].max())
        out["last_sessions"] = float(px["ActiveSessions"].iloc[-1])
    return out


def detect(d: dict) -> list:
    """Events: the proxy losing its repository connection, bursts of bad tickets, slow logins, TLS failures."""
    out = []
    c = classify(d.get("proxy_audit"))
    if len(c):
        for kind, title, per_h, sev, why in [
            ("repo_fail", "Proxy couldn't reach the repository", 5, "Medium",
             "The proxy's connection to the Qlik repository (port 4242) dropped and it had to reconnect. Users see slow "
             "or failed logins and hub loads while this happens. Often the repository service is busy or restarting."),
            ("ticket_bad", "Login tickets rejected", 20, "Low",
             f"Tickets from the {site_config.LOGIN_SERVICE} were invalid or expired by the time the proxy got them. A few are normal "
             "(a refreshed page); many in an hour means logins are failing or clocks are out of step."),
            ("tls", "Secure connections failing", 10, "Low",
             "Something connected to the proxy and dropped during the TLS handshake. Usually a scanner or a client with "
             "old TLS settings."),
        ]:
            x = c[c["kind"].eq(kind)]
            if x.empty:
                continue
            ph = x.set_index("ts").resample("60min").size()
            hot = ph[ph >= per_h]
            for _, g in hot.groupby(qe._groups(hot.index.to_series(), pd.Timedelta(hours=2))):
                a, b = g.index.min(), g.index.max() + pd.Timedelta(hours=1)
                out.append(qe._ev("Login / proxy", f"{title} ({int(g.sum())} times)", a, b, sev, why,
                                  metric=f"{g.max():.0f}/h", source="Proxy audit", key=kind))
        lt = login_times(c)
        if len(lt) >= 5:
            h = lt.set_index("ts")["seconds"].resample("60min").median().dropna()
            n = lt.set_index("ts")["seconds"].resample("60min").size()
            slow = h[(h >= 20) & (n.reindex(h.index) >= 3)]
            for _, g in slow.groupby(qe._groups(slow.index.to_series(), pd.Timedelta(hours=2))):
                a, b = g.index.min(), g.index.max() + pd.Timedelta(hours=1)
                out.append(qe._ev("Login / proxy", f"Slow logins (median {g.max():.0f}s)", a, b, "Medium",
                                  "From being sent to the login page to having a Qlik session took far longer than usual. "
                                  f"Check the {site_config.LOGIN_SERVICE} and the repository at that time.",
                                  metric=f"{g.max():.0f}s", source="Proxy audit", key="slowlogin"))
    return out

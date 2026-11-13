"""Qlik Community search: turn what the logs show into a web search, with anything site-specific taken out.

The app never calls a search service itself. It builds the search and gives you links: Google limited to Qlik's sites
(community.qlik.com and help.qlik.com), and Qlik Community's own search. Nothing leaves the PC until you click one.

Before a search is built, scrub() removes what identifies your site: server and host names, domain\\user names, e-mail
addresses, IP addresses, GUIDs and long hex IDs, file paths and lib:// paths, URLs, timestamps, long numbers, and
anything in quotes or square brackets (app, field, table and file names). What is left is the generic error wording,
which is what other people's posts contain.

No Streamlit code here.
"""
from __future__ import annotations

import re
from urllib.parse import quote_plus

import pandas as pd

SITES = ["community.qlik.com", "help.qlik.com"]
COMMUNITY_SEARCH = "https://community.qlik.com/t5/forums/searchpage/tab/message?q="

_SCRUB = [
    (re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://\S+"), " "),                                   # URLs, lib:// paths
    (re.compile(r"\\\\[^\s'\"]+"), " "),                                                     # UNC paths
    (re.compile(r"(?i)\b[a-z]:\\[^\s'\"]*"), " "),                                          # C:\... paths
    (re.compile(r"(?<![\w.])/(?:[\w.-]+/)+[\w.-]*"), " "),                                  # /unix/paths
    (re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), " "),                                     # e-mail addresses
    (re.compile(r"\b[\w.-]+\\[\w.$-]+"), " "),                                              # DOMAIN\user
    (re.compile(r"(?i)\b(?:user(?:id)?|userdirectory|directory|host(?:name)?|server|machine|node)\s*[=:]\s*\S+"), " "),
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), " "),   # GUIDs
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), " "),                             # IPv4
    (re.compile(r"(?i)\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b"), " "),                     # IPv6
    (re.compile(r"(?i)\b(?=[a-z0-9-]*[a-z])[a-z0-9-]+(?:\.[a-z0-9-]+){2,}\b"), " "),        # host.domain.tld
    (re.compile(r"\b\d{8}T\d{6}(?:[.,]\d+)?(?:[+-]\d{4}|Z)?\b"), " "),                       # Qlik timestamps
    (re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?(?:[.,]\d+)?)?\b"), " "),  # ISO dates/times
    (re.compile(r"\b\d{1,2}[/.]\d{1,2}[/.]\d{2,4}\b"), " "),                                # 28/10/2026
    (re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AaPp][Mm])?\b"), " "),                   # times
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), " "),                                             # long hex IDs
    (re.compile(r"\b\d{6,}\b"), " "),                                                       # long numbers
    (re.compile(r"'[^']*'|\"[^\"]*\"|\[[^\]]*\]|«[^»]*»"), " "),                            # quoted names
    (re.compile(r"\(\s*[^()]{0,60}\)"), " "),                                               # short bracketed detail
]
_SPACES = re.compile(r"\s+")
_EDGE = re.compile(r"^[\s:;,.\-|>]+|[\s:;,\-|>]+$")


def scrub(text: str, max_words: int = 14) -> str:
    """The generic wording of a message, with site-specific detail removed and cut to max_words words."""
    t = str(text or "")
    for rx, rep in _SCRUB:
        t = rx.sub(rep, t)
    t = _SPACES.sub(" ", t)
    t = _EDGE.sub("", t)
    words = t.split(" ")
    return " ".join(words[:max_words]).strip() if words != [""] else ""


def google_url(query: str, sites: list[str] | None = None) -> str:
    sites = SITES if sites is None else sites
    q = query.strip()
    if sites:
        q += " (" + " OR ".join(f"site:{s}" for s in sites) + ")"
    return "https://www.google.com/search?q=" + quote_plus(q)


def community_url(query: str) -> str:
    return COMMUNITY_SEARCH + quote_plus(query.strip())


def item(label: str, query: str, why: str = "") -> dict:
    query = _SPACES.sub(" ", query).strip()
    return {"label": label, "query": query, "why": why, "google": google_url(query), "community": community_url(query)}


def _phrase(text: str, max_words: int = 10) -> str:
    """A scrubbed message as an exact-phrase search, when it is long enough to be worth matching exactly."""
    s = scrub(text, max_words)
    return f'"{s}"' if len(s.split()) >= 3 else s


# Curated searches for each kind of event and each likely cause, in the words people use in Qlik Community posts.
EVENT_QUERIES = {
    "Restart": ["Qlik Sense engine service restarted unexpectedly", "Qlik Sense engine stopped responding users disconnected"],
    "Server CPU": ["Qlik Sense server high CPU usage"],
    "Engine CPU": ["Qlik Sense engine high CPU Average CPU usage high"],
    "Memory": ["Qlik Sense engine working set low limit memory", "Qlik Sense engine memory usage keeps growing"],
    "Request storm": ["Qlik Sense engine high number of requests one session", "Qlik Sense extension object infinite loop requests"],
    "App refresh churn": ["Qlik Sense app reopened repeatedly after reload users connected"],
    "Request volume": ["Qlik Sense engine audit log very large AuditActivity"],
    "Reload pile-up": ["Qlik Sense many reload tasks running at the same time max concurrent reloads"],
    "Reload overlap": ["Qlik Sense task trigger skipped previous execution still running"],
    "Reload load": ["Qlik Sense reload task frequency best practice"],
    "Slow reload": ["Qlik Sense reload taking much longer than usual"],
    "Reload failure": ["Qlik Sense reload task failed"],
    "Reload failing": ["Qlik Sense reload task keeps failing"],
    "Reload time-out": ["Qlik Sense reload task aborted timeout"],
    "Login / proxy": ["Qlik Sense proxy lost connection to repository", "Qlik Sense login ticket invalid or expired"],
    "Proxy noise": ["Qlik Sense proxy audit log malformed request"],
    "Scheduler housekeeping": ["Qlik Sense scheduler task skipped many times"],
    "Engine warnings": ["Qlik Sense System_Engine log warning"],
}
CAUSE_QUERIES = {
    "engine_restart": "Qlik Sense engine service restarted unexpectedly",
    "engine_down": "Qlik Sense engine not responding no engine available",
    "engine_overload": "Qlik Sense engine overloaded requests per minute",
    "memory": "Qlik Sense engine working set limit memory pressure",
    "reload_pileup": "Qlik Sense too many concurrent reloads slow",
    "cpu": "Qlik Sense server CPU 100%",
    "outside_qlik": "Qlik Sense server CPU high antivirus exclusions",
    "proxy": "Qlik Sense proxy repository connection lost",
    "app": "Qlik Sense app slow or failing reload",
    "network_auth": "Qlik Sense login fails authentication ticket",
}
SYMPTOM_WORDS = {
    "Can't open an app": "app will not open", "Session dropped mid-use": "session disconnected",
    "Slow": "slow", "Reload failed": "reload failed", "Blank objects / errors in sheets": "objects not loading",
    "Can't log in": "cannot log in",
}


def for_event(ev) -> list[dict]:
    """Searches for one detected event: its category's usual wording, plus its own message text if it has some."""
    cat = str(ev.get("category", "") or "")
    out = [item(f"{cat}: {q}", q, "What people usually call this") for q in EVENT_QUERIES.get(cat, [])]
    msg = scrub(ev.get("detail", ""), 12)
    if cat in ("Engine warnings", "Reload failure", "Reload failing", "Login / proxy") and len(msg.split()) >= 3:
        out.insert(0, item("The message itself", f"Qlik Sense {_phrase(msg)}", "The log wording, with your details removed"))
    if not out:
        out.append(item(cat or "Event", f"Qlik Sense {scrub(ev.get('title', ''), 10)}"))
    return out


def for_error(text: str, context: str = "Qlik Sense") -> list[dict]:
    """Searches for an error message (a reload error, a pasted error text, a log line)."""
    s = scrub(text, 12)
    if not s:
        return []
    out = [item("The error, word for word", f"{context} {_phrase(s, 12)}", "Exact wording, with your details removed")]
    loose = scrub(text, 8)
    if loose and f'"{loose}"' != _phrase(s, 12):
        out.append(item("The error, loosely", f"{context} {loose}", "Fewer words, not exact"))
    return out


def for_incident(symptom: str = "", error_text: str = "", ranked: list | None = None, restart: dict | None = None,
                 top: int = 2) -> list[dict]:
    """Searches for a reported issue: the pasted error, the engine's own restart reason, and the likeliest causes."""
    out: list[dict] = []
    if restart:
        out += for_restart(restart)
    if error_text:
        out += for_error(error_text)
    words = SYMPTOM_WORDS.get(symptom, "")
    seen = set()
    for r in (ranked or [])[:top + 2]:
        hid = r.get("id")
        if hid in CAUSE_QUERIES and hid not in seen and r.get("role", "cause") == "cause" and len(seen) < top:
            seen.add(hid)
            out.append(item(f"Likely cause: {r.get('title', hid)}", CAUSE_QUERIES[hid] + (f" {words}" if words else ""),
                            "The cause in the words people use"))
    if not out and words:
        out.append(item("What happened", f"Qlik Sense {words}"))
    return _dedupe(out)


def for_restart(restart: dict) -> list[dict]:
    """Searches for an engine restart: the engine's own reason line if it wrote one, then the restart in general."""
    out: list[dict] = []
    cx = (restart or {}).get("context") or {}
    ab = cx.get("abort")
    if ab is not None and len(ab) and "Message" in ab:
        line = str(ab["Message"].iloc[0])
        m = re.search(r"(?i)reason for restart[:.]?\s*(.+)", line)
        reason = scrub(m.group(1) if m else line, 10)
        if reason:
            out.append(item("The engine's own restart reason", f'Qlik Sense "{reason}"', "Exact wording from the engine log"))
    st = cx.get("stuck")
    if st is not None and len(st) and "Message" in st:
        out.append(item("Stuck requests before it", f"Qlik Sense {_phrase(str(st['Message'].iloc[0]), 6)}",
                        "Lines the engine wrote while it was stalling"))
    out.append(item("Engine restarts in general", "Qlik Sense engine service restarted unexpectedly users disconnected"))
    if cx.get("low_limit") or any("working set" in str(t).lower() for t, *_ in (cx.get("load") or [])):
        out.append(item("Memory at its limit before a restart", "Qlik Sense engine working set low limit restart"))
    return _dedupe(out)


def _dedupe(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for x in items:
        if x["query"].lower() not in seen:
            seen.add(x["query"].lower())
            out.append(x)
    return out


MESSAGE_KINDS = {"system": "Engine system log", "service": "Service warnings and errors", "svc_system": "Service trace"}


def common_messages(data: dict, top: int = 12) -> pd.DataFrame:
    """Warning and error messages in the loaded logs, with site detail taken out and alike ones grouped, most frequent
    first: message (scrubbed), count, source, first, last, example (one raw line, kept on this PC)."""
    rows = []
    for kind, label in MESSAGE_KINDS.items():
        df = (data or {}).get(kind)
        if df is None or not len(df) or "Message" not in df:
            continue
        x = df
        if "Level" in x:
            x = x[x["Level"].astype(str).str.upper().isin(["WARN", "WARNING", "ERROR", "FATAL"])]
        if not len(x):
            continue
        g = pd.DataFrame({"message": x["Message"].astype(str).map(lambda m: scrub(m, 12)),
                          "ts": x["ts"] if "ts" in x else pd.NaT, "raw": x["Message"].astype(str), "source": label})
        rows.append(g[g["message"].str.split().str.len() >= 3])
    if not rows:
        return pd.DataFrame(columns=["message", "count", "source", "first", "last", "example"])
    a = pd.concat(rows, ignore_index=True)
    out = (a.groupby(["message", "source"], as_index=False)
           .agg(count=("raw", "size"), first=("ts", "min"), last=("ts", "max"), example=("raw", "first")))
    return out.sort_values(["count", "last"], ascending=[False, False]).head(top).reset_index(drop=True)


def for_text(text: str) -> list[dict]:
    """Searches for anything typed or pasted: an error, a log line, or a description in plain words."""
    s = scrub(text, 16)
    if not s:
        return []
    if len(s.split()) >= 4 and not re.search(r"(?i)\bqlik\b", s):
        return for_error(text)
    return [item("Your search", s if re.search(r"(?i)\bqlik\b", s) else f"Qlik Sense {s}")]

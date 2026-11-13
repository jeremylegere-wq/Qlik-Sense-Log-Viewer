"""How to set up Qlik Sense logging so history can be pulled, and a check of how much history an archive holds.

Everything here is guidance plus plain functions over the ArchivedLogs listing (qlik_events.scan_archive); nothing
touches the server. Where Qlik documents a setting the wording says so; where it does not (for example how long
archived logs are kept) the guide says that too and gives a starting point to adjust, not a rule.
"""
from __future__ import annotations

import pandas as pd

# What each log type gives the app, and which pages go quiet without it.
# (log type in the file name, component folder, what the app uses it for, pages that need it)
LOG_NEEDS = [
    ("Performance_Engine", "Engine", "CPU, memory, sessions and cache every few minutes; restart signature",
     "Server CPU, Engine health, Restart history, Trends"),
    ("System_Engine", "Engine", "The engine's own words: restart reason, memory limits, errors",
     "Events, Restart history, System events"),
    ("Session_Engine", "Engine", "Who opened which app and how much CPU it used", "Apps & users, Server CPU"),
    ("AuditActivity_Engine", "Engine", "Every request to the engine (8 MB files that can fill in minutes)",
     "Requests, Events (storms)"),
    ("Service_Engine", "Engine", "Warnings and errors from the engine service", "Events, Engine health"),
    ("Performance_Repository", "Repository", "Machine CPU and memory", "Server CPU"),
    ("AuditActivity_Repository", "Repository", "QMC and hub actions", "Events"),
    ("Performance_Proxy", "Proxy", "Sessions and logins per interval", "Logins & proxy"),
    ("Audit_Proxy", "Proxy", "Login and session events", "Logins & proxy, Reload failures"),
    ("TaskExecution_Scheduler", "Scheduler", "Reload task runs, durations and results", "Reloads, Reload failures"),
    ("Service_Scheduler", "Scheduler", "Scheduler warnings and errors", "Reload failures, Events"),
    ("System_Scheduler", "Scheduler", "Scheduler system messages", "Reload failures"),
    ("System_Proxy", "Proxy", "Proxy system messages", "Logins & proxy"),
    ("Script", "Script (per app)", "The reload script log of each app: load statements and row counts",
     "Reload failures (detail)"),
]

# QMC > Engines > (engine) > Logging. Names can differ a little by version.
QMC_SETTINGS = [
    ("Performance log interval (minutes)", "5 (Qlik's default)",
     "One performance row per interval. Shorter shows short spikes but writes more; longer smooths them away. "
     "The restart signature and the CPU pages assume a few minutes, so keep 5 unless you have a reason."),
    ("Performance log level", "Info (Qlik's default)",
     "Turns the engine performance log on. Without it the CPU, memory, cache and sessions pages are empty."),
    ("Audit activity log level", "Basic (Qlik's default)",
     "Records engine activity. It is the busiest log and fills 8 MB files fast; keep it on if you want the "
     "Requests page and request storms, and plan disk for it (see the size check in section 4)."),
    ("System log level", "Info (Qlik's default)",
     "The engine's own messages. Warn is the least that still shows restart reasons and memory-limit warnings; "
     "Info keeps the context around them. Keep it at Info."),
    ("Session log level", "Info", "Who opened which app, and its CPU. Needed for Apps & users."),
    ("Service log level", "Info", "Warnings and errors from the engine service."),
]

# Folder shape the app expects, shown as a tree.
TREE = r"""%ProgramData%\Qlik\Sense\Log               live logs on each node (.txt, being written)
  Engine\{Audit, System, Trace}
  Proxy\{Audit, System, Trace}
  Repository\{Audit, System, Trace}
  Scheduler\{Audit, System, Trace}
  Script\                                 reload logs, one per reload

<shared persistence>\ArchivedLogs\<node>\   finished logs (.log); one folder per node
  <node-name>_Performance_Engine_<date>_<timestamp>.log
  <node-name>_System_Engine_...  <node-name>_Audit... and so on
  Script\<app-id>_<timestamp>.log          reload logs (per app)

<history store>\ArchivedLogs\<node>\       your longer copy (same layout; see "Keep history" below)"""

# Baselines. Qlik documents no default for how long archived logs are kept; these are starting points.
RETENTION = [
    ("Production", 18, "Qlik's suggested minimum for production (about 18 months), so a year-on-year comparison and "
                       "a full financial cycle are covered."),
    ("Development", 6, "Qlik's suggested minimum for development (about 6 months)."),
    ("Sandbox / test", 2, "1–2 months is usually enough."),
]

SOURCES = [
    ("Qlik Support: Can we delete old log files for Qlik Sense Enterprise on Windows?",
     "https://community.qlik.com/t5/Official-Support-Articles/Can-we-delete-old-log-files-for-Qlik-Sense-Enterprise-on-Windows/ta-p/1977341",
     "Qlik archives logs but does not delete them; monitoring apps read 3 months by default"),
    ("Qlik Support: How logging works in Qlik Sense",
     "https://community.qlik.com/t5/Support-Knowledge-Base/How-logging-works-in-Qlik-Sense/ta-p/1715137",
     "Log folders, Audit/System/Trace, rollover at restart, 8 MB or 12 hours, keep at least a month"),
    ("Qlik Support: Script logs are deleted from the ArchivedLogs location",
     "https://community.qlik.com/t5/Support-Knowledge-Base/Qlik-Sense-Script-logs-are-deleted-from-ArchivedLogs-location/ta-p/1713654",
     "Only a few script logs are kept per app; copy them with robocopy"),
    ("Qlik Help: Engine properties (logging and tracing defaults)",
     "https://help.qlik.com/en-us/sense/2.0/Subsystems/ManagementConsole/Content/engines-properties.htm",
     "Log levels and the 5 minute performance log interval (older help version; check yours)"),
    ("Qlik Admin Playbook: Archive old archived logs",
     "https://help.qlik.com/en-US/qs-admin-playbook/Content/backup_and_archiving/archive_old_archived_logs.htm",
     "The move-to-an-archive pattern the script follows"),
]


def targets() -> pd.DataFrame:
    return pd.DataFrame(RETENTION, columns=["Environment", "Months", "Why"])


def history(listing: pd.DataFrame, now: pd.Timestamp | None = None, need_days: int = 30) -> pd.DataFrame:
    """One row per log type found: how far back it goes, how long since the newest file, the biggest hole, and a
    verdict against `need_days` of history. `listing` is qlik_events.scan_archive output (path, name, folder, type,
    mtime, size_mb)."""
    cols = ["log type", "files", "oldest", "newest", "days of history", "days since newest", "biggest gap (days)",
            "MB per day", "status"]
    if listing is None or listing.empty:
        return pd.DataFrame(columns=cols)
    now = now or listing["mtime"].max()
    rows = []
    for t, g in listing.groupby("type"):
        m = g["mtime"].sort_values()
        span = max((m.iloc[-1] - m.iloc[0]).total_seconds() / 86400, 0.0)
        gaps = m.diff().dt.total_seconds().dropna() / 86400
        gap = float(gaps.max()) if len(gaps) else 0.0
        behind = (now - m.iloc[-1]).total_seconds() / 86400
        perday = float(g["size_mb"].sum() / max(span, 1.0))
        if behind > 3:
            status = "Stopped - nothing new for " + f"{behind:.0f} days"
        elif span < need_days:
            status = f"Short - {span:.0f} of {need_days} days"
        elif gap > 3:
            status = f"Hole - {gap:.0f} days with nothing"
        else:
            status = "OK"
        rows.append([t, len(g), m.iloc[0], m.iloc[-1], round(span, 1), round(behind, 1), round(gap, 1),
                     round(perday, 1), status])
    out = pd.DataFrame(rows, columns=cols)
    order = {t[0]: i for i, t in enumerate(LOG_NEEDS)}
    return out.assign(_o=out["log type"].map(order).fillna(99)).sort_values(["_o", "log type"]).drop(columns="_o") \
              .reset_index(drop=True)


def missing_types(listing: pd.DataFrame) -> list[str]:
    """Log types the app uses that are not in the listing at all (so logging or archiving is off for them)."""
    have = set(listing["type"]) if listing is not None and not listing.empty else set()
    return [t[0] for t in LOG_NEEDS if t[0] not in have and t[0] != "Script"]


def storage_estimate(listing: pd.DataFrame, days: int) -> dict:
    """GB needed to keep `days` of history at the rate seen in the listing (total MB over the days it spans)."""
    if listing is None or listing.empty:
        return {"per_day_mb": 0.0, "gb": 0.0, "basis_days": 0.0}
    span = max((listing["mtime"].max() - listing["mtime"].min()).total_seconds() / 86400, 1.0)
    per_day = float(listing["size_mb"].sum() / span)
    return {"per_day_mb": per_day, "gb": per_day * days / 1024, "basis_days": span}


def archive_script(source: str, dest: str, keep_days: int, dry_run: bool = True) -> str:
    """A PowerShell script that MOVES archived logs older than `keep_days` from the live archive to a history folder
    (robocopy /MOV /MINAGE), keeping the folder layout. It never deletes: delete from the history folder yourself,
    on your own retention rule. Dry run lists what it would move."""
    src = source.strip() or r"\\server\QlikShare$\ArchivedLogs\server"
    dst = dest.strip() or r"D:\QlikLogHistory\server"
    keep = max(int(keep_days), 1)
    flag = " /L" if dry_run else ""
    return f"""# Move archived Qlik Sense logs older than {keep} days to a history folder. Nothing is deleted.
# {'DRY RUN: lists what would move. Remove /L (or set $dry = $false) to move for real.' if dry_run else 'Moves files for real.'}
# Run it on a schedule (Windows Task Scheduler, daily, as an account that can read/write both folders).
$src  = '{src}'
$dst  = '{dst}'
$keep = {keep}          # days to leave in the live archive
$dry  = ${'true' if dry_run else 'false'}
$log  = Join-Path $dst ('_moves_{{0:yyyyMMdd}}.log' -f (Get-Date))

New-Item -ItemType Directory -Force -Path $dst | Out-Null
$ra = @($src, $dst, '*.log', '*.txt', '/S', '/MOV', "/MINAGE:$keep", '/R:1', '/W:1', '/NP', '/NDL', "/LOG+:$log")
if ($dry) {{ $ra += '/L' }}
robocopy @ra
# robocopy exit codes 0-7 are success (1 = files copied); 8 or more means a failure.
if ($LASTEXITCODE -ge 8) {{ throw "robocopy failed: $LASTEXITCODE (see $log)" }}
"""

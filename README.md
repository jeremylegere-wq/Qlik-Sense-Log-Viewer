# Qlik Server Event Manager

A local, read-only troubleshooting console for **Qlik Sense Enterprise on Windows**. Point it at a node's
ArchivedLogs folder and it turns the logs into a list of **events** (request storms, CPU spikes, reload pile-ups and
failures, memory pressure, engine restarts, login problems), keeps a register of **issues people report** and ranks
their **likely causes** against the evidence, and builds **Qlik Community searches** for what it finds.

It runs on your own Windows PC and opens in your browser. It only reads the logs: it never changes anything on the
Qlik server or the share.

> Not affiliated with or endorsed by Qlik. "Qlik" and "Qlik Sense" are trademarks of their owner.

## Features
- **Overview**: health banner, stat tiles, open events, a CPU honeycomb (one hexagon per 5-minute sample; bands show
  scheduled load), CPU / users / reloads on one time axis, and top lists.
- **Events**: everything worth a look, with status, owner, ticket and notes that are kept between runs, a likely
  root cause → failure → impact lead for each, and every other event at the same time.
- **Reported issues**: log what a user reports (when, app, symptom, error text), check the logs cover that time, see a
  timeline, and get **ranked likely causes** with the evidence for and against each, what to check next, an incident
  note and a prompt for Jira Rovo. Includes a register, trends and CSV/Excel bulk import.
- **Engine restarts**: recognised from the engine performance log; ranked first when a report falls on one, with its
  possible causes (stall, crash, manual or scheduled, automatic restart) and a restart history.
- **Qlik Community search**: ready-made searches for each finding, with site detail taken out (see below).
- **Log setup guide**: how to set up Qlik Sense logging and keep the archive so history can be pulled, with an archive
  move script and a check of how much history your archive holds. Choose where logs come from (share, local folder or
  upload) in the Load logs panel.
- **Apps** (from a QMC export, the share and the logs), **Storage** (a scan of QlikShare$), **Reload failures** with
  the reason from each app's reload log, **Logins & proxy**, **Server CPU**, **Reloads**, **Requests** (the whole
  archive's engine-request history from the folder listing alone) and deeper **Engine** views.
- **Export** to CSV and Excel.

## Requirements
- Windows PC with **Python 3.9 or later** (3.11+ recommended). The launcher installs the packages
  (Streamlit, pandas, Plotly, openpyxl) into a private `.venv` folder on first run.
- Read access to the node's ArchivedLogs folder (usually `\\<server>\QlikShare$\ArchivedLogs\<server>`), or a copy of the logs.

## Quick start
1. Download or clone this repository to a local folder (not a OneDrive-synced one).
2. Edit **`site_config.py`** for your server (at least `ARCHIVE_ROOT`; see below).
3. Double-click **`Start Qlik Log Analyzer.bat`**. The first run sets itself up (a few minutes, once), then your
   browser opens at <http://localhost:8601>. Leave the command window open while you use it.
4. Optional: **`Create Desktop Shortcut.bat`** for a desktop shortcut.

By hand: `pip install -r requirements.txt` then `python launch.py` (or `streamlit run app.py --server.port 8601`).
The launcher uses port 8601 (or the next free one, or `QLIK_EM_PORT`) so it can run next to other Streamlit apps,
listens on this PC only, and opens the running copy if you start it twice.

## Configure it for your server: `site_config.py`
| Setting | What it does |
|---|---|
| `ARCHIVE_ROOT` | The node's ArchivedLogs folder, pre-filled in the app and used by the fetch script. Empty: type it in the app |
| `SERVER_LABEL` | How the server is named in summaries you paste elsewhere |
| `FAULT_URL`, `FAULT_SYSTEM`, `FAULT_FORM_NAME` | Your service desk's fault form. Empty `FAULT_URL` hides the "Log a fault" buttons |
| `TICKET_HINT`, `JIRA_PROJECT` | Ticket placeholder text; the Jira project key used in the Rovo prompt |
| `LOGIN_SERVICE`, `LOGIN_SERVICE_HINT` | The login or SSO service in front of Qlik, named in login findings |
| `LOCAL_TZ_NAME`, `LOCAL_TZ_MIN` | The time zone people report problems in (minutes east of UTC). `None` uses the PC's time zone |
| `SERVER_CORES`, `SERVER_RAM_GB` | Starting values for **Server settings** (CPU and memory calculations) |

Environment variables (optional, restart the app after setting): `QLIK_ARCHIVE_ROOT`, `QLIK_FAULT_URL`,
`QLIK_LOG_FOLDER` (pre-fill the local folder box), `QLIK_EVENT_DATA` (where the app keeps its data),
`QLIK_EVENT_STORE` (a shared event register), `QLIK_SHARE_ROOT` (the share to scan on Storage), `QLIK_EM_PORT`.

## Loading logs
- **From the ArchivedLogs folder** (default): the app walks every subfolder, works out each file's log type from its
  name, and reads the newest files within **Days back** (default 2) and **Max MB per log type** (default 64). The
  engine-request history for the whole archive comes from the folder listing without opening files.
- **From a local copy**: `Fetch latest Qlik logs.bat` copies the newest logs to `%USERPROFILE%\QlikLogs\latest`;
  point **…or read every log in a local folder** at it. The script takes its source from `-Root`,
  `QLIK_ARCHIVE_ROOT` or `site_config.py`.
- **Drop files in** the Load panel.

### Log types used
| Folder | File | Gives you |
|---|---|---|
| Engine\Trace | `*_Performance_Engine` | Engine CPU, users, memory, cache every 5 min |
| Engine\Trace | `*_Session_Engine` | CPU spent by app and user (recorded when a session closes) |
| Engine\Trace | `*_System_Engine` | Memory/CPU warnings, app suspends, loads, security lookups |
| Engine\Audit | `*_AuditActivity_Engine` | Every engine request, used to detect request storms |
| Engine\System | `*_Service_Engine` | Failed engine requests |
| Repository\Trace | `*_Performance_Repository` | **Whole-server CPU** every 5 min |
| Repository\Audit | `*_AuditActivity_Repository` | App opens (wallboards reconnecting) |
| Proxy\Trace | `*_Performance_Proxy` | Users connected every 5 min |
| Proxy\Trace | `*_Audit_Proxy` | Malformed requests and other proxy noise |
| Scheduler\Trace | `*_TaskExecution_Scheduler` | Every reload run: start, end, status |
| Scheduler\System | `*_Service_Scheduler` | Triggers refused because the last run was still going |
| Scheduler\Trace | `*_System_Scheduler` | Scheduler warnings and errors |

## What it detects
| Category | Rule (defaults, change them in Server settings) |
|---|---|
| Request storm | One session making 600+ engine requests a minute, or filling 70%+ of a day's sampled audit file |
| Request volume | A day with 4x (and 30+ files above) the usual audit volume for that kind of day (weekday or weekend) |
| Server CPU / Engine CPU | Two or more 5-minute samples in a row at or above the CPU alert threshold; engine health warnings |
| Memory | Working-set and "Low on RAM" warnings, grouped |
| Reload failure / overlap / pile-up | Failed runs; triggers refused because the last run was still going; 10+ reloads at once |
| Reload load | A task running 20+ times an hour and busy 5%+ of the time |
| Slow reload | Runs 5x longer than that task's usual time (and 10+ min) |
| App refresh churn | 200+ session refreshes an hour on one app; one app re-opened 300+ times |
| Proxy noise | 600+ malformed requests an hour (usually a misconfigured health check) |
| Login / proxy | 5+ proxy-to-repository connection failures an hour; 20+ rejected tickets an hour; slow logins (median 20 s+) |
| Reload failing | A task's last 3+ runs failed, or an app's last 3+ reload logs show a failure |
| Reload time-out | Aborted runs cut off at almost exactly the same length (a time-out, not a script error) |
| Reported issue | Anything logged with Report an issue (or bulk-imported) |
| Scheduler housekeeping | Tasks skipped 50+ times |
| Engine restart (High) | 2+ restart signals together: users and CPU to zero, memory down 70%+ then rebuilt, cache hit ~100% after, a data gap before, a new engine process (thresholds in `incident_rules.RESTART`) |

Treat events as leads, not proof of cause.

## How likely causes are ranked
A transparent, rule-based score (not machine learning), all in `incident_rules.py`:

```
score = prior × symptom multiplier × error-text multiplier × exp( Σ weight × signal × temperature × coverage factor )
probability = score ÷ sum of all scores
```

Signals run from −1 (the data was there and looked normal) to +1 (clearly abnormal); missing data adds nothing and
lowers confidence. When an engine restart signature (3+ signals) is in the window, "Engine restart" gets at least 88%
(60% with two signals), and request storms, reload pile-ups, high CPU and memory pressure are shown as possible
upstream causes. The percentages order leads; they are not measured probabilities, and the weights are starting
points to tune against your own incidents. The wording is always "likely" or "consistent with".

## Engine restarts
A restart shows in the engine performance log as several things at once: CPU and users to zero, memory down more than
70% then rebuilding, a cache hit rate near 100% straight after, a gap in the samples just before, and a new engine
process. Two or more signals raise a High event; one alone is weak; a partial memory drop with users steady is a
cache purge. If the engine system log has the engine's own restart reason (for example *Server aborted. Reason for
restart: Phoenix detected: Server Watchdog is hung*), that cause reads "Stated in the engine log". Each restart lists
what would confirm the cause: Windows System log (Service Control Manager 7031 / 7034 / 7036), Application log,
`System_Engine`, the Service Dispatcher and Repository logs, dump files (including `Engine\CrashDumps`) and the
change calendar.

## Qlik Community search
On each event, each restart, a reported issue's likely causes, Reload failures, and the **Qlik Community search**
page, the app offers searches built from what the logs show: the engine's restart reason, the error text, the likely
causes in the words people use, and the most frequent warnings. **Google** opens Google limited to
community.qlik.com and help.qlik.com; **Qlik Community** opens Community's own search.

Before anything is searched, site detail is taken out: server and host names, domain\user names, e-mail and IP
addresses, GUIDs and long IDs, file and `lib://` paths, URLs, dates and times, long numbers, and anything in quotes or
square brackets (app, field, table and file names). The exact words are shown before you click. Searches open in your
browser; the app makes no web calls. (Google's Custom Search JSON API is closed to new customers and ends on
1 January 2027, and Qlik Community's API ranks by date rather than relevance, so results are not shown inside the app.)

## Where the rules and guidance come from
| What | Basis |
|---|---|
| Log folders, file names, archive | [Qlik Help: log file format and storage](https://help.qlik.com/en-us/sense/2.2/Subsystems/PlanningQlikSenseDeployments/Content/Server/Server-Logging-New-Log-File-Format-Storage.htm) |
| Engine performance log fields (Entry Type, Server Started, ProcessId) | [Qlik Help: Performance log](https://help.qlik.com/en-us/sense/2.2/Subsystems/PlanningQlikSenseDeployments/Content/Server/Server-Logging-Tracing-Log-File-Format-Additional-Fields-Performance-Log.htm) |
| Working-set limits (70% / 90%), cache purged at the low limit | [Qlik Support: Engine memory management](https://community.qlik.com/t5/Support-Knowledge-Base/Qlik-Engine-Memory-Management/ta-p/1710559) |
| CacheHits / CacheLookups | [Qlik Community answer citing Qlik R&D](https://community.qlik.com/t5/Deployment-Management/What-are-the-definitions-of-CacheHits-and-CacheLookups-in/m-p/1932302) |
| Engine watchdog restart reason, core dumps, stuck requests | [Qlik Community thread](https://community.qlik.com/t5/Deployment-Management/Phoenix-detected-Server-Watchdog-is-hung/td-p/1836385) (reported by users; not in Qlik Help) |
| Engine stops while engine.exe keeps running; low virtual memory | [Qlik Support article](https://community.qlik.com/t5/Official-Support-Articles/Qlik-Sense-Engine-Service-stops-but-engine-exe-still-running/ta-p/1717251) |
| "No engine available" style hub errors | [Qlik Support: troubleshoot engine issues](https://community.qlik.com/t5/Knowledge-Base/Qlik-Sense-How-to-troubleshoot-Engine-related-issue/ta-p/1711694) |
| Windows event IDs | General Windows knowledge |
| Priors, weights, thresholds, restart floor | Judgement; not validated against a set of incidents with known causes |

## Your data
Everything the app writes stays on the PC, in `%USERPROFILE%\.qlik_log_analyzer` (or `QLIK_EVENT_DATA`): event
statuses and notes, the reported-issues register, the app list, share listings and small settings. These contain
usernames and server detail, so `.gitignore` keeps them, real logs and PowerShell outputs out of the repository.

## Development
```
pip install -r requirements-dev.txt
python -m pytest
```
The tests use synthetic logs written by `tests/conftest.py`; nothing in them comes from a real server. Main modules:
`app.py` (pages), `qlik_logs.py` and `qlik_events.py` (parsing and event detection), `qlik_incident.py` and
`incident_rules.py` (the investigator and its rules), `qlik_restart.py` (restarts), `qlik_search.py` (Qlik
Community search), `qlik_reloads.py` / `qlik_scriptlog.py` (reload failures), `qlik_proxy.py`, `qlik_share.py`,
`qlik_catalog.py`, `qlik_reports.py`, `site_config.py`, `launch.py`.

## Licence
MIT. See `LICENSE`.

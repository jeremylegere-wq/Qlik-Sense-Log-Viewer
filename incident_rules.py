"""Scoring rules for the Incident Investigator. Edit this file to tune weights or add hypotheses.

How a score is worked out (transparent, no machine learning):

    score(h) = prior(h) × symptom multiplier × error-text multiplier × exp( Σ weight(h, signal) × value(signal) )

    probability(h) = score(h) / Σ scores        (a heuristic estimate, not proof)

* A signal's value runs from -1 to +1. Positive = something abnormal was seen (it supports the hypotheses that give
  it a positive weight). Negative = the data was there and looked normal (it counts against them). A signal with no
  data has no value and adds nothing, which is why poor coverage pushes "not enough data" up instead.
* Weights: about 1 = a useful clue, 2 = strong, 3 = close to decisive. Negative weights make a signal count against a
  hypothesis (e.g. low CPU against "CPU saturation").
* Each signal counts once per hypothesis (its strongest item); overlapping events count once per category and at
  most EVENTS_CAP together. The evidence sum is multiplied by TEMPERATURE, and (except for "not enough data") by
  how well the logs cover the window, so thin data gives flatter, less confident results.
* Bands: High ≥ BANDS["High"], Medium ≥ BANDS["Medium"], otherwise Low. Nothing but "not enough data" is High
  when coverage is below HIGH_NEEDS_COVERAGE (except an engine restart with a strong signature, which is read
  straight from the data that is there).
* Engine restarts: when the restart signature (RESTART below) is in the window with 2+ signals, "Engine restart" gets
  at least RESTART_FLOOR of the estimate and the hypotheses in RESTART_UPSTREAM are shown as possible upstream
  causes of the restart (what may have led to it), not as competing explanations.

To add a hypothesis: add it to HYPOTHESES (id, title, prior, checks, raise, lower), give it weights in WEIGHTS, and
optionally symptom and error-text multipliers. To add a signal: compute it in qlik_incident.evidence() and give it
weights here.
"""

import site_config

BANDS = {"High": 0.40, "Medium": 0.18}
TEMPERATURE = 0.7          # < 1 softens the evidence so one strong signal doesn't swamp everything
COVERAGE_FLOOR = 0.4       # evidence for real causes is multiplied by FLOOR + (1 - FLOOR) × coverage
HIGH_NEEDS_COVERAGE = 0.35  # below this coverage nothing except 'not enough data' is shown as High
EVENTS_CAP = 1.6           # detected events together add at most this much to one hypothesis

# ----------------------------------------------------------------------------------------------
# Engine restart signature (qlik_restart.find). A restart shows as several of these at once; one alone is weak.
# ----------------------------------------------------------------------------------------------
RESTART = {
    "min_users_before": 10,     # users (or document sessions) before the drop for it to count as a collapse
    "near_zero_users": 2,       # users after the drop at or below this (or 10% of before) = near zero
    "near_zero_cpu": 5,         # engine CPU % after the drop at or below this = near zero
    "vm_drop_pct": 70,          # engine memory falling by more than this % ...
    "vm_near_zero_gb": 2,       # ... or to below this many GB
    "vm_min_before_gb": 5,      # ignore memory drops from less than this
    "rebuild_within_min": 90,   # memory must build up again within this time to count as "rebuilt"
    "cache_full_pct": 99.5,     # cache hit rate at or above this straight after the drop (seen on a real restart; not documented by Qlik)
    "gap_min": 7,               # a sample interval this long (and 1.8x the usual) just before counts as a data gap
    "pair_within_min": 7,       # signals within this of each other belong to one restart (about 2 minutes, or the
                                #   next sample when the log samples every 5 minutes)
    "event_min_signals": 2,     # fewer signals = weak candidate: listed on Restart history, not raised as an event
    "strong_signals": 3,
    "lookback_min": 30,         # a restart this long before a report's window still counts for that report
    "business_hours": (7, 18),  # Mon-Fri; a restart then with many users on is unlikely to be planned
    "off_peak_hours": (20, 6),  # evenings and nights
    "maintenance": [],          # planned windows, e.g. [("Sun", "02:00", "04:00")]; a restart inside one points to (c)
}
# number of signals -> the least share of the estimate "Engine restart" gets when the signature is in the window
RESTART_FLOOR = {2: 0.60, 3: 0.88}
# hypotheses that describe what may have led to a restart: shown under it when a restart is found, not as competitors
RESTART_UPSTREAM = ["engine_overload", "reload_pileup", "memory", "cpu", "engine_down"]

HYPOTHESES = [
    {"id": "engine_restart", "short": "Engine restart", "title": "Engine restart (the engine went down and came back)", "prior": 0.5,
     "checks": ["Windows Event Viewer > System log on the server, 5-10 minutes either side: Service Control Manager 7031 / 7034 "
                "(Qlik Sense Engine Service terminated unexpectedly) and 7036 (service entered the stopped / running state)",
                "Windows Event Viewer > Application log, same time: crash entries for the engine (Application Error 1000, "
                "Windows Error Reporting 1001, .NET Runtime 1026)",
                "Engine\\Trace\\*_System_Engine: shutdown lines before the restart and start-up lines after it",
                "Service Dispatcher log (C:\\ProgramData\\Qlik\\Sense\\Log\\ServiceDispatcher) and Repository\\Trace\\*_System_Repository",
                "Dump files (.dmp) from that time: Windows Error Reporting (C:\\ProgramData\\Microsoft\\Windows\\WER) and the Qlik Sense log folders",
                "The change / maintenance calendar: a planned restart, patching, or someone restarting the service by hand",
                "Restart history page: other restart signatures in the full history (a one-off or a pattern?)"],
     "raise": "Users and engine CPU falling to zero together, memory falling to near zero and building up again, a cache hit "
              "rate of 100% straight after, a gap in the performance log just before, a new engine process.",
     "lower": "Unbroken performance samples through the window with the same engine process and steady users and memory."},
    {"id": "engine_down", "short": "Engine unresponsive", "title": "Engine unresponsive or stalled (no restart seen)", "prior": 0.8,
     "checks": ["Engine\\Trace\\*_System_Engine: long silences, 'not responding', calculation time-outs",
                "Engine\\Trace\\*_Performance_Engine: gaps in the 5-minute samples",
                "QMC > Nodes / Service status: was the engine service up?",
                "Proxy\\Audit\\*_Audit_Proxy: 'no engine available' while it was stalled"],
     "raise": "A gap in the engine's own logs at the time; 'no engine available' errors from the proxy.",
     "lower": "Unbroken performance samples through the window."},
    {"id": "engine_overload", "short": "Request storm / churn", "title": "Engine overloaded by a request storm or app refresh churn", "prior": 1.0,
     "checks": ["Engine\\Audit\\*_AuditActivity_Engine: requests per minute by session and app",
                "Engine\\Trace\\*_System_Engine: overlapping suspend messages, 'calculation timed out'",
                "Requests page of this app: storms and re-opens around the time"],
     "raise": "One session or app making hundreds of requests a minute, or many overlapping app suspends.",
     "lower": "Normal request volume and no suspend build-up."},
    {"id": "memory", "short": "Memory pressure", "title": "Memory pressure (engine working set near its limit)", "prior": 0.8,
     "checks": ["Engine\\Trace\\*_Performance_Engine: VMCommitted against the low/high working-set limits",
                "Engine\\Trace\\*_System_Engine: 'working set' / 'memory' warnings, cache purges",
                "QMC > Engines > Advanced: working-set limits"],
     "raise": "Working set above the low limit, a sudden memory drop (cache purge), falling cache hit rate.",
     "lower": "Memory well below the limits and steady."},
    {"id": "reload_pileup", "short": "Reload pile-up", "title": "Reloads starving the engine (pile-up or long reloads)", "prior": 0.9,
     "checks": ["Scheduler\\Trace\\*_TaskExecution_Scheduler: reloads running at the time",
                "Reloads page: concurrency, tasks every 1-2 minutes, unusually long runs",
                "QMC > Tasks: triggers firing at the same minute"],
     "raise": "Many reloads running together, or a reload far longer than usual over the window.",
     "lower": "Few reloads running, all of normal length."},
    {"id": "cpu", "short": "CPU saturation", "title": "CPU saturation", "prior": 1.0,
     "checks": ["Repository\\Trace\\*_Performance_Repository: whole-server CPU",
                "Engine\\Trace\\*_Performance_Engine: engine CPU",
                "Server CPU page: CPU spikes and what was happening"],
     "raise": "Server CPU at or above the alert line through the window, well above its usual level.",
     "lower": "CPU below the warning line and close to normal."},
    {"id": "outside_qlik", "short": "Outside Qlik", "title": "Something outside Qlik using the server (security software, backup, agents)", "prior": 0.6,
     "checks": ["Server CPU against Engine CPU on the Server CPU page: a big difference is non-Qlik work",
                "Windows Performance Monitor / Task Manager history for other processes",
                "Ask the server team about scans, backups, patching at that time"],
     "raise": "Server CPU high while the Qlik engine's own CPU is low.",
     "lower": "Server and engine CPU moving together."},
    {"id": "proxy", "short": "Proxy / repository", "title": "Proxy, repository or node availability problem", "prior": 0.8,
     "checks": ["Proxy\\Audit\\*_Audit_Proxy and Proxy\\Trace\\*_System_Proxy: 'no engine', repository connection failures",
                "Repository\\Trace\\*_System_Repository: errors, restarts",
                "QMC > Nodes and Virtual proxies: node status, load balancing"],
     "raise": "The proxy losing its repository connection or finding no engine; sessions dropped together.",
     "lower": "A quiet proxy log apart from routine messages."},
    {"id": "app", "short": "One app", "title": "A problem in one app (heavy, broken, or a failing reload)", "prior": 1.0,
     "checks": ["Apps page for the affected app: its reloads, failures and users",
                "Reload failures page: errors from the app's reload log",
                "Open the app as an affected user and note the sheet and object"],
     "raise": "The affected app failing to reload, using most of the CPU, or the only app with problems.",
     "lower": "Problems spread across many apps."},
    {"id": "network_auth", "short": "Network / login / external", "title": "Network, login/authentication or an external dependency (database, file share)", "prior": 0.8,
     "checks": ["Logins & proxy page: rejected tickets, slow logins, TLS failures",
                site_config.LOGIN_SERVICE_HINT,
                "Database / file share the reload reads, if the error mentions ODBC, OLE DB or lib://"],
     "raise": "Login tickets rejected, slow logins, a database or file error, a single user or site affected.",
     "lower": "Normal logins and no external errors."},
    {"id": "no_data", "short": "Not enough data", "title": "Cause not in these logs, or not enough data to tell", "prior": 0.6,
     "checks": ["Load logs covering the reported time (Load logs panel: more days, or run the fetch script after the logs rotate)",
                "Windows Event Log and the live log folder C:\\ProgramData\\Qlik\\Sense\\Log on the server",
                "Ask the user for the exact time, app, sheet and a screenshot of the error"],
     "raise": "Logs not covering the window, or nothing abnormal anywhere.",
     "lower": "Good coverage and a clear signal for another hypothesis."},
]

# weight(hypothesis, signal). Signals are produced by qlik_incident.evidence().
WEIGHTS = {
    "restart_signature": {"engine_restart": 4.0, "engine_down": 0.4},   # value 0.35 (one signal) .. 1 (three or more)
    "restart":          {"engine_restart": 1.2, "engine_down": 0.4},    # service start/stop messages in the logs
    "perf_gap":         {"engine_down": 1.6, "engine_overload": 0.6, "no_data": 0.8},
    "no_engine":        {"engine_down": 2.2, "proxy": 2.0, "memory": 0.6},
    "session_drop":     {"engine_down": 1.5, "proxy": 1.2, "network_auth": 0.6},
    "cpu_high":         {"cpu": 2.4, "reload_pileup": 0.5, "engine_overload": 0.4, "outside_qlik": 0.5},
    "cpu_not_qlik":     {"outside_qlik": 2.6, "cpu": 0.5},
    "memory_high":      {"memory": 2.4, "engine_down": 0.4},
    "memory_drop":      {"memory": 1.4, "engine_down": 1.4},
    "cache_dip":        {"memory": 1.0, "engine_overload": 0.5},
    "reload_pileup":    {"reload_pileup": 2.4, "cpu": 0.4, "memory": 0.4},
    "reload_long":      {"reload_pileup": 1.2, "app": 0.8},
    "reload_failed":    {"app": 1.6, "network_auth": 0.6, "reload_pileup": 0.3},
    "storm":            {"engine_overload": 2.6, "app": 0.8},
    "suspends":         {"engine_overload": 1.6, "memory": 0.4},
    "security_lookups": {"engine_overload": 0.6, "proxy": 0.4},
    "repo_fail":        {"proxy": 2.2, "network_auth": 0.5},
    "auth_problems":    {"network_auth": 2.2, "proxy": 0.5},
    "slow_logins":      {"network_auth": 1.4, "proxy": 0.8},
    "one_app":          {"app": 1.8, "engine_overload": 0.4},
    "events":           {},   # overlapping events: weight comes from EVENT_MAP below
    "coverage_poor":    {"no_data": 2.6},
    "nothing_abnormal": {"no_data": 1.6},
    "replicated":       {"app": 1.0, "network_auth": 0.4, "engine_down": -0.4, "engine_restart": -0.4, "cpu": -0.3},
    "many_users":       {"engine_down": 0.8, "engine_restart": 0.6, "proxy": 0.8, "cpu": 0.6, "memory": 0.5, "engine_overload": 0.4,
                         "app": -0.4},
}

# Detected events overlapping the window: category -> {hypothesis: weight}
EVENT_MAP = {
    "Restart": {"engine_restart": 1.5}, "Server CPU": {"cpu": 1.0}, "Engine CPU": {"cpu": 0.8},
    "Memory": {"memory": 1.2}, "Request storm": {"engine_overload": 1.2}, "App refresh churn": {"engine_overload": 0.8},
    "Request volume": {"engine_overload": 0.6}, "Reload pile-up": {"reload_pileup": 1.2},
    "Reload overlap": {"reload_pileup": 0.6}, "Reload load": {"reload_pileup": 0.5}, "Slow reload": {"reload_pileup": 0.6},
    "Reload failure": {"app": 0.8}, "Reload failing": {"app": 1.0}, "Reload time-out": {"app": 0.6, "network_auth": 0.4},
    "Login / proxy": {"proxy": 0.8, "network_auth": 0.8}, "Engine warnings": {"engine_overload": 0.4, "memory": 0.3},
}

# An event category is skipped when the signal(s) here were measured directly for the window: the event is the
# same fact seen another way, and counting both would double it.
EVENT_DUPLICATES = {
    "Server CPU": ["cpu_high"], "Engine CPU": ["cpu_high"], "Memory": ["memory_high"], "Restart": ["restart_signature", "restart"],
    "Request storm": ["storm"], "Reload pile-up": ["reload_pileup"], "Slow reload": ["reload_long"],
    "Reload failure": ["reload_failed"], "Reload failing": ["reload_failed"], "Login / proxy": ["repo_fail", "auth_problems"],
}

SYMPTOMS = ["Not sure", "Can't open an app", "Session dropped mid-use", "Slow", "Reload failed",
            "Blank objects / errors in sheets", "Can't log in"]

# symptom -> {hypothesis: prior multiplier}
SYMPTOM_PRIORS = {
    "Can't open an app": {"engine_down": 1.8, "engine_restart": 1.5, "proxy": 1.6, "memory": 1.2, "app": 1.2, "cpu": 0.8,
                          "reload_pileup": 0.8},
    "Session dropped mid-use": {"engine_down": 2.0, "engine_restart": 2.0, "proxy": 1.6, "network_auth": 1.3, "memory": 1.2,
                                "app": 0.7},
    "Slow": {"cpu": 1.6, "engine_overload": 1.6, "reload_pileup": 1.4, "memory": 1.2, "outside_qlik": 1.3, "proxy": 0.7},
    "Reload failed": {"app": 2.2, "network_auth": 1.5, "reload_pileup": 1.2, "engine_down": 0.7, "engine_restart": 0.8, "proxy": 0.4},
    "Blank objects / errors in sheets": {"app": 1.8, "engine_overload": 1.4, "memory": 1.3, "cpu": 1.1},
    "Can't log in": {"network_auth": 2.4, "proxy": 2.0, "engine_down": 0.6, "engine_restart": 0.6, "cpu": 0.5, "app": 0.3},
}

# pasted error text: (regex, {hypothesis: multiplier}, what it usually means)
ERROR_TEXT = [
    (r"NoEngineAvailable|OnNoEngine|no engine", {"engine_down": 2.5, "engine_restart": 2.0, "proxy": 1.8, "memory": 1.3},
     "the proxy found no engine to send the user to"),
    (r"NoConnectionCreated|OnConnectionLost|ConnectionLost|web ?socket|connection (was )?lost",
     {"engine_down": 1.6, "engine_restart": 1.6, "proxy": 1.6, "network_auth": 1.6},
     "the browser's connection to the engine failed or dropped"),
    (r"SessionTimedOut|session (has )?(timed out|expired)", {"network_auth": 1.3, "engine_overload": 1.2},
     "the session ended (inactivity or the engine stopped answering)"),
    (r"access denied|forbidden|\b403\b|not authori[sz]ed|licen[cs]e|ticket", {"network_auth": 2.2, "proxy": 1.2},
     "a login, access or licence problem"),
    (r"ODBC|OLE ?DB|SQL|Connector|Cannot open file|lib://|timeout expired", {"app": 1.8, "network_auth": 1.6},
     "a database or file the app reads didn't answer"),
    (r"out of memory|memory|working set", {"memory": 2.2}, "memory"),
    (r"calculation (timed out|aborted)|incomplete visuali[sz]ation|object.*(timed out|failed)",
     {"engine_overload": 1.6, "cpu": 1.3, "app": 1.3, "memory": 1.2}, "the engine couldn't finish calculating"),
]


# Where the rules and the guidance text come from (checked October 2026). The scoring numbers above are judgement,
# tuned on a real restart and real logs, and have not been validated against past incidents with known causes.
# status: "documented" = in Qlik's help or a Qlik Support article; "community" = reported in Qlik Community threads;
# "general" = general Windows / Qlik knowledge, not checked against a page; "judgement" = ours.
SOURCES = [
    {"topic": "Log folders, file names, archive", "status": "documented",
     "url": "https://help.qlik.com/en-us/sense/2.2/Subsystems/PlanningQlikSenseDeployments/Content/Server/Server-Logging-New-Log-File-Format-Storage.htm"},
    {"topic": "Engine performance log fields (Entry Type, Server Started, ProcessId)", "status": "documented",
     "url": "https://help.qlik.com/en-us/sense/2.2/Subsystems/PlanningQlikSenseDeployments/Content/Server/Server-Logging-Tracing-Log-File-Format-Additional-Fields-Performance-Log.htm"},
    {"topic": "Working-set limits 70% / 90%, cache purged at the low limit", "status": "documented",
     "url": "https://community.qlik.com/t5/Support-Knowledge-Base/Qlik-Engine-Memory-Management/ta-p/1710559"},
    {"topic": "CacheHits / CacheLookups definitions", "status": "community",
     "url": "https://community.qlik.com/t5/Deployment-Management/What-are-the-definitions-of-CacheHits-and-CacheLookups-in/m-p/1932302"},
    {"topic": "Engine watchdog restart reason, core dump folder, stuck requests", "status": "community",
     "url": "https://community.qlik.com/t5/Deployment-Management/Phoenix-detected-Server-Watchdog-is-hung/td-p/1836385"},
    {"topic": "Engine stops while engine.exe keeps running; low virtual memory event", "status": "documented",
     "url": "https://community.qlik.com/t5/Official-Support-Articles/Qlik-Sense-Engine-Service-stops-but-engine-exe-still-running/ta-p/1717251"},
    {"topic": "Hub engine errors (no engine available)", "status": "documented",
     "url": "https://community.qlik.com/t5/Knowledge-Base/Qlik-Sense-How-to-troubleshoot-Engine-related-issue/ta-p/1711694"},
    {"topic": "Windows event IDs 7031 / 7034 / 7036, 1000, 1001, 1026", "status": "general", "url": ""},
    {"topic": "Priors, weights, multipliers, thresholds, restart floor", "status": "judgement", "url": ""},
]

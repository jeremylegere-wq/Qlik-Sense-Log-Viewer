"""Synthetic Qlik logs for tests. Nothing here comes from a real server."""
import os
import sys
from datetime import datetime, timedelta

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

HOST = "testhost"


@pytest.fixture(autouse=True)
def _apptest_segmented_control_quirk(monkeypatch):
    """Streamlit 1.50's test harness (AppTest) can't re-run a page with a single-choice segmented control (it reads
    the chosen option as a list of letters). In a browser it works. On those versions the tests use the radio-button
    fallback the app already has (app.seg); newer versions test the real control."""
    import streamlit as st
    major, minor = (int(x) for x in st.__version__.split(".")[:2])
    if (major, minor) < (1, 51):
        monkeypatch.setattr(st, "segmented_control", None, raising=False)


def ts(dt: datetime) -> str:
    return dt.strftime("%Y%m%dT%H%M%S.") + f"{dt.microsecond // 1000:03d}+1000"


def tsv(cols, rows) -> str:
    return "\t".join(cols) + "\n" + "\n".join("\t".join(str(r.get(c, "")) for c in cols) for r in rows) + "\n"


T0 = datetime(2026, 10, 20, 9, 0, 0)


def perf_engine(n=24, cpu=50):
    import qlik_logs as q
    cols = ["Sequence#", "Timestamp", "Level", "Hostname", "Logger", "ProcessId", "Server Started"] + q.NUM_PERF
    rows = [{"Sequence#": i, "Timestamp": ts(T0 + timedelta(minutes=5 * i)), "Level": "INFO", "Hostname": HOST,
             "Logger": "Performance.Engine", "ProcessId": 100, "Server Started": "20261019T030000.000+1000",
             "ActiveUsers": 10 + i, "ActiveDocSessions": 12 + i, "CPULoad": cpu + (40 if 10 <= i <= 14 else 0),
             "VMCommitted(MB)": 150000, "CacheHits": 90, "CacheLookups": 100, "Calls": 1000, "Selections": 50,
             "VMAllocated(MB)": 140000, "VMFree(MB)": 100000} for i in range(n)]
    return tsv(cols, rows)


def repo_perf(n=24):
    cols = ["Sequence#", "Timestamp", "Level", "Hostname", "Logger", "Id", "Message", "Machine_ProcessorTimePercent",
            "Repository_ProcessorTimePercent", "Repository_WorkingSetMemory"]
    rows = [{"Sequence#": i, "Timestamp": ts(T0 + timedelta(minutes=5 * i)), "Level": "INFO", "Hostname": HOST,
             "Logger": "Performance.Repository", "Id": f"rp{i}", "Message": "Repository performance counters",
             "Machine_ProcessorTimePercent": 30 + (60 if 10 <= i <= 13 else 0), "Repository_ProcessorTimePercent": 1,
             "Repository_WorkingSetMemory": 5e8} for i in range(n)]
    return tsv(cols, rows)


def engine_activity(per_min=900, minutes=3, multi_app=False):
    """One noisy session (optionally across several apps) plus a few quiet users."""
    cols = ["Sequence#", "ProductVersion", "Timestamp", "Hostname", "Id", "Description", "ProxySessionId", "UserId",
            "SessionId", "ObjectId", "ObjectName", "Service", "Command", "Result", "Message"]
    rows, k = [], 0
    apps = ["APP_A", "APP_B", "APP_C"] if multi_app else ["APP_A"]
    for m in range(minutes):
        for j in range(per_min):
            k += 1
            t = T0 + timedelta(minutes=m, seconds=j * 60 / per_min)
            rows.append({"Sequence#": k, "Timestamp": ts(t), "Hostname": HOST, "Id": f"a{k}", "ProxySessionId": "sess-1",
                         "UserId": "noisy", "SessionId": "s1", "ObjectId": f"app-guid|OBJ{k}",
                         "ObjectName": f"{apps[k % len(apps)]}|Not available", "Service": "Engine",
                         "Command": "Get layout", "Result": "0", "Message": "Success"})
    for u in range(3):
        k += 1
        rows.append({"Sequence#": k, "Timestamp": ts(T0 + timedelta(minutes=1)), "Hostname": HOST, "Id": f"a{k}",
                     "ProxySessionId": f"sess-q{u}", "UserId": f"quiet{u}", "SessionId": f"q{u}", "ObjectId": "g|x",
                     "ObjectName": "APP_B|Not available", "Service": "Engine", "Command": "Get layout", "Result": "0",
                     "Message": "Success"})
    return tsv(cols, rows)


def task_exec():
    cols = ["Sequence#", "Timestamp", "Level", "Hostname", "Logger", "Id", "Message", "TaskId", "TaskName", "AppId",
            "AppName", "Status", "StartTime", "StopTime", "Duration", "FailureReason"]
    rows, k = [], 0
    for i in range(120):  # a task every minute for 2 hours, 20 s each
        k += 1
        s = T0 + timedelta(minutes=i)
        rows.append({"Sequence#": k, "Timestamp": ts(s + timedelta(seconds=20)), "Level": "INFO", "Hostname": HOST,
                     "Logger": "TaskExecution.Scheduler", "Id": f"t{k}", "Message": "Task execution finished",
                     "TaskId": "task-1", "TaskName": "Every minute", "AppId": "app-1", "AppName": "RT App",
                     "Status": "FinishedSuccess" if i % 40 else "Error", "StartTime": ts(s),
                     "StopTime": ts(s + timedelta(seconds=20)), "Duration": 20000})
    for j in range(12):  # 12 at once -> pile-up
        k += 1
        s = T0 + timedelta(minutes=30)
        rows.append({"Sequence#": k, "Timestamp": ts(s + timedelta(minutes=5)), "Level": "INFO", "Hostname": HOST,
                     "Logger": "TaskExecution.Scheduler", "Id": f"t{k}", "Message": "Task execution finished",
                     "TaskId": f"big-{j}", "TaskName": f"Nightly {j}", "AppId": f"b{j}", "AppName": f"Big {j}",
                     "Status": "FinishedSuccess", "StartTime": ts(s), "StopTime": ts(s + timedelta(minutes=5)),
                     "Duration": 300000})
    return tsv(cols, rows)


def system_engine():
    cols = ["Sequence#", "Timestamp", "Level", "Hostname", "Logger", "Thread", "Id", "ServiceUser", "Message",
            "ProxySessionId", "ActiveUserDirectory", "ActiveUserId", "EngineTimestamp", "ProcessId", "SessionId", "AppId"]
    msgs = ["EngineHealthRequest: Average CPU usage high for a period of time",
            r"CGenericConnection: pipe[\\.\pipe\data_1e5cf0ccae6770739475b767b4a396b2386a1169.pip] pipe has already connected to unknown process",
            r"CGenericConnection: pipe[\\.\pipe\data_4078ff5b4b5253e2c840ccd4d22dc021c269d3ce.pip] pipe has already connected to unknown process"]
    rows = [{"Sequence#": i, "Timestamp": ts(T0 + timedelta(minutes=50, seconds=i)), "Level": "WARN", "Hostname": HOST,
             "Logger": "System.Engine.Engine", "Id": f"s{i}", "Message": msgs[i % 3]} for i in range(9)]
    return tsv(cols, rows)


@pytest.fixture
def archive(tmp_path):
    """A small ArchivedLogs-style tree with realistic file names and modified times."""
    files = {
        "Engine/Trace/testhost_Performance_Engine_2026-10-20T01.00.00Z.log": perf_engine(),
        "Engine/Trace/testhost_System_Engine_2026-10-20T01.00.00Z.log": system_engine(),
        "Engine/Audit/testhost_AuditActivity_Engine_2026-10-20T01.00.00Z.log": engine_activity(multi_app=True),
        "Repository/Trace/testhost_Performance_Repository_2026-10-20T01.00.00Z.log": repo_perf(),
        "Scheduler/Trace/testhost_TaskExecution_Scheduler_2026-10-20T01.00.00Z.log": task_exec(),
        "Repository/Trace/testhost_License_Repository_2026-10-20T01.00.00Z.log": "Sequence#\tTimestamp\tLogger\n1\t20261020T090000.000+1000\tLicense\n",
    }
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        t = datetime(2026, 10, 20, 11, 0).timestamp()
        os.utime(p, (t, t))
    # older audit files to build history (tiny, content irrelevant)
    for d in range(30):
        for h in range(3 if d < 25 else 30):
            p = tmp_path / f"Engine/Audit/testhost_AuditActivity_Engine_2026-09-{(d % 28) + 1:02d}T{h % 24:02d}.{d:02d}.00Z.log"
            p.write_text(engine_activity(per_min=2, minutes=1), encoding="utf-8")
            t = (datetime(2026, 9, 20, 0, 0) + timedelta(days=d, minutes=h * 40)).timestamp()
            os.utime(p, (t, t))
    return tmp_path


APP1 = "0b06745a-ef88-49a2-954a-31c9039e6f5e"
APP2 = "1c17856b-f099-4ab3-a65b-42da0a2f7f6f"


def proxy_audit():
    """Logins (login page -> session), a burst of repository connection failures, and a steady malformed probe."""
    cols = ["Sequence#", "Timestamp", "Level", "Hostname", "Logger", "Thread", "Id", "ServiceUser", "Message",
            "ProxySessionId", "ConnectionId", "ActiveUserDirectory", "ActiveUserId", "TicketId", "IpAddress", "AppId",
            "TargetHost", "VirtualProxy", "Checksum"]
    rows, k = [], 0

    def add(t, msg, user="", ip="", app="", level="INFO"):
        nonlocal k
        k += 1
        rows.append({"Sequence#": k, "Timestamp": ts(t), "Level": level, "Hostname": HOST, "Logger": "Audit.Proxy.Proxy",
                     "Id": f"p{k}", "ServiceUser": "CORP\\svc", "Message": msg, "ActiveUserId": user, "IpAddress": ip,
                     "AppId": app})
    for i in range(12):
        t = T0 + timedelta(minutes=10 * i)
        ip = f"::ffff:10.0.0.{i}"
        add(t, "Authentication required, redirecting client@http://x/ to https://login.example/Account/Login", ip=ip)
        add(t + timedelta(seconds=6 + i), f"User 'user{i}' used 'ticket' authentication, got session: 's{i}'", f"user{i}", ip)
        add(t + timedelta(seconds=20), "New target uri chosen: wss://testhost:4747/, app: " + APP1, f"user{i}", ip, APP1)
    for j in range(8):
        add(T0 + timedelta(minutes=60, seconds=20 * j), "The already opened client to target failed to connect, trying to "
            "reconnect with a new client once. https://testhost:4242/", "user1", "::ffff:10.0.0.1")
    for s_ in range(0, 120 * 60, 2):
        add(T0 + timedelta(seconds=s_), "Bad request, malformed first line: GET /", level="WARN")
    return tsv(cols, rows)


def system_scheduler():
    cols = ["Sequence#", "Timestamp", "Level", "Hostname", "Logger", "Thread", "Id", "ServiceUser", "Message", "Exception",
            "StackTrace", "ProxySessionId", "TaskName", "TaskId", "User", "ExecutionId", "AppName", "AppId", "Id2"]
    rows = [{"Sequence#": 1, "Timestamp": ts(T0 + timedelta(minutes=40, seconds=20)), "Level": "ERROR", "Hostname": HOST,
             "Logger": "System.Scheduler.Scheduler.Slave.Execution", "Id": "s1", "Message": "Reload aborted on worker",
             "TaskName": "Every minute", "ExecutionId": "ex-40", "AppName": "RT App", "AppId": "app-1"}]
    return tsv(cols, rows)


def reload_log(start: datetime, ok: bool = True, cut: bool = False) -> str:
    def t(sec):
        return ts(start + timedelta(seconds=sec))
    lines = [f"{t(0)} Execution started.", f"{t(0)} Reload Executed By            UserDirectory=INTERNAL; UserId=sa_scheduler",
             f"{t(1)} 0002  Events:", f"{t(1)} 0003  LOAD * FROM [lib://QVD/Events.qvd] (qvd);",
             f"{t(3)}       Events << Events (qvd optimized) 1,234 Lines fetched"]
    if cut:
        return "\n".join(lines) + "\n"
    if ok:
        lines += [f"{t(4)} 0005  STORE Events INTO [lib://QVD/Out.qvd] (qvd);", f"{t(5)}       Execution finished."]
    else:
        lines += [f"{t(4)}       The following error occurred:", f"{t(4)}       Cannot open file: 'lib://Data/Targets.xlsx'",
                  f"{t(5)}       Execution Failed", f"{t(5)}       Execution finished."]
    return "\n".join(lines) + "\n"


@pytest.fixture
def share(tmp_path):
    """A QlikShare$-style tree: Apps (files, lock, search index), ArchivedLogs with engine, proxy and scheduler logs,
    and reload script logs in ArchivedLogs\\<host>\\Script."""
    root = tmp_path / "QlikShare"
    arch = root / "ArchivedLogs" / HOST
    files = {
        "Engine/Trace/testhost_Performance_Engine_2026-10-20T01.00.00Z.log": perf_engine(),
        "Engine/Trace/testhost_System_Engine_2026-10-20T01.00.00Z.log": system_engine(),
        "Engine/Audit/testhost_AuditActivity_Engine_2026-10-20T01.00.00Z.log": engine_activity(multi_app=True),
        "Repository/Trace/testhost_Performance_Repository_2026-10-20T01.00.00Z.log": repo_perf(),
        "Scheduler/Trace/testhost_TaskExecution_Scheduler_2026-10-20T01.00.00Z.log": task_exec(),
        "Scheduler/Trace/testhost_System_Scheduler_2026-10-20T01.00.00Z.log": system_scheduler(),
        "Proxy/Audit/testhost_Audit_Proxy_2026-10-20T01.00.00Z.log": proxy_audit(),
    }
    stamp = datetime(2026, 10, 20, 11, 0).timestamp()
    for rel, text in files.items():
        p = arch / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        os.utime(p, (stamp, stamp))
    sc = arch / "Script"
    sc.mkdir(parents=True)
    for i, (ok, cut) in enumerate([(True, False), (False, False), (False, False), (False, False), (True, True)]):
        st_ = T0 + timedelta(minutes=30 * i)
        p = sc / f"{APP1}.{st_:%Y%m%dT%H%M%S}.000+1000.{i:020X}.log"
        p.write_text(reload_log(st_, ok, cut), encoding="utf-8")
        os.utime(p, (st_.timestamp(), st_.timestamp()))
    apps = root / "Apps"
    (apps / "Search" / APP1).mkdir(parents=True)
    (apps / APP1).write_bytes(b"x" * 2_000_000)
    (apps / (APP1 + ".lock")).write_bytes(b"")
    (apps / APP2).write_bytes(b"x" * 500_000)
    (apps / "Search" / APP1 / "1_abc").write_bytes(b"x" * 300_000)
    old = datetime(2024, 1, 1).timestamp()
    os.utime(apps / APP2, (old, old))
    (root / "StaticContent" / "Content").mkdir(parents=True)
    (root / "StaticContent" / "Content" / "logo.png").write_bytes(b"x" * 1000)
    return arch


# ----------------------------------------------------------------------------------------------
# The sample restart case: an engine restart at about 15:50:21-15:51:12 (server time), after a gap in the
# performance log from 15:36 to 15:50, with a request storm and a reload pile-up building up before it.
# Synthetic numbers shaped on what the real charts showed.
# ----------------------------------------------------------------------------------------------
RDAY = datetime(2026, 3, 25)


def perf_restart_sample(cache_purge: bool = False):
    import qlik_logs as q
    cols = ["Sequence#", "Timestamp", "Level", "Hostname", "Logger", "ProcessId", "Server Started", "Entry Type"] + q.NUM_PERF
    rows = []

    def add(t, pid, started, users, cpu, vm_gb, hits, lookups):
        rows.append({"Sequence#": len(rows) + 1, "Timestamp": ts(t), "Level": "INFO", "Hostname": HOST,
                     "Logger": "Performance.Engine.Engine", "ProcessId": pid, "Server Started": started, "Entry Type": "Normal",
                     "ActiveUsers": users, "Users": users, "ActiveDocSessions": users + 3 if users else 0,
                     "DocSessions": users + 3 if users else 0,
                     "CPULoad": cpu, "VMCommitted(MB)": int(vm_gb * 1024), "VMAllocated(MB)": int(vm_gb * 900),
                     "VMFree(MB)": 100000, "CacheHits": hits, "CacheLookups": lookups, "Calls": 2000, "Selections": 80})
    old, old_start = 11020, "20260322T021513.000+1000"                # the weekly Sunday 02:15 start
    t = RDAY.replace(hour=13, minute=1)
    i = 0
    while t <= RDAY.replace(hour=15, minute=36):
        build = max(0, (t - RDAY.replace(hour=14, minute=30)).total_seconds() / 3960)      # 0 → 1 from 14:30 to 15:36
        users = 38 + (i % 5) + int(6 * build)
        vm = 150 + 15 * build
        if cache_purge and t == RDAY.replace(hour=14, minute=1):
            vm = 75                                                     # a purge: memory 180 → 75 GB, users steady
        if cache_purge and t < RDAY.replace(hour=14, minute=1):
            vm = 180
        add(t, old, old_start, users, 55 + 37 * build, vm, 800, 1000)
        t += timedelta(minutes=5)
        i += 1
    if cache_purge:                     # the purge case has no restart: samples carry on
        while t <= RDAY.replace(hour=17, minute=30):
            add(t, old, old_start, 44, 40, 110, 800, 1000)
            t += timedelta(minutes=5)
        return tsv(cols, rows)
    # 15:36 -> 15:50: nothing written (the engine stalled), then the old engine's last sample and the new engine's first
    add(RDAY.replace(hour=15, minute=50, second=21), old, old_start, 44, 3, 161, 300, 420)
    new, new_start = 23456, "20260325T155058.000+1000"
    add(RDAY.replace(hour=15, minute=51, second=12), new, new_start, 0, 0, 0.3, 4, 4)
    t = RDAY.replace(hour=15, minute=56, second=12)
    k = 0
    while t <= RDAY.replace(hour=17, minute=30):
        vm = min(110, 18 + 22 * k)
        users = min(40, 4 + 6 * k)
        add(t, new, new_start, users, 25 + min(30, 5 * k), vm, 700, 1000)
        t += timedelta(minutes=5)
        k += 1
    return tsv(cols, rows)


def repo_perf_sample():
    cols = ["Sequence#", "Timestamp", "Level", "Hostname", "Logger", "Id", "Message", "Machine_ProcessorTimePercent",
            "Repository_ProcessorTimePercent", "Repository_WorkingSetMemory"]
    rows = []
    t, i = RDAY.replace(hour=13, minute=0), 0
    while t <= RDAY.replace(hour=17, minute=30):
        busy = RDAY.replace(hour=15, minute=10) <= t <= RDAY.replace(hour=15, minute=50)
        rows.append({"Sequence#": i, "Timestamp": ts(t), "Level": "INFO", "Hostname": HOST, "Logger": "Performance.Repository",
                     "Id": f"rp{i}", "Message": "Repository performance counters",
                     "Machine_ProcessorTimePercent": 93 if busy else 45, "Repository_ProcessorTimePercent": 2,
                     "Repository_WorkingSetMemory": 5e8})
        t += timedelta(minutes=5)
        i += 1
    return tsv(cols, rows)


def storm_sample():
    """One session hammering the engine 15:22-15:28, a few quiet users through the afternoon."""
    cols = ["Sequence#", "ProductVersion", "Timestamp", "Hostname", "Id", "Description", "ProxySessionId", "UserId",
            "SessionId", "ObjectId", "ObjectName", "Service", "Command", "Result", "Message"]
    rows, k = [], 0
    base = RDAY.replace(hour=15, minute=22)
    for m in range(6):
        for j in range(900):
            k += 1
            rows.append({"Sequence#": k, "Timestamp": ts(base + timedelta(minutes=m, seconds=j / 15)), "Hostname": HOST,
                         "Id": f"a{k}", "ProxySessionId": "sess-storm", "UserId": "wallboard01", "SessionId": "s1",
                         "ObjectId": f"app-guid|OBJ{k % 40}", "ObjectName": "Sales_Dashboard|Not available", "Service": "Engine",
                         "Command": "Get layout", "Result": "0", "Message": "Success"})
    for q_ in range(0, 270, 3):
        k += 1
        rows.append({"Sequence#": k, "Timestamp": ts(RDAY.replace(hour=13) + timedelta(minutes=q_)), "Hostname": HOST,
                     "Id": f"a{k}", "ProxySessionId": f"sess-q{q_}", "UserId": f"user{q_ % 7}", "SessionId": f"q{q_}",
                     "ObjectId": "g|x", "ObjectName": "ED Dashboard|Not available", "Service": "Engine",
                     "Command": "Get layout", "Result": "0", "Message": "Success"})
    return tsv(cols, rows)


def tasks_sample():
    """Normal reloads through the afternoon, then 14 starting together at 15:15-15:25 and running 20-30 minutes."""
    cols = ["Sequence#", "Timestamp", "Level", "Hostname", "Logger", "Id", "Message", "TaskId", "TaskName", "AppId",
            "AppName", "Status", "StartTime", "StopTime", "Duration", "FailureReason"]
    rows, k = [], 0
    for i in range(0, 270, 15):
        k += 1
        s = RDAY.replace(hour=13) + timedelta(minutes=i)
        rows.append({"Sequence#": k, "Timestamp": ts(s + timedelta(minutes=2)), "Level": "INFO", "Hostname": HOST,
                     "Logger": "TaskExecution.Scheduler", "Id": f"t{k}", "Message": "Task execution finished",
                     "TaskId": "task-rt", "TaskName": "RT Events reload", "AppId": "app-rt", "AppName": "RT Events",
                     "Status": "FinishedSuccess", "StartTime": ts(s), "StopTime": ts(s + timedelta(minutes=2)), "Duration": 120000})
    for j in range(14):
        k += 1
        s = RDAY.replace(hour=15, minute=15) + timedelta(seconds=40 * j)
        e = s + timedelta(minutes=20 + j % 10)
        rows.append({"Sequence#": k, "Timestamp": ts(e), "Level": "INFO", "Hostname": HOST, "Logger": "TaskExecution.Scheduler",
                     "Id": f"t{k}", "Message": "Task execution finished", "TaskId": f"pm-{j}", "TaskName": f"PM extract {j}",
                     "AppId": f"pm{j}", "AppName": f"PM Extract {j}", "Status": "FinishedSuccess", "StartTime": ts(s),
                     "StopTime": ts(e), "Duration": int((e - s).total_seconds() * 1000)})
    return tsv(cols, rows)


def system_engine_sample(watchdog=False):
    """Routine lines all afternoon (so the log covers the restart), working-set warnings before it, no shutdown lines.
    watchdog=True adds the engine's own restart reason, stuck-request lines and a core dump (wording as quoted in Qlik
    Community threads; invented values)."""
    cols = ["Sequence#", "Timestamp", "Level", "Hostname", "Logger", "Thread", "Id", "ServiceUser", "Message",
            "ProxySessionId", "ActiveUserDirectory", "ActiveUserId", "EngineTimestamp", "ProcessId", "SessionId", "AppId"]
    rows = []

    def add(t, level, msg):
        rows.append({"Sequence#": len(rows) + 1, "Timestamp": ts(t), "Level": level, "Hostname": HOST,
                     "Logger": "System.Engine.Engine", "Id": f"y{len(rows)}", "Message": msg})
    t = RDAY.replace(hour=13)
    while t <= RDAY.replace(hour=17, minute=30):
        if not (RDAY.replace(hour=15, minute=37) <= t <= RDAY.replace(hour=15, minute=50)):
            add(t, "INFO", "QrsSecurityManagement: retrieving rules for user")
        t += timedelta(minutes=7)
    for m in range(0, 26, 2):
        add(RDAY.replace(hour=15, minute=10) + timedelta(minutes=m), "WARN",
            "WorkingSet: Virtual Memory (163 GB) is growing beyond the low limit (179 GB)")
    if watchdog:
        add(RDAY.replace(hour=15, minute=33), "WARN", "LogChain: Request stuck report for Global::OpenApp")
        add(RDAY.replace(hour=15, minute=35), "WARN", "StdServer: Waiting on monitor")
        add(RDAY.replace(hour=15, minute=50, second=15), "ERROR",
            "Engine: Server aborted. Reason for restart: Phoenix detected: Server Watchdog is hung.")
        add(RDAY.replace(hour=15, minute=50, second=16), "ERROR",
            "Core dump: Writing core dump file to C:\\ProgramData\\Qlik\\Sense\\Engine\\CrashDumps\\Coredump_test.dmp")
    return tsv(cols, rows)


def _restart_tree(tmp_path, watchdog=False):
    arch = tmp_path / "ArchivedLogs" / HOST
    files = {
        "Engine/Trace/testhost_Performance_Engine_2026-03-25T08.00.00Z.log": perf_restart_sample(),
        "Engine/Trace/testhost_System_Engine_2026-03-25T08.00.00Z.log": system_engine_sample(watchdog),
        "Engine/Audit/testhost_AuditActivity_Engine_2026-03-25T08.00.00Z.log": storm_sample(),
        "Repository/Trace/testhost_Performance_Repository_2026-03-25T08.00.00Z.log": repo_perf_sample(),
        "Scheduler/Trace/testhost_TaskExecution_Scheduler_2026-03-25T08.00.00Z.log": tasks_sample(),
    }
    stamp = datetime(2026, 3, 25, 17, 40).timestamp()
    for rel, text in files.items():
        p = arch / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        os.utime(p, (stamp, stamp))
    return arch


@pytest.fixture
def restart_case(tmp_path):
    """ArchivedLogs-style tree for 25 Mar 2026 with the engine restart at 15:50."""
    return _restart_tree(tmp_path)


@pytest.fixture
def restart_case_watchdog(tmp_path):
    """The same, with the engine's own restart reason (watchdog), stuck requests and a core dump in the system log."""
    return _restart_tree(tmp_path, watchdog=True)

import qlik_events as qe
import qlik_logs as q
from conftest import engine_activity, perf_engine, repo_perf, system_engine, task_exec


def test_detects_each_kind():
    assert q.parse_log("p", perf_engine().encode())[0] == "performance"
    assert q.parse_log("r", repo_perf().encode())[0] == "repo_perf"
    assert q.parse_log("a", engine_activity().encode())[0] == "activity"
    assert q.parse_log("t", task_exec().encode())[0] == "task_exec"
    assert q.parse_log("s", system_engine().encode())[0] == "system"


def test_unused_log_is_skipped_politely():
    kind, df, msg = q.parse_log("x", b"Sequence#\tTimestamp\tLogger\n1\t20261020T090000.000+1000\tLicense\n")
    assert kind is None and "skipped" in msg


def test_powershell_outputs():
    kind, df = qe.parse_text(b"2026-10-20 09:00  5\n2026-10-20 10:00  7\n2026-10-20 11:00  9\n"
                             b"2026-10-20 12:00  4\n2026-10-20 13:00  3\n")
    assert kind == "audit_counts" and df["files"].sum() == 28 and bool(df["hourly"].iloc[0])
    text = ("\nDay        Files Sampled TopAppUser                    SharePct\n"
            "---        ----- ------- ----------                    --------\n"
            "2026-10-18    71 03:11   APP_A|Not available, someone       100\n"
            "2026-10-19   128 14:09   APP_A|Not available, other          17\n"
            "2026-10-20   258 13:25   APP_B|Not available, third          72\n")
    kind, df = qe.parse_text(text.encode("utf-16"))  # PowerShell Out-File writes UTF-16
    assert kind == "audit_sample" and list(df["app"]) == ["APP_A", "APP_A", "APP_B"] and df["share_pct"].max() == 100


def test_hex_ids_collapse_into_one_message_type():
    a = q.categorise("WARN", r"CGenericConnection: pipe[\\.\pipe\data_1e5cf0ccae6770739475b767b4a396b2386a1169.pip] x")
    b = q.categorise("WARN", r"CGenericConnection: pipe[\\.\pipe\data_4078ff5b4b5253e2c840ccd4d22dc021c269d3ce.pip] x")
    assert a == b

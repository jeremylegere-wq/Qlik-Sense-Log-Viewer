"""Reload failures (task runs + scheduler trace + reload logs) and proxy / login analysis."""
import pandas as pd

import qlik_events as qe
import qlik_logs as q
import qlik_proxy as qp
import qlik_reloads as qr
from conftest import APP1


def _load(share):
    parts = []
    listing = qe.scan_archive(str(share))
    for r in listing[listing["type"] != "Script"].itertuples():
        kind, df, _ = q.parse_log(r.name, open(r.path, "rb").read())
        if kind:
            parts.append((kind, df))
    return q.combine(parts), listing


def test_script_logs_are_found_and_read(share):
    data, listing = _load(share)
    files = qr.script_files(listing, 60)
    assert len(files) == 5 and set(files["app_id"]) == {APP1}
    runs = qr.script_runs(files)
    assert runs["status"].value_counts().to_dict() == {"failed": 3, "ok": 1, "incomplete": 1}
    assert "Cannot open file" in runs.loc[runs["status"] == "failed", "error"].iloc[0]
    assert runs.loc[runs["status"] == "incomplete", "last_line"].iloc[0].startswith("line 3")


def test_failures_join_sources_and_explain(share):
    data, listing = _load(share)
    te = data["task_exec"]
    sched = data["svc_system"][data["svc_system"]["service"] == "Scheduler"]
    scripts = qr.script_runs(qr.script_files(listing, 60))
    f = qr.failures(te, sched, scripts, {APP1: "Test app"})
    assert len(f) >= 3
    assert (f["why_source"] == "reload log").any()            # errors from the app's own log
    rc = qr.recurring(f)
    assert rc.iloc[0]["failures"] >= 2
    th = qr.task_health(te)
    assert {"failing_streak", "aborts_at"} <= set(th.columns)
    ev = qr.detect(te, scripts, {APP1: "Test app"})
    assert any(e["category"] == "Reload failing" for e in ev)  # 3 failed reload logs in a row


def test_failures_with_nothing_loaded():
    assert qr.failures(None, None, None).empty
    assert qr.task_health(None).empty
    assert qr.detect(None, None) == []


def test_proxy_classify_logins_and_problems(share):
    data, _ = _load(share)
    c = qp.classify(data["proxy_audit"])
    k = c["kind"].value_counts()
    assert k["login"] == 12 and k["repo_fail"] == 8 and k["probe"] > 3000
    lt = qp.login_times(c)
    assert len(lt) == 12 and lt["seconds"].between(5, 20).all()
    s = qp.summary(c)
    assert s["logins"] == 12 and s["problems"] == 8 and s["probe_share"] > 0.9
    assert len(qp.users(c)) == 12
    assert qp.apps_opened(c, {APP1: "Test app"}).iloc[0]["app"] == "Test app"
    ev = qp.detect(data)
    assert any("repository" in e["title"] for e in ev)


def test_proxy_with_no_data():
    assert qp.classify(None).empty
    assert qp.detect({}) == []
    assert qp.login_times(qp.classify(None)).empty


# ---- reload logs with control characters / NUL padding (Reload failures unreadable, Excel export failing) -------------
def _script_log(tmp_path, body: bytes, name="9f3c2a10-1111-2222-3333-444455556666.20261020T153942.0.log"):
    p = tmp_path / name
    p.write_bytes(body)
    return str(p)


_BAD = ("20261020T153942.000+1000 0001  Reload Executed By    DOMAIN\\svc\n"
        "20261020T153943.000+1000 0010 LOAD * FROM x\n"
        "20261020T153944.000+1000      The following error occurred:\n"
        "20261020T153944.000+1000      Connector reply error: bad \x00\x07 thing \x1b[31mred\x1b[0m\n"
        "20261020T153944.000+1000      Execution Failed\n")


def test_script_error_text_has_no_control_characters(tmp_path):
    import re
    import qlik_reloads as qr
    for enc in ("utf-8", "utf-16", "utf-16-le"):
        r = qr.read_script(_script_log(tmp_path, _BAD.replace("\x00", "").encode(enc) if enc != "utf-8" else _BAD.encode()))
        assert r["status"] == "failed"
        assert "Connector reply error" in r["error"]
        assert not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", r["error"]), repr(r["error"])


def test_nul_padded_script_log_is_still_read(tmp_path):
    import qlik_reloads as qr
    r = qr.read_script(_script_log(tmp_path, _BAD.encode() + b"\x00" * 40000))
    assert r["status"] == "failed" and "Connector reply error" in r["error"]


def test_failures_table_and_excel_export_survive_bad_characters(tmp_path):
    import io
    import pandas as pd
    import qlik_logs as q
    import qlik_reloads as qr
    files = pd.DataFrame([{"path": _script_log(tmp_path, _BAD.encode() + b"\x00" * 9000), "name": "n", "app_id": "app1",
                           "start": pd.Timestamp("2026-10-20 15:39:42"), "mtime": pd.Timestamp("2026-10-20 15:40"), "size_mb": 0.0}])
    F = qr.failures(None, None, qr.script_runs(files), {})
    assert len(F) == 1 and "\x00" not in F["error"].iloc[0] and "\x1b" not in F["error"].iloc[0]
    dirty = F.assign(error="x\x00y\x07z", end=F["end"].dt.tz_localize("UTC"))     # even uncleaned text and tz-aware times export
    with pd.ExcelWriter(io.BytesIO(), engine="openpyxl") as xw:
        q.xl_safe(dirty).to_excel(xw, sheet_name="Reload failures", index=False)


def test_scheduler_log_text_columns_are_cleaned_on_load():
    import qlik_logs as q
    cols = ["Sequence#", "Timestamp", "Level", "Hostname", "Logger", "Thread", "Id", "ServiceUser", "Message", "Exception",
            "StackTrace", "ProxySessionId", "TaskId", "TaskName", "AppId", "AppName", "ExecutionId", "ExecutingNodeId",
            "ExecutingNodeName", "Status", "StartTime", "StopTime", "Duration", "FailureReason", "Id2"]
    row = ["1", "20261020T153942.000+1000", "INFO", "h", "TaskExecution.x", "1", "i", "u", "Task execution finished", "", "",
           "0", "t", "Task\x00A", "a", "App", "e", "n", "node", "FinishedFail", "20261020T153900.000+1000",
           "20261020T153942.000+1000", "42000", "Reload failed \x1b[31mbad\x07", "x"]
    kind, df, msg = q.parse_log("x_TaskExecution_Scheduler.log", ("\t".join(cols) + "\n" + "\t".join(row) + "\n").encode())
    assert kind == "task_exec", msg
    assert "\x00" not in df["TaskName"].iloc[0] and "\x1b" not in df["FailureReason"].iloc[0] and "\x07" not in df["FailureReason"].iloc[0]

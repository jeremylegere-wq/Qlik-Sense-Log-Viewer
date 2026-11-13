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

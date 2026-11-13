"""Incident Investigator: coverage, evidence, scoring, notes, and the reported-issues register."""
import pandas as pd

import incident_rules as R
import qlik_events as qe
import qlik_incident as qi
import qlik_logs as q
import qlik_reports as qrp
from conftest import T0


def _data(share):
    parts = []
    for r in qe.scan_archive(str(share)).itertuples():
        if r.type == "Script":
            continue
        kind, df, _ = q.parse_log(r.name, open(r.path, "rb").read())
        if kind:
            parts.append((kind, df))
    return q.combine(parts)


def test_timezones():
    assert qi.to_server_time(pd.Timestamp("2026-10-21 08:00"), "UTC", 600) == pd.Timestamp("2026-10-21 18:00")
    assert qi.to_server_time(pd.Timestamp("2026-10-21 08:00"), qi.LOCAL_LABEL, qi.LOCAL_MIN) == pd.Timestamp("2026-10-21 08:00")
    assert qi.to_server_time(pd.Timestamp("2026-10-21 08:00"), qi.LOCAL_LABEL, qi.LOCAL_MIN + 60) == pd.Timestamp("2026-10-21 09:00")
    assert "UTC+10" in qi.tz_label(600)


def test_investigation_in_a_busy_window(share):
    data = _data(share)
    assert qi.server_offset_min(data) == 600
    inc = qi.Incident(pd.Timestamp(T0) + pd.Timedelta(minutes=62), symptom="Can't log in", users_affected=8)
    cov = qi.coverage(data, inc)
    assert 0 < cov["score"] <= 1 and set(cov["table"]["status"]) & {"Covers", "Partial"}
    ev = qi.evidence(data, inc, qe.detect_all(data), {}, None, cov)
    sig = {e["signal"] for e in ev}
    assert "repo_fail" in sig and "cpu_high" in sig
    ranked = qi.score(ev, inc, cov["score"])
    assert abs(sum(r["p"] for r in ranked) - 1) < 1e-9
    assert {r["id"] for r in ranked} == {h["id"] for h in R.HYPOTHESES}
    assert ranked[0]["id"] in ("proxy", "network_auth")       # login symptom + repository failures at the time
    note = qi.note(inc, cov, ranked, "server time")
    assert "likely" in note.lower() and "confirmed cause" in note.lower()


def test_cpu_spike_points_at_cpu(share):
    data = _data(share)
    inc = qi.Incident(pd.Timestamp(T0) + pd.Timedelta(minutes=60), symptom="Slow")   # repo CPU 90% at 50-65 min
    cov = qi.coverage(data, inc)
    ranked = qi.score(qi.evidence(data, inc, None, {}, None, cov), inc, cov["score"])
    assert [r["id"] for r in ranked[:3]].count("cpu") == 1


def test_no_data_and_data_ending_before():
    inc = qi.Incident(pd.Timestamp("2026-10-25 09:00"))
    cov = qi.coverage({}, inc)
    assert cov["score"] == 0 and cov["warnings"]
    ranked = qi.score(qi.evidence({}, inc, None, {}, None, cov), inc, cov["score"])
    assert ranked[0]["id"] == "no_data"


def test_data_ends_before_report(share):
    data = _data(share)
    inc = qi.Incident(pd.Timestamp("2026-11-30 09:00"), symptom="Slow", error_text="ProxyError.OnNoEngineAvailable")
    cov = qi.coverage(data, inc)
    assert any("ends before" in w for w in cov["warnings"])
    ranked = qi.score(qi.evidence(data, inc, None, {}, None, cov), inc, cov["score"])
    assert ranked[0]["id"] == "no_data"
    assert all(r["band"] != "High" for r in ranked if r["id"] != "no_data")


def test_error_text_and_symptom_change_priors():
    inc_a = qi.Incident(pd.Timestamp("2026-10-21 09:00"))
    inc_b = qi.Incident(pd.Timestamp("2026-10-21 09:00"), symptom="Session dropped mid-use",
                        error_text="ProxyError.OnNoEngineAvailable")
    a = {r["id"]: r["p"] for r in qi.score([], inc_a, 1.0)}
    b = {r["id"]: r["p"] for r in qi.score([], inc_b, 1.0)}
    assert b["engine_down"] > a["engine_down"] and b["cpu"] < a["cpu"]


def test_register_add_bulk_import_trends_and_jira(tmp_path):
    p = tmp_path / "reg.csv"
    R_ = qrp.load(p)
    R_, rid = qrp.add(R_, {"reported": pd.Timestamp("2026-10-21 08:15"), "app": "Sales_Dashboard", "reporter": "Jane",
                           "symptom": "Slow", "users_affected": 3})
    new, problems = qrp.read_bulk(qrp.template_csv(), "t.csv")
    assert len(new) == 2 and not problems
    R_, n = qrp.merge_bulk(R_, new)
    assert n["added"] == 2
    R_, n = qrp.merge_bulk(R_, new)
    assert n == {"added": 0, "skipped": 2}
    odd = b"Date,Time,Dashboard,User,Issue\n27/10/2026,14:05,Activity,Bob,report wouldn't load - spinning\nbad,,x,y,z\n"
    new2, problems2 = qrp.read_bulk(odd, "odd.csv", lambda t: t + pd.Timedelta(hours=1))
    assert len(new2) == 1 and problems2 and new2.loc[0, "symptom"] == "Slow"
    assert new2.loc[0, "reported"] == pd.Timestamp("2026-10-27 15:05")
    R_ = qrp.update(R_, rid, likely_cause="CPU saturation", likely_p=40.0)
    qrp.save(R_, p)
    back = qrp.load(p)
    assert len(back) == 3 and back.set_index("id").loc[rid, "likely_p"] == 40.0
    assert len(qrp.as_events(back)) == 3
    T = qrp.trends(back)
    assert T["total"] == 3 and len(T["causes"]) == 1
    prompt = qrp.jira_rovo_prompt(back.set_index("id").loc[rid].to_dict() | {"id": rid}, None, None, "server time", "ABC")
    assert "Jira project ABC" in prompt and "Sales_Dashboard" in prompt
    store = {"_reported": [{"id": "rold", "start": "2026-10-20 10:00", "end": "2026-10-20 10:30", "title": "timing out",
                            "app": "X", "user": "u", "detail": "", "logged": "2026-10-20 11:00"}]}
    mig, n = qrp.migrate_events_store(back, store)
    assert n == 1 and "rold" in set(mig["id"])
    assert qrp.migrate_events_store(mig, store)[1] == 0

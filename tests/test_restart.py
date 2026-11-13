"""Engine restart signature, the restart hypothesis and its cause ranking, and the sample restart case."""
import pandas as pd

import incident_rules as R
import qlik_events as qe
import qlik_incident as qi
import qlik_logs as q
import qlik_reports as qrp
import qlik_restart as qrs
from conftest import RDAY, perf_restart_sample, perf_engine


def _perf(text):
    kind, df, _ = q.parse_log("x_Performance_Engine.log", text.encode())
    assert kind == "performance"
    return df


def _data(arch):
    parts = []
    for r in qe.scan_archive(str(arch)).itertuples():
        kind, df, _ = q.parse_log(r.name, open(r.path, "rb").read())
        if kind:
            parts.append((kind, df))
    return q.combine(parts)


def test_signature_on_the_sample_restart():
    s = qrs.find(_perf(perf_restart_sample()))
    assert len(s) == 1
    r = s.iloc[0]
    assert r["n"] == 5 and r["strength"] == "Strong" and set(r["signals"]) == set(qrs.SIGNALS)
    assert r["start"] == pd.Timestamp("2026-03-25 15:50:21") and r["end"] == pd.Timestamp("2026-03-25 15:51:12")
    assert r["users_before"] == 45 and r["users_lost"] == 45
    assert r["gap_start"] == pd.Timestamp("2026-03-25 15:36") and r["gap_end"] == pd.Timestamp("2026-03-25 15:50:21")
    assert r["vm_before"] > 150 and r["vm_low"] < 1 and r["rebuilt"] and 100 <= r["vm_settled"] <= 115
    assert r["cache_after"] == 100 and r["pid_after"] == "23456"
    assert r["recovery_min"] > 0


def test_cache_purge_is_not_a_restart():
    """Memory 180 GB -> 75 GB with users steady: a cache purge, not a restart."""
    assert qrs.find(_perf(perf_restart_sample(cache_purge=True))).empty


def test_one_signal_alone_is_weak_and_raises_no_event():
    P = _perf(perf_engine(n=24))
    P.loc[12:, "VM_GB"] = 10          # memory falls >70% but users, CPU and the process carry on
    s = qrs.find(P)
    assert len(s) == 1 and s.iloc[0]["n"] == 1 and s.iloc[0]["strength"] == "Weak"
    assert qrs.restarts(s).empty
    assert not qe.detect_restarts({"performance": P})


def test_restart_is_a_high_event_with_users_lost(restart_case):
    ev = qe.detect_all(_data(restart_case))
    rs = ev[ev["category"].eq("Restart")]
    assert len(rs) == 1
    r = rs.iloc[0]
    assert r["severity"] == "High" and "45 users lost" in r["title"] and r["metric"] == "45 users lost"
    assert r["start"] == pd.Timestamp("2026-03-25 15:50:21") and r["end"] == pd.Timestamp("2026-03-25 15:51:12")
    # the load building up before it is detected too (upstream causes)
    assert {"Request storm", "Reload pile-up"} <= set(ev["category"])


def _investigate(arch, reported, symptom="Session dropped mid-use", users=30):
    data = _data(arch)
    events = qe.detect_all(data)
    inc = qi.Incident(pd.Timestamp(reported), symptom=symptom, users_affected=users)
    cov = qi.coverage(data, inc)
    ev = qi.evidence(data, inc, events, {}, None, cov)
    ranked = qi.score(ev, inc, cov["score"])
    rf = qi.restart_finding(data, inc, events, {}, qrs.find(data["performance"]))
    return data, inc, cov, ev, ranked, rf


def test_sample_report_engine_restart_ranks_first(restart_case):
    """The confirmed outcome: an engine restart at about 15:50:21-15:51:12, after a 15:36-15:50 gap."""
    data, inc, cov, ev, ranked, rf = _investigate(restart_case, "2026-03-25 16:00")
    main = [r for r in ranked if r["role"] == "cause"]
    top = main[0]
    assert top["id"] == "engine_restart" and top["band"] == "High" and top["p"] > 0.85
    assert abs(sum(r["p"] for r in ranked) - 1) < 1e-9
    # the signature evidence and the gap are shown
    sup = " | ".join(s["text"] for s in top["support"])
    assert "5 of 5 signals" in sup and "15:50:21–15:51:12" in sup and "45 users lost" in sup
    assert "15:36–15:50" in sup
    assert any(g["kind"] == "performance" and g["start"] == pd.Timestamp("2026-03-25 15:36") for g in cov["gaps"])
    # a request storm and reload pile-up are upstream causes of the restart, not competitors
    roles = {r["id"]: r["role"] for r in ranked}
    assert roles["engine_overload"] == "upstream" and roles["reload_pileup"] == "upstream"
    assert all(r["id"] not in R.RESTART_UPSTREAM for r in main)
    seen = {u["id"]: u["seen"] for u in rf["upstream"]}
    assert any("Request storm" in t for t in seen["engine_overload"]) and any("reloads" in t for t in seen["reload_pileup"])
    # cause sub-ranking: stall / overload before the restart is plausible but not confirmed
    first = rf["ranked"][0]
    assert first["id"] == "stall" and first["verdict"] == "Plausible – not confirmed"
    joined = " ".join(first["for"])
    assert "Request storm" in joined and "reloads running at once" in joined and "15:36–15:50" in joined
    assert not rf["confirmed"] and rf["insufficient"].startswith("Insufficient data to confirm the cause")
    assert all(c["verdict"] != "Confirmed" for c in rf["ranked"])
    assert {c["id"] for c in rf["ranked"]} == {"stall", "crash", "manual", "auto"}
    assert next(c for c in rf["ranked"] if c["id"] == "manual")["verdict"] == "Unlikely"     # business hours, 45 users on
    # what to check next
    checks = " ".join(rf["checks"])
    for must in ("7031", "7034", "7036", "Application log", "System_Engine", "Service Dispatcher", "System_Repository",
                 "Dump files", "maintenance calendar", "full history"):
        assert must in checks, must
    note = qi.note(inc, cov, ranked, "server time", restart=rf)
    assert "Insufficient data to confirm the cause" in note and "not a confirmed cause" in note
    assert "Stall or overload before the restart" in note and "Plausible – not confirmed" in note
    jira = qrp.jira_rovo_prompt({"reported": inc.reported, "symptom": inc.symptom, "app": "Sales_Dashboard"}, ranked,
                                cov["score"], "server time", restart=rf)
    assert "Engine restart 15:50:21–15:51:12" in jira and "7034" in jira


def test_a_late_report_still_finds_the_restart(restart_case):
    *_, ranked, rf = _investigate(restart_case, "2026-03-25 16:20", symptom="Not sure", users=0)
    assert rf is not None and [r for r in ranked if r["role"] == "cause"][0]["id"] == "engine_restart"


def test_no_restart_no_boost(share):
    data = _data(share)
    from conftest import T0
    inc = qi.Incident(pd.Timestamp(T0) + pd.Timedelta(minutes=60), symptom="Slow")
    cov = qi.coverage(data, inc)
    ev = qi.evidence(data, inc, None, {}, None, cov)
    assert any(e["signal"] == "restart_signature" and e["value"] < 0 for e in ev)
    ranked = qi.score(ev, inc, cov["score"])
    assert ranked[0]["id"] != "engine_restart" and all(r["role"] == "cause" for r in ranked)
    assert qi.restart_finding(data, inc) is None


def test_pattern_one_off_or_recurring():
    one = qrs.find(_perf(perf_restart_sample()))
    assert "one-off" in qrs.pattern(one, (RDAY, RDAY + pd.Timedelta(days=1)))
    two = pd.concat([one, one.assign(start=one["start"] + pd.Timedelta(days=7), end=one["end"] + pd.Timedelta(days=7),
                                     id="x")], ignore_index=True)
    txt = qrs.pattern(two, (RDAY, RDAY + pd.Timedelta(days=8)))
    assert txt.startswith("2 restarts") and "same time of day" in txt
    assert qrs.pattern(qrs.find(None)).startswith("No engine restarts")


def test_restart_history_from_archive_files(restart_case):
    files = qe.scan_archive(str(restart_case))
    P = qrs.read_archive_performance(files, 30, lambda p: open(p, "rb").read())
    s = qrs.restarts(qrs.find(P))
    assert len(s) == 1 and s.iloc[0]["n"] == 5


def test_missing_data_does_not_crash():
    assert qrs.find(None).empty and qrs.find(pd.DataFrame()).empty
    P = _perf(perf_restart_sample()).drop(columns=["ProcessId", "server_started", "cache_hit_pct"])
    s = qrs.find(P)
    assert len(s) == 1 and s.iloc[0]["n"] == 3                 # collapse, memory, gap: still strong
    c = qrs.causes(s.iloc[0], {"performance": P})
    assert c["ranked"] and next(x for x in c["ranked"] if x["id"] == "crash")["verdict"] == "Can't tell from these logs"


def test_engine_start_times_and_the_usual_slot():
    """'Server Started' gives every engine start; weekly Sunday 02:15 starts are the usual (scheduled-looking) slot,
    and the 25 Mar 15:50 restart is outside it."""
    P = _perf(perf_restart_sample())
    extra = []
    for day in (8, 15):
        x = P.head(2).copy()
        x["ts"] = x["ts"].apply(lambda t, d=day: t.replace(day=d))
        x["server_started"] = pd.Timestamp(f"2026-03-{day:02d} 02:15:13")
        x["ProcessId"] = f"9{day}"
        extra.append(x)
    P2 = pd.concat(extra + [P], ignore_index=True).sort_values("ts").reset_index(drop=True)
    st = qrs.engine_starts(P2)
    assert len(st) == 4 and st["started"].dt.day_of_week.tolist().count(6) == 3
    slot = qrs.usual_slot(st, exclude=pd.Timestamp("2026-03-25 15:50:58"))
    assert slot["weekday"] == "Sun" and slot["time"] == "02:15" and slot["count"] == 3
    s = qrs.restarts(qrs.find(P2))
    s = s[s["start"].dt.day == 25].iloc[0]
    man = next(c for c in qrs.causes(s, {"performance": P2})["ranked"] if c["id"] == "manual")
    assert any("usually restarts on Sun at about 02:15" in t for t in man["against"]) and man["verdict"] == "Unlikely"


def test_engines_own_restart_reason_is_picked_up(restart_case_watchdog):
    """Qlik's watchdog writes 'Reason for restart: Phoenix detected: Server Watchdog is hung' itself. It is Qlik's own
    record, so the stall and auto-restart causes read 'Stated in the engine log'; a manual restart is ruled against."""
    data, inc, cov, ev, ranked, rf = _investigate(restart_case_watchdog, "2026-03-25 16:00")
    by = {c["id"]: c for c in rf["ranked"]}
    assert by["stall"]["verdict"] == "Stated in the engine log"
    assert by["auto"]["verdict"] == "Stated in the engine log"
    assert by["manual"]["verdict"] == "Unlikely"
    assert any("Phoenix detected" in f for f in by["auto"]["for"])
    assert any("stuck" in f.lower() for f in by["stall"]["for"])
    assert any("core" in f.lower() and "dump" in f.lower() for f in by["crash"]["for"])     # the dump it wrote
    assert rf["confirmed"] is False and "Insufficient data to confirm the cause" in rf["insufficient"]
    assert "states a reason" in rf["insufficient"]
    assert any("Reason for restart" in c and "Phoenix" in c for c in rf["checks"])
    assert any("CrashDumps" in c for c in rf["checks"])
    assert [r for r in ranked if r["role"] == "cause"][0]["id"] == "engine_restart"


def test_without_the_watchdog_line_nothing_changes(restart_case):
    data, inc, cov, ev, ranked, rf = _investigate(restart_case, "2026-03-25 16:00")
    assert all(c["verdict"] != "Stated in the engine log" for c in rf["ranked"])
    assert "Phoenix" not in " ".join(f for c in rf["ranked"] for f in c["for"])

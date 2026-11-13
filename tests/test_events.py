import pandas as pd

import qlik_events as qe
import qlik_logs as q
from conftest import engine_activity, perf_engine, repo_perf, system_engine, task_exec


def load(*texts):
    return q.combine([q.parse_log("f", t.encode())[:2] for t in texts])


def test_request_storm_found_per_app_even_in_one_session():
    ev = qe.detect_all(load(engine_activity(per_min=900, minutes=3, multi_app=True)))
    storms = ev[ev["category"] == "Request storm"]
    assert len(storms) == 1 or set(storms["app"]) <= {"APP_A", "APP_B", "APP_C"}
    assert not storms.empty and (storms["user"] == "noisy").all()
    assert not (ev["user"].str.startswith("quiet")).any()


def test_cpu_breaches():
    ev = qe.detect_all(load(perf_engine(), repo_perf()), cpu_thr=80)
    assert {"Engine CPU", "Server CPU"} <= set(ev["category"])


def test_reload_events():
    ev = qe.detect_all(load(task_exec()), conc_thr=10)
    cats = set(ev["category"])
    assert {"Reload failure", "Reload load", "Reload pile-up"} <= cats


def test_engine_health_warning_cluster():
    ev = qe.detect_all(load(system_engine()))
    assert "Engine CPU" in set(ev["category"])


def test_event_ids_are_stable():
    d = load(task_exec(), repo_perf())
    assert list(qe.detect_all(d)["id"]) == list(qe.detect_all(d)["id"])


def test_store_roundtrip_and_reported_issues(tmp_path):
    path = tmp_path / "store.json"
    store = {"abc": {"status": "Investigating", "owner": "me", "notes": "n"}}
    eid = qe.add_reported(store, "User says slow", "2026-10-21 10:00", "2026-10-21 10:30", "High", "APP_A")
    qe.save_store(store, path)
    back = qe.load_store(path)
    assert back["abc"]["status"] == "Investigating"
    rep = qe.reported_events(back)
    assert rep.iloc[0]["category"] == "Reported issue" and rep.iloc[0]["id"] == eid
    others = pd.DataFrame([{"id": "x", "start": pd.Timestamp("2026-10-21 10:38"), "end": pd.Timestamp("2026-10-21 10:39")},
                           {"id": "y", "start": pd.Timestamp("2026-10-21 14:00"), "end": pd.Timestamp("2026-10-21 14:10")}])
    assert list(qe.overlapping(others, "2026-10-21 10:00", "2026-10-21 10:30", 30)["id"]) == ["x"]
    qe.remove_reported(back, eid)
    assert qe.reported_events(back).empty


def test_fault_summary():
    ev = pd.Series({"title": "Request storm on APP_A (noisy)", "start": pd.Timestamp("2026-10-21 10:00"),
                    "end": pd.Timestamp("2026-10-21 10:30"), "severity": "High", "category": "Request storm",
                    "app": "APP_A", "user": "noisy", "detail": "Lots of requests.", "notes": "user rang the desk"},
                   name="abc123")
    rel = pd.DataFrame([{"start": pd.Timestamp("2026-10-21 10:38"), "category": "Engine CPU", "title": "CPU high"}])
    text = qe.fault_summary(ev, rel, "9.9.9")
    assert "Request storm on APP_A" in text and "10:00 to 10:30" in text and "CPU high" in text
    assert "user rang the desk" in text and "abc123" in text and "v9.9.9" in text
    import site_config
    assert qe.FAULT_URL == site_config.FAULT_URL


def test_cpu_spikes_line_up_events_and_reloads():
    d = load(perf_engine(), repo_perf(), task_exec())
    ev = qe.detect_all(d)
    sp = qe.cpu_spikes(d, warn_thr=60, events=ev)
    assert set(sp["source"]) == {"Engine", "Server"}
    assert (sp["peak_cpu"] >= 60).all()
    assert {"events", "event_titles", "reloads_running", "busiest_reloads"} <= set(sp.columns)
    assert sp["reloads_running"].max() >= 1


def test_cpu_spikes_fall_back_to_highest_samples():
    d = load(perf_engine(cpu=10))
    sp = qe.cpu_spikes(d, warn_thr=99)
    assert len(sp) == 5 and (sp["peak_cpu"] < 99).all()


def test_diagnose_points_a_cpu_event_at_the_overlapping_cause():
    d = load(perf_engine(), repo_perf(), task_exec(), engine_activity(per_min=900, minutes=3))
    ev = qe.detect_all(d, cpu_thr=80)
    cpu = ev[ev["category"] == "Server CPU"].iloc[0]
    out = qe.diagnose(cpu, ev, d)
    assert set(out) == {"root", "failure", "impact"}
    assert out["failure"]["head"] == cpu["title"]
    storm = ev[ev["category"] == "Request storm"].iloc[0]
    assert qe.diagnose(storm, ev, d)["root"]["head"] == storm["title"]    # a cause is its own root

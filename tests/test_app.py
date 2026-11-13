"""Smoke test: the whole app renders against a synthetic archive without errors on any page."""
import os

import pandas as pd
from streamlit.testing.v1 import AppTest

import ui

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


def test_app_renders(archive, tmp_path, monkeypatch):
    monkeypatch.setenv("QLIK_ARCHIVE_ROOT", str(archive))
    monkeypatch.setenv("QLIK_EVENT_STORE", str(tmp_path / "store.json"))
    monkeypatch.setenv("QLIK_EVENT_DATA", str(tmp_path / "data"))
    at = AppTest.from_file(APP, default_timeout=180).run()
    assert not at.exception, [e.value for e in at.exception]
    assert not at.error, [e.value for e in at.error]
    assert len(at.sidebar.button) == len(ui.NAV)  # one rail button per page


def test_every_page_renders(share, tmp_path, monkeypatch):
    monkeypatch.setenv("QLIK_ARCHIVE_ROOT", str(share))
    monkeypatch.setenv("QLIK_EVENT_STORE", str(tmp_path / "store.json"))
    monkeypatch.setenv("QLIK_EVENT_DATA", str(tmp_path / "data"))
    at = AppTest.from_file(APP, default_timeout=180)
    for page in [p for p, _, _ in ui.NAV]:
        at.session_state["page"] = page
        at.run()
        assert not at.exception, (page, [e.value for e in at.exception])
        assert not at.error, (page, [e.value for e in at.error])


def test_app_landing_when_share_unreachable(tmp_path, monkeypatch):
    monkeypatch.setenv("QLIK_ARCHIVE_ROOT", str(tmp_path / "missing"))
    monkeypatch.setenv("QLIK_EVENT_STORE", str(tmp_path / "store.json"))
    monkeypatch.setenv("QLIK_EVENT_DATA", str(tmp_path / "data"))
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    assert any("Can't reach" in w.value for w in at.warning)


def test_pages_that_work_without_logs(tmp_path, monkeypatch):
    monkeypatch.setenv("QLIK_ARCHIVE_ROOT", str(tmp_path / "missing"))
    monkeypatch.setenv("QLIK_EVENT_STORE", str(tmp_path / "store.json"))
    monkeypatch.setenv("QLIK_EVENT_DATA", str(tmp_path / "data"))
    at = AppTest.from_file(APP, default_timeout=120)
    for page in ["Apps", "Storage", "Reported issues"]:
        at.session_state["page"] = page
        at.run()
        assert not at.exception, (page, [e.value for e in at.exception])
        assert not at.error, (page, [e.value for e in at.error])


def test_report_an_issue_saves_and_investigates(share, tmp_path, monkeypatch):
    import datetime as dt
    monkeypatch.setenv("QLIK_ARCHIVE_ROOT", str(share))
    monkeypatch.setenv("QLIK_EVENT_STORE", str(tmp_path / "store.json"))
    monkeypatch.setenv("QLIK_EVENT_DATA", str(tmp_path / "data"))
    at = AppTest.from_file(APP, default_timeout=180)
    at.session_state["page"] = "Reported issues"
    at.run()
    at.date_input[0].set_value(dt.date(2026, 10, 20))
    at.radio(key="new_tz").set_value("Server time")            # the clock the logs use, whatever this PC's zone is
    at.time_input[0].set_value(dt.time(10, 2))
    at.text_input(key="new_who").input("Jane")
    at.selectbox(key="new_sym").set_value("Can't log in")
    [b for b in at.button if b.label == "Save and investigate"][0].click()
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    rid = at.session_state["iss_pick"]
    assert rid.startswith("i")
    assert any("Likely causes" in m.value for m in at.markdown)
    import qlik_reports as qrp
    reg = qrp.load(tmp_path / "data" / "reported_issues.csv")
    assert len(reg) == 1 and reg.loc[0, "likely_cause"]
    assert reg.loc[0, "reported"] == pd.Timestamp("2026-10-20 10:02")          # the time typed, not 'now'
    # edit it: move the time and change the symptom
    import streamlit as st_
    if tuple(int(x) for x in st_.__version__.split(".")[:2]) < (1, 51):
        # Streamlit 1.50's test harness trips over the cleared 'new report' form from the run before (a browser
        # doesn't; checked by hand), so carry on in a fresh session opened on the saved report
        at = AppTest.from_file(APP, default_timeout=180)
        at.session_state["page"] = "Reported issues"
        at.session_state["iss_pick"] = rid
        at.run()
    at.radio(key=f"ed_{rid}_tz").set_value("Server time")
    at.date_input(key=f"ed_{rid}_day").set_value(dt.date(2026, 10, 20))
    at.time_input(key=f"ed_{rid}_time").set_value(dt.time(9, 40))
    at.selectbox(key=f"ed_{rid}_sym").set_value("Slow")
    [b for b in at.button if b.label == "Save changes and investigate again"][0].click()
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    reg = qrp.load(tmp_path / "data" / "reported_issues.csv")
    assert reg.loc[0, "reported"] == pd.Timestamp("2026-10-20 09:40") and reg.loc[0, "symptom"] == "Slow"
    picker = [s_ for s_ in at.selectbox if (s_.key or "").startswith("iss_pick_")][0]
    assert picker.value == rid and any("09:40" in o for o in picker.options)     # the list shows the new time
    picker.set_value("__new")                                                     # and can still be changed
    at.run()
    assert not at.exception and at.session_state["iss_pick"] == "__new"


def test_apps_and_storage_with_app_list_but_no_share_scan(tmp_path, monkeypatch):
    """The first run on a PC: a QMC export imported, the share scan not finished yet."""
    from conftest import APP1
    import qlik_catalog as qc
    monkeypatch.setenv("QLIK_ARCHIVE_ROOT", str(tmp_path / "missing"))
    monkeypatch.setenv("QLIK_EVENT_STORE", str(tmp_path / "store.json"))
    monkeypatch.setenv("QLIK_EVENT_DATA", str(tmp_path / "data"))
    new = qc.read_export(f'"Name","ID","Stream","Base memory size (MB)"\n"Sales_Dashboard","{APP1}","Finance","120.5"\n'.encode())
    qc.save(qc.merge(qc.load(tmp_path / "none.csv"), new)[0], tmp_path / "data" / "app_catalogue.csv")
    at = AppTest.from_file(APP, default_timeout=120)
    for page in ["Apps", "Storage", "Overview", "Reported issues"]:
        at.session_state["page"] = page
        at.run()
        assert not at.exception, (page, [e.value for e in at.exception])
        assert not at.error, (page, [e.value for e in at.error])


def test_restart_history_page_and_the_sample_report(restart_case, tmp_path, monkeypatch):
    """The sample restart case in the app: the restart on Restart history, and the report investigated with the restart
    first, its causes ranked and 'insufficient data to confirm the cause' visible."""
    import qlik_reports as qrp
    monkeypatch.setenv("QLIK_ARCHIVE_ROOT", str(restart_case))
    monkeypatch.setenv("QLIK_EVENT_STORE", str(tmp_path / "store.json"))
    monkeypatch.setenv("QLIK_EVENT_DATA", str(tmp_path / "data"))
    reg, rid = qrp.add(qrp.load(tmp_path / "data" / "reported_issues.csv"),
                       {"reported": pd.Timestamp("2026-03-25 16:00"), "app": "Sales_Dashboard", "symptom": "Session dropped mid-use",
                        "users_affected": 30, "reporter": "Service desk", "status": "Open", "source": "manual"})
    qrp.save(reg, tmp_path / "data" / "reported_issues.csv")
    at = AppTest.from_file(APP, default_timeout=180)
    at.session_state["page"] = "Restart history"
    at.run()
    assert not at.exception and not at.error, [e.value for e in at.exception] + [e.value for e in at.error]
    md = " ".join(m.value for m in at.markdown)
    assert "Engine restart Wed 25 Mar 15:50:21–15:51:12" in md and "45 users lost" in md
    assert "Insufficient data to confirm the cause" in md
    at.session_state["rh_weak"] = True
    at.run()
    assert not at.exception
    at.session_state["rh_scope"] = "Archive history"                # read the archive's Performance_Engine files
    at.run()
    assert not at.exception and not at.error, [e.value for e in at.exception] + [e.value for e in at.error]
    assert "Engine restart Wed 25 Mar 15:50:21–15:51:12" in " ".join(m.value for m in at.markdown)
    at.session_state["page"] = "Reported issues"
    at.session_state["iss_pick"] = rid
    at.run()
    assert not at.exception and not at.error, [e.value for e in at.exception] + [e.value for e in at.error]
    md = " ".join(m.value for m in at.markdown)
    assert "Engine restart found in this window" in md and "Insufficient data to confirm the cause" in md
    assert "Possible upstream causes" in md
    frames = [d_.value for d_ in at.dataframe]
    first = next(f_ for f_ in frames if "Likely cause" in f_)               # the main 'likely causes' table
    assert first.iloc[0]["Likely cause"].startswith("Engine restart") and first.iloc[0]["Confidence"] == "High"
    first_cause = md[md.index("Insufficient data to confirm the cause"):]                # what may have caused the restart
    assert first_cause.index("1. Stall or overload before the restart") < first_cause.index("2. ")
    assert "Plausible – not confirmed" in first_cause[:first_cause.index("2. ")]
    assert "Qlik Sense engine service restarted unexpectedly" in md            # Qlik Community searches for the issue
    at.session_state["page"] = "Events"
    at.run()
    assert not at.exception and not at.error


def test_qlik_community_search_page(restart_case, tmp_path, monkeypatch):
    """The search page works without logs, takes site detail out of what is pasted, and lists messages from the logs."""
    monkeypatch.setenv("QLIK_ARCHIVE_ROOT", str(tmp_path / "missing"))
    monkeypatch.setenv("QLIK_EVENT_STORE", str(tmp_path / "store.json"))
    monkeypatch.setenv("QLIK_EVENT_DATA", str(tmp_path / "data"))
    at = AppTest.from_file(APP, default_timeout=120)
    at.session_state["page"] = "Qlik Community search"
    at.run()
    assert not at.exception and not at.error, [e.value for e in at.exception] + [e.value for e in at.error]
    at.text_area(key="cs_text").set_value(r"Cannot open file 'lib://Data/Sales.qvd' on srv01.corp.example.org for CORP\jdoe").run()
    assert not at.exception
    md = " ".join(m.value for m in at.markdown)
    assert "Cannot open file" in md and "srv01" not in md and "jdoe" not in md and "Sales.qvd" not in md
    monkeypatch.setenv("QLIK_ARCHIVE_ROOT", str(restart_case))
    at2 = AppTest.from_file(APP, default_timeout=180)
    at2.session_state["page"] = "Qlik Community search"
    at2.run()
    assert not at2.exception and not at2.error, [e.value for e in at2.exception] + [e.value for e in at2.error]
    msgs = [m for f_ in at2.dataframe if "Message (as searched)" in f_.value for m in f_.value["Message (as searched)"]]
    assert any("Virtual Memory is growing beyond the low limit" in m for m in msgs)     # the working-set warnings, grouped


def test_log_source_selector(archive, tmp_path, monkeypatch):
    monkeypatch.setenv("QLIK_ARCHIVE_ROOT", str(archive))
    monkeypatch.setenv("QLIK_EVENT_STORE", str(tmp_path / "store.json"))
    monkeypatch.setenv("QLIK_EVENT_DATA", str(tmp_path / "data"))
    at = AppTest.from_file(APP, default_timeout=180).run()
    radio = next(r for r in at.radio if r.key == "log_source")
    assert radio.value == "Qlik server share" and len(radio.options) == 3
    for choice in ("Local folder", "Upload files"):
        at.session_state["log_source"] = choice
        at.run()
        assert not at.exception, (choice, [e.value for e in at.exception])
    labels = [t.label for t in at.text_input]
    assert "ArchivedLogs folder" not in labels  # the share box is hidden when the share isn't the source

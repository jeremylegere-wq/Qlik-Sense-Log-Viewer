"""Qlik Community search: what is taken out of a search, and the links built."""
import pandas as pd

import qlik_search as qs_


def test_scrub_removes_site_details():
    raw = (r"20261028T155021.000+1000 Connection to \\srv01.corp.example.org\Share$\Apps failed for CORP\jdoe "
           r"(jane.doe@example.org) from 10.1.2.3:4747 on app 1a2b3c4d-1111-2222-3333-444455556666 "
           r"Cannot open file 'lib://Data/Sales.qvd' [Sales] at C:\ProgramData\Qlik\Sense\Log host=node01 "
           r"https://qlik.example.org/hub id 0123456789abcdef0123 at 28/10/2026 15:50")
    s = qs_.scrub(raw, 40)
    for bad in ("srv01", "corp.example", "jdoe", "jane.doe", "10.1.2.3", "1a2b3c4d", "Sales", "ProgramData", "node01",
                "qlik.example", "0123456789abcdef", "2026", "15:50", "CORP"):
        assert bad not in s, (bad, s)
    assert "Connection to" in s and "failed for" in s and "Cannot open file" in s


def test_links_limit_to_qlik_sites_and_encode():
    it = qs_.item("x", 'Qlik Sense "Server Watchdog is hung"')
    assert it["google"].startswith("https://www.google.com/search?q=")
    assert "site%3Acommunity.qlik.com" in it["google"] and "site%3Ahelp.qlik.com" in it["google"]
    assert it["community"].startswith("https://community.qlik.com/") and "Watchdog" in it["community"]


def test_restart_search_uses_the_engines_own_reason():
    ab = pd.DataFrame({"Message": ["Engine: Server aborted. Reason for restart: Phoenix detected: Server Watchdog is hung."]})
    out = qs_.for_restart({"context": {"abort": ab, "stuck": pd.DataFrame(), "load": [], "low_limit": False}})
    assert out[0]["query"] == 'Qlik Sense "Phoenix detected: Server Watchdog is hung."'


def test_incident_search_from_error_text_and_causes():
    ranked = [{"id": "engine_restart", "title": "Engine restart", "role": "cause"},
              {"id": "memory", "title": "Memory", "role": "upstream"},
              {"id": "proxy", "title": "Proxy", "role": "cause"}]
    out = qs_.for_incident("Session dropped mid-use", "ProxyError.OnNoEngineAvailable for user CORP\\jdoe", ranked)
    qs = [o["query"] for o in out]
    assert any("ProxyError.OnNoEngineAvailable" in q for q in qs) and not any("jdoe" in q for q in qs)
    assert any(q.startswith("Qlik Sense engine service restarted unexpectedly") for q in qs)
    assert not any("working set limit memory pressure" in q for q in qs)          # upstream causes aren't searched
    assert len(qs) == len(set(qs))


def test_event_and_empty_inputs():
    assert qs_.for_event({"category": "Request storm", "title": "x", "detail": "y"})
    assert qs_.for_event({"category": "Something new", "title": "Odd thing on srv01.corp.example.org", "detail": ""})
    assert qs_.for_error("") == [] and qs_.for_incident() == []


def test_common_messages_groups_alike_lines_and_scrubs():
    df = pd.DataFrame({"ts": pd.to_datetime(["2026-10-28 10:00", "2026-10-28 10:05", "2026-10-28 10:06"]),
                       "Level": ["WARN", "WARN", "INFO"],
                       "Message": ["Connection to srv01.corp.example.org failed for CORP\\jdoe after timeout",
                                   "Connection to srv02.corp.example.org failed for CORP\\asmith after timeout",
                                   "Routine line nothing to see"]})
    cm = qs_.common_messages({"system": df})
    assert len(cm) == 1 and cm.loc[0, "count"] == 2
    assert "srv0" not in cm.loc[0, "message"] and "jdoe" not in cm.loc[0, "message"]
    assert qs_.common_messages({}).empty


def test_free_text_search():
    assert qs_.for_text("engine slow") [0]["query"] == "Qlik Sense engine slow"
    assert qs_.for_text("") == []
    long = qs_.for_text("ProxyError.OnNoEngineAvailable while opening the hub for CORP\\jdoe")
    assert long and all("jdoe" not in i["query"] for i in long)

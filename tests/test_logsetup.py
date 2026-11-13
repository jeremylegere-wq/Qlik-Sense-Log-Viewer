"""Log setup guide: history check, size estimate, archive script."""
import pandas as pd

import qlik_logsetup as ls


def _listing():
    rows = []
    for d in range(0, 40):
        rows.append(["p", f"n_Performance_Engine_{d}.log", "Engine", "Performance_Engine",
                     pd.Timestamp("2026-03-25") - pd.Timedelta(days=d), 2.0])
    for d in (0, 1, 2, 20, 21):  # a hole between day 2 and 20
        rows.append(["p", f"n_System_Engine_{d}.log", "Engine", "System_Engine",
                     pd.Timestamp("2026-03-25") - pd.Timedelta(days=d), 1.0])
    rows.append(["p", "n_Audit_Proxy_x.log", "Proxy", "Audit_Proxy", pd.Timestamp("2026-03-01"), 1.0])
    return pd.DataFrame(rows, columns=["path", "name", "folder", "type", "mtime", "size_mb"])


def test_history_status():
    h = ls.history(_listing(), need_days=15).set_index("log type")
    assert h.loc["Performance_Engine", "status"] == "OK"
    assert h.loc["System_Engine", "status"].startswith("Hole")
    assert h.loc["Audit_Proxy", "status"].startswith("Stopped")


def test_short_history():
    h = ls.history(_listing(), need_days=90).set_index("log type")
    assert h.loc["Performance_Engine", "status"].startswith("Short")


def test_missing_and_empty():
    assert "Performance_Repository" in ls.missing_types(_listing())
    assert ls.history(pd.DataFrame()).empty
    assert ls.storage_estimate(pd.DataFrame(), 30)["gb"] == 0


def test_storage_estimate_scales():
    a, b = ls.storage_estimate(_listing(), 30), ls.storage_estimate(_listing(), 60)
    assert abs(b["gb"] - 2 * a["gb"]) < 1e-9 and a["per_day_mb"] > 0


def test_script_moves_never_deletes():
    s = ls.archive_script(r"\\a\b", r"D:\h", 35, dry_run=True)
    assert "/MOV" in s and "/MINAGE:$keep" in s and "$keep = 35" in s and "$dry  = $true" in s
    assert "Remove-Item" not in s and "/PURGE" not in s and "/MIR" not in s
    assert "$dry  = $false" in ls.archive_script("", "", 5, dry_run=False)

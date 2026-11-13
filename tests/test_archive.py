import qlik_events as qe


def test_scan_and_pick(archive):
    files = qe.scan_archive(str(archive))
    assert {"Performance_Engine", "AuditActivity_Engine", "TaskExecution_Scheduler", "License_Repository"} <= set(files["type"])
    picked = qe.pick_latest(files, days=1, mb_per_type=64)
    assert "License_Repository" not in set(picked["type"])  # unused types are never loaded
    assert picked.groupby("type").size().min() >= 1
    tiny = qe.pick_latest(files, days=60, mb_per_type=0.001)  # budget: always at least the newest file per type
    assert (tiny.groupby("type").size() == 1).all()


def test_history_from_listing(archive):
    files = qe.scan_archive(str(archive))
    counts = qe.audit_counts_from_listing(files)
    assert counts["files"].sum() == (files["type"] == "AuditActivity_Engine").sum()
    sample = qe.audit_daily_sample(files, days=90)
    assert not sample.empty and {"app", "user", "share_pct"} <= set(sample.columns)

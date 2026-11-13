"""Share listing, classification, snapshots and the app catalogue."""
import io
import time

import pandas as pd
import pytest

import qlik_catalog as qc
import qlik_share as qs
from conftest import APP1, APP2


def test_share_root_from_archive_root():
    assert qs.share_root_from(r"\\srv.example\QlikShare$\ArchivedLogs\srv.example") == r"\\srv.example\QlikShare$"
    assert qs.share_root_from("/data/QlikShare/ArchivedLogs/host") == "/data/QlikShare"
    assert qs.share_root_from(r"C:\Logs\latest") == ""


def test_background_scan_classifies_and_saves(share, tmp_path):
    root = share.parent.parent
    job = qs.ShareScan()
    assert job.start(str(root), folder=tmp_path / "snaps")
    for _ in range(100):
        if not job.running:
            break
        time.sleep(0.05)
    assert job.status == "done", job.error
    df, meta = qs.load_snapshot(job.saved)
    assert meta["files"] == len(df)
    c = qs.classify(df)
    areas = set(c["area"])
    assert {"Apps", "App search index", "Archived logs", "Reload script logs", "Static content"} <= areas
    af = qs.app_files(c).set_index("app_id")
    assert af.loc[APP1, "lock"] and af.loc[APP1, "search_MB"] > 0 and af.loc[APP1, "script_logs"] == 5
    assert af.loc[APP2, "age_days"] > 365
    lt = qs.log_types(c)
    assert "Audit_Proxy" in set(lt["log_type"])
    assert len(qs.history(tmp_path / "snaps")) >= 5


def test_cancelled_scan(tmp_path):
    job = qs.ShareScan()
    job.stop.set()
    with pytest.raises(qs.Cancelled):
        qs.walk(str(tmp_path), stop=job.stop)


def test_powershell_listing_import(tmp_path):
    csv = ("RelativePath,Name,Folder,Extension,SizeBytes,SizeMB,CreatedUtc,LastModifiedUtc,LastAccessUtc,AgeDaysModified,Attributes,Owner\n"
           f"Apps\\{APP1},{APP1},x,(none),1048576,1,4/01/2024 11:18:03 PM,4/01/2024 11:18:11 PM,,1,Archive,\n"
           "ArchivedLogs\\h\\Proxy\\Audit\\h_Audit_Proxy_2026-10-20T22.42.52Z.log,h_Audit_Proxy_2026-10-20T22.42.52Z.log,x,.log,8388608,8,"
           "20/10/2026 10:00:00 PM,20/10/2026 10:42:52 PM,,1,Archive,\n").encode("utf-8-sig")
    df = qs.read_powershell_csv(csv)
    assert len(df) == 2 and df["mtime"].notna().all() and df.loc[0, "ext"] == ""
    c = qs.classify(df)
    assert c.loc[0, "sub"] == "App file" and c.loc[1, "log_type"] == "Audit_Proxy"
    with pytest.raises(ValueError):
        qs.read_powershell_csv(b"a,b\n1,2\n")


QMC = ('"Name","Owner","Published","Stream","Tags","Target app ID","Description","File size (MB)","Last reload",'
       '"Base memory size (MB)","ID","Created","Last modified","Modified by"\n'
       f'"Sales_Dashboard","Jane (CORP\\\\jane)","2025-07-07 14:21","Finance","","00000000-0000-0000-0000-000000000000","","174.6",'
       f'"2026-10-28 06:31","\'-1916.82","{APP1.upper()}","2021-05-20 10:50","2026-10-28 04:01","INTERNAL\\\\sa_scheduler"\n')


def test_catalogue_import_merge_and_gaps(tmp_path):
    new = qc.read_export(QMC.encode(), "QlikApps.csv")
    assert new.loc[0, "id"] == APP1 and pd.isna(new.loc[0, "base_MB"]) and new.loc[0, "target_app_id"] == ""
    part = qc.read_export(b'"Name","Owner"\n"Old app","x"\n')        # no ID column: kept by name
    cat, n1 = qc.merge(qc.load(tmp_path / "none.csv"), part, "first")
    cat, n2 = qc.merge(cat, new, "second")
    assert n2["added"] == 1 and len(cat) == 2
    cat, n3 = qc.merge(cat, new, "again")                           # re-import replaces, never duplicates
    assert n3["updated"] == 1 and len(cat) == 2
    qc.save(cat, tmp_path / "cat.csv")
    assert len(qc.load(tmp_path / "cat.csv")) == 2
    files = pd.DataFrame({"app_id": [APP1, APP2], "file_MB": [10.0, 5.0], "modified": pd.to_datetime(["2026-10-28", "2024-01-01"]),
                          "created": pd.NaT, "age_days": [0, 1000], "search_MB": [1.0, 0.0], "lock": [True, False], "script_logs": [3, 0]})
    m = qc.apps(cat, files, {APP2: "Named by logs"})
    assert m.set_index("id").loc[APP1, "name"] == "Sales_Dashboard"
    assert m.set_index("id").loc[APP2, "name_source"] == "logs"
    assert qc.gaps(qc.apps(cat, files, {})).iloc[0]["id"] == APP2


def test_environment_check_flags_other_environment():
    ids = [f"{i:08x}-0000-0000-0000-000000000000" for i in range(30)]
    other = pd.DataFrame({"id": ids, "name": ids})
    assert "another" in qc.environment_check(other, {f"{i:08x}-1111-0000-0000-000000000000" for i in range(30)})
    assert qc.environment_check(other, set(ids)) == ""

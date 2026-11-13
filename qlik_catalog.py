"""The app catalogue: which Qlik app each GUID is (name, owner, stream, size, last reload).

It is built from QMC exports (Apps table → Export, any columns, any order), which can be imported again whenever
apps change. Imports add to what is already there, so a partial export (the QMC shows a page at a time) never
loses apps imported earlier. Names the logs reveal (scheduler task runs, engine sessions) fill in apps the export
doesn't have. Anything on the share or in the logs with no name lands on a gap list, so new apps show up there
until the next export.

Saved as %USERPROFILE%\\.qlik_log_analyzer\\app_catalogue.csv, next to the event statuses.
"""
from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pandas as pd

import qlik_share as qs

def path():
    return qs.data_dir() / "app_catalogue.csv"

FIELDS = ["id", "name", "owner", "stream", "published", "tags", "target_app_id", "description", "file_MB",
          "last_reload", "base_MB", "created", "modified", "modified_by", "imported", "import_file"]
_HEAD = {  # QMC column header (lower case) -> field
    "id": "id", "app id": "id", "name": "name", "owner": "owner", "published": "published", "stream": "stream",
    "tags": "tags", "target app id": "target_app_id", "description": "description", "file size (mb)": "file_MB",
    "last reload": "last_reload", "base memory size (mb)": "base_MB", "created": "created",
    "last modified": "modified", "modified by": "modified_by",
}
NULL_GUID = "00000000-0000-0000-0000-000000000000"


def _num(s: pd.Series) -> pd.Series:
    v = pd.to_numeric(s.astype(str).str.replace(r"[',\s]", "", regex=True), errors="coerce")
    return v.where(v >= 0)          # QMC sometimes shows a negative base memory: treat as unknown


def _from_qrs_json(obj) -> pd.DataFrame:
    """The Repository API's /qrs/app/full output (a list of apps)."""
    rows = []
    for a in obj if isinstance(obj, list) else [obj]:
        if not isinstance(a, dict):
            continue
        own = a.get("owner") or {}
        rows.append({"id": a.get("id", ""), "name": a.get("name", ""),
                     "owner": f"{own.get('name', '')} ({own.get('userDirectory', '')}\\{own.get('userId', '')})" if own else "",
                     "published": a.get("publishTime", "") if a.get("published") else "",
                     "stream": (a.get("stream") or {}).get("name", ""),
                     "tags": ", ".join(t.get("name", "") for t in a.get("tags") or []),
                     "target_app_id": "", "description": a.get("description", ""),
                     "file_MB": (a.get("fileSize") or 0) / 1024 ** 2, "last_reload": a.get("lastReloadTime", ""),
                     "base_MB": None, "created": a.get("createdDate", ""), "modified": a.get("modifiedDate", ""),
                     "modified_by": a.get("modifiedByUserName", "")})
    return pd.DataFrame(rows)


def read_export(raw: bytes, filename: str = "") -> pd.DataFrame:
    """A QMC Apps export (CSV/TSV/Excel) or /qrs/app/full JSON, normalised to FIELDS. Raises ValueError."""
    name = filename.lower()
    if name.endswith((".xlsx", ".xls")):
        df = pd.read_excel(io.BytesIO(raw), dtype=str)
    elif name.endswith(".json") or raw.lstrip()[:1] in (b"[", b"{"):
        try:
            df = _from_qrs_json(json.loads(raw.decode("utf-8-sig")))
        except ValueError as exc:
            raise ValueError(f"Couldn't read that JSON: {exc}")
    else:
        text = raw.decode("utf-8-sig", errors="replace")
        sep = "\t" if "\t" in text.split("\n", 1)[0] else ","
        df = pd.read_csv(io.StringIO(text), sep=sep, dtype=str, keep_default_na=False)
    df = df.rename(columns={c: _HEAD.get(str(c).strip().lower(), str(c).strip()) for c in df.columns})
    if "name" not in df and "id" not in df:
        raise ValueError("This doesn't look like a QMC Apps export: it needs at least a Name or ID column.")
    for f in FIELDS:
        if f not in df:
            df[f] = ""
    df = df[FIELDS[:-2]].copy()
    for c in df.columns:
        if df[c].dtype == object:
            df[c] = df[c].fillna("").astype(str).str.strip()
    df["id"] = df["id"].str.lower()
    df.loc[~df["id"].str.fullmatch(qs.GUID_RE.pattern, case=False), "id"] = ""
    df["target_app_id"] = df["target_app_id"].str.lower().replace(NULL_GUID, "")
    df["file_MB"], df["base_MB"] = _num(df["file_MB"]), _num(df["base_MB"])
    return df[(df["id"] != "") | (df["name"] != "")].reset_index(drop=True)


def _key(df: pd.DataFrame) -> pd.Series:
    return df["id"].where(df["id"] != "", "name:" + df["name"].str.lower())


def load(path: Path | None = None) -> pd.DataFrame:
    p = path or globals()["path"]()
    if not p.exists():
        return pd.DataFrame(columns=FIELDS)
    df = pd.read_csv(p, dtype=str, keep_default_na=False)
    for f in FIELDS:
        if f not in df:
            df[f] = ""
    df["file_MB"], df["base_MB"] = _num(df["file_MB"]), _num(df["base_MB"])
    return df[FIELDS]


def save(df: pd.DataFrame, path: Path | None = None) -> None:
    p = path or globals()["path"]()
    p.parent.mkdir(parents=True, exist_ok=True)
    df[FIELDS].to_csv(p, index=False)


def merge(cur: pd.DataFrame, new: pd.DataFrame, label: str = "", when: pd.Timestamp | None = None) -> tuple[pd.DataFrame, dict]:
    """Add an import to the catalogue. Rows with an ID replace that ID; ID-less rows match by name. Apps the import
    doesn't mention are kept. Returns (catalogue, counts)."""
    when = when or pd.Timestamp.now()
    new = new.copy()
    new["imported"], new["import_file"] = f"{when:%Y-%m-%d %H:%M}", label
    if cur is None or cur.empty:
        out = new
        counts = {"added": len(new), "updated": 0, "kept": 0}
    else:
        k_cur, k_new = _key(cur), _key(new)
        # an ID-less row from an earlier import is replaced by a row with an ID and the same name
        named = new.loc[new["id"] != "", "name"].str.lower()
        drop_named = (cur["id"] == "") & cur["name"].str.lower().isin(set(named))
        keep = cur[~k_cur.isin(set(k_new)) & ~drop_named]
        out = pd.concat([keep, new], ignore_index=True)
        counts = {"added": int((~k_new.isin(set(k_cur))).sum()), "updated": int(k_new.isin(set(k_cur)).sum()),
                  "kept": len(keep)}
    out = out[~_key(out).duplicated(keep="last")].reset_index(drop=True)
    return out[FIELDS], counts


def environment_check(new: pd.DataFrame, share_ids: set[str]) -> str:
    """A warning when an export's IDs barely match the apps on the share (an export from another environment)."""
    ids = set(new.loc[new["id"] != "", "id"])
    if len(ids) < 20 or len(share_ids) < 20:
        return ""
    hit = len(ids & share_ids) / len(ids)
    if hit < 0.2:
        return (f"Only {hit:.0%} of this export's app IDs are on the share that was scanned. It may come from another "
                "environment (PAT or DEV), where every app has a different ID. It has been imported, but only the "
                "matching IDs will be used for names.")
    return ""


def is_copy(name: str) -> bool:
    return bool(re.search(r"\(\d+\)\s*$", str(name)))


def apps(cat: pd.DataFrame, files: pd.DataFrame | None = None, log_names: dict | None = None,
         now: pd.Timestamp | None = None) -> pd.DataFrame:
    """The master app list: everything in the catalogue, on the share or named in the logs, one row per app ID.

    name_source tells where the name came from: 'QMC export', 'logs' or '' (no name yet = a gap)."""
    log_names = {str(k).lower(): v for k, v in (log_names or {}).items() if k and v}
    c = cat[cat["id"] != ""].drop_duplicates("id", keep="last").set_index("id") if cat is not None and len(cat) else \
        pd.DataFrame(columns=FIELDS).set_index("id")
    f = files.set_index("app_id") if files is not None and len(files) else pd.DataFrame(
        columns=["app_id", "file_MB", "modified", "created", "age_days", "search_MB", "lock", "script_logs"]).set_index("app_id")
    ids = sorted(set(c.index) | set(f.index) | set(log_names))
    out = pd.DataFrame(index=pd.Index(ids, name="id"))
    out = out.join(c.drop(columns=["file_MB", "modified", "created"], errors="ignore"), how="left")
    out = out.join(c[["file_MB", "modified", "created"]].rename(columns={
        "file_MB": "qmc_file_MB", "modified": "qmc_modified", "created": "qmc_created"}), how="left")
    out = out.join(f, how="left")
    for col in ("name", "owner", "stream", "published", "tags", "target_app_id", "description", "last_reload",
                "modified_by", "imported", "import_file", "qmc_modified", "qmc_created"):
        if col not in out:
            out[col] = ""
        out[col] = out[col].fillna("")
    out["name_source"] = out["name"].ne("").map({True: "QMC export", False: ""})
    ln = pd.Series(log_names).reindex(out.index).fillna("")
    fill = out["name"].eq("") & ln.ne("")
    out.loc[fill, "name"] = ln[fill]
    out.loc[fill, "name_source"] = "logs"
    out["on_share"] = out.index.isin(set(f.index))
    out["in_qmc"] = out.index.isin(set(c.index))
    out["published_flag"] = out["published"].ne("")
    out["copy"] = out["name"].map(is_copy) | out["target_app_id"].ne("")
    out["display"] = out["name"].where(out["name"].ne(""), out.index.to_series().str[:8] + "… (no name yet)")
    # an empty share listing or catalogue leaves these as 'object' columns; pages need real numbers and dates
    for col in ("file_MB", "search_MB", "base_MB", "qmc_file_MB", "age_days", "script_logs"):
        if col in out:
            out[col] = pd.to_numeric(out[col], errors="coerce").astype(float)
    for col in ("modified", "created"):
        if col in out:
            out[col] = pd.to_datetime(out[col], errors="coerce")
    out["lock"] = out["lock"].eq(True) if "lock" in out else False
    return out.reset_index()


def gaps(master: pd.DataFrame) -> pd.DataFrame:
    """Apps with no name (on the share or in the logs, but not in any export), biggest first."""
    g = master[master["name"].eq("")]
    return g.sort_values("file_MB", ascending=False, na_position="last")


def by_name(cat: pd.DataFrame, name: str) -> pd.DataFrame:
    if cat is None or cat.empty or not name:
        return pd.DataFrame(columns=FIELDS)
    return cat[cat["name"].str.lower() == str(name).lower()]

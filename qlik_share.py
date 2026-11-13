"""The QlikShare$ folder: a background listing of every file (what the PowerShell export did), and the summaries the
Storage and Apps pages draw from it.

Only the directory listing is read: names, sizes and dates. No file is opened and nothing is changed. A scan of the
production share (about 184,000 files) takes a few minutes over the network, so it runs on a background thread and
saves a snapshot to %USERPROFILE%\\.qlik_log_analyzer\\share. The newest snapshots are kept, plus a small history of
totals per area so growth can be charted across scans. A listing made by the PowerShell script can be imported too.
"""
from __future__ import annotations

import datetime as _dt
import io
import json
import os
import re
import threading
import time
from pathlib import Path

import pandas as pd



def data_dir() -> Path:
    """Where the app keeps its own files (catalogue, share listings, reported issues, settings)."""
    return Path(os.environ.get("QLIK_EVENT_DATA", "") or (Path.home() / ".qlik_log_analyzer"))


def share_dir() -> Path:
    return data_dir() / "share"

HISTORY = "history.csv"
KEEP_SNAPSHOTS = 3
GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
COLS = ["path", "name", "ext", "size", "mtime", "ctime"]   # internal listing; times are this PC's local time
AREAS = ["Apps", "App search index", "Archived logs", "Reload script logs", "Static content", "Other"]


def _settings_path() -> Path:
    return data_dir() / "settings.json"


def get_setting(key: str, default=None):
    try:
        return json.loads(_settings_path().read_text(encoding="utf-8")).get(key, default)
    except (OSError, ValueError):
        return default


def set_setting(key: str, value) -> None:
    p = _settings_path()
    try:
        cur = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cur = {}
    cur[key] = value
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cur, indent=2), encoding="utf-8")


def share_root_from(archive_root: str) -> str:
    """\\\\server\\QlikShare$\\ArchivedLogs\\host  ->  \\\\server\\QlikShare$ (the folder that holds ArchivedLogs)."""
    env = os.environ.get("QLIK_SHARE_ROOT", "")
    if env:
        return env
    r = (archive_root or "").rstrip("\\/")
    sep = "\\" if "\\" in r else "/"
    parts = re.split(r"[\\/]", r)
    for i, p in enumerate(parts):
        if p.lower() == "archivedlogs" and i > 0:
            return sep.join(parts[:i])
    return ""


# ----------------------------------------------------------------------------------------------
# Walking the share
# ----------------------------------------------------------------------------------------------
class Cancelled(Exception):
    pass


def walk(root: str, progress=None, stop: threading.Event | None = None) -> tuple[pd.DataFrame, int]:
    """Every file under root as (path relative to root, name, ext, size, mtime, ctime). Returns (listing, folders
    that couldn't be read). Uses os.scandir, which on Windows gets size and dates from the directory listing itself."""
    root = os.path.abspath(root) if not root.startswith("\\\\") else root
    rows, errors, n_bytes = [], 0, 0
    stack = [root]
    last = 0.0
    cut = len(root.rstrip("\\/")) + 1
    while stack:
        if stop is not None and stop.is_set():
            raise Cancelled()
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            errors += 1
            continue
        with it:
            for e in it:
                try:
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
                        continue
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                n_bytes += st.st_size
                ct = getattr(st, "st_birthtime", None) or st.st_ctime
                rows.append((e.path[cut:].replace("/", "\\"), e.name, os.path.splitext(e.name)[1].lower(), st.st_size,
                             st.st_mtime, ct))
        if progress and time.time() - last > 0.5:
            last = time.time()
            progress(len(rows), n_bytes, d[cut:] if len(d) > cut else d)
    df = pd.DataFrame(rows, columns=COLS)
    for c in ("mtime", "ctime"):
        df[c] = pd.to_datetime(df[c], unit="s", utc=True).dt.tz_convert(_local_tz()).dt.tz_localize(None)
    return df, errors


def _local_tz():
    return _dt.datetime.now().astimezone().tzinfo


# ----------------------------------------------------------------------------------------------
# Snapshots on disk
# ----------------------------------------------------------------------------------------------
def snapshots(folder: Path | None = None) -> list[Path]:
    folder = folder or share_dir()
    return sorted(folder.glob("listing_*.csv.gz"), reverse=True) if folder.is_dir() else []


def save_snapshot(df: pd.DataFrame, root: str, taken: pd.Timestamp | None = None, folder: Path | None = None,
                  source: str = "scan") -> Path:
    folder = folder or share_dir()
    folder.mkdir(parents=True, exist_ok=True)
    taken = taken or pd.Timestamp.now()
    p = folder / f"listing_{taken:%Y%m%d_%H%M%S}.csv.gz"
    out = df[COLS].copy()
    for c in ("mtime", "ctime"):
        out[c] = out[c].dt.strftime("%Y-%m-%d %H:%M:%S")
    meta = json.dumps({"root": root, "taken": f"{taken:%Y-%m-%d %H:%M:%S}", "files": len(df), "source": source})
    buf = io.StringIO()
    buf.write("#" + meta + "\n")
    out.to_csv(buf, index=False)
    import gzip
    with gzip.open(p, "wt", encoding="utf-8", newline="") as fh:
        fh.write(buf.getvalue())
    _append_history(classify(df), taken, folder)
    for old in snapshots(folder)[KEEP_SNAPSHOTS:]:
        try:
            old.unlink()
        except OSError:
            pass
    return p


def load_snapshot(path: Path) -> tuple[pd.DataFrame, dict]:
    import gzip
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        first = fh.readline()
        meta = json.loads(first[1:]) if first.startswith("#") else {}
        df = pd.read_csv(fh, dtype={"path": str, "name": str, "ext": str}, keep_default_na=False)
    for c in ("mtime", "ctime"):
        df[c] = pd.to_datetime(df[c], errors="coerce")
    df["size"] = pd.to_numeric(df["size"], errors="coerce").fillna(0).astype("int64")
    return df, meta


def read_powershell_csv(raw: bytes) -> pd.DataFrame:
    """The CSV made by the share-listing PowerShell script (RelativePath, Name, Extension, SizeBytes,
    CreatedUtc, LastModifiedUtc ...). Dates are day-first and in UTC."""
    df = pd.read_csv(io.BytesIO(raw), encoding="utf-8-sig", dtype=str, keep_default_na=False, low_memory=False)
    need = {"RelativePath", "Name", "SizeBytes", "LastModifiedUtc"}
    if not need <= set(df.columns):
        raise ValueError("This doesn't look like a share listing: it needs the columns " + ", ".join(sorted(need)) + ".")
    tz = _local_tz()

    def utc(col):
        if col not in df:
            return pd.Series(pd.NaT, index=df.index)
        s = pd.to_datetime(df[col], format="%d/%m/%Y %I:%M:%S %p", errors="coerce")
        bad = s.isna() & df[col].ne("")
        if bad.any():   # another date layout (a PC with different regional settings)
            s[bad] = pd.to_datetime(df.loc[bad, col], dayfirst=True, errors="coerce", format="mixed")
        return s.dt.tz_localize("UTC").dt.tz_convert(tz).dt.tz_localize(None)

    ext = df["Extension"].str.lower().replace("(none)", "") if "Extension" in df else df["Name"].map(
        lambda n: os.path.splitext(n)[1].lower())
    return pd.DataFrame({"path": df["RelativePath"], "name": df["Name"], "ext": ext,
                         "size": pd.to_numeric(df["SizeBytes"], errors="coerce").fillna(0).astype("int64"),
                         "mtime": utc("LastModifiedUtc"), "ctime": utc("CreatedUtc")})


def _append_history(c: pd.DataFrame, taken: pd.Timestamp, folder: Path) -> None:
    h = c.groupby("area").agg(files=("size", "size"), bytes=("size", "sum")).reset_index()
    h.insert(0, "taken", f"{taken:%Y-%m-%d %H:%M:%S}")
    p = folder / HISTORY
    h.to_csv(p, mode="a", header=not p.exists(), index=False)


def history(folder: Path | None = None) -> pd.DataFrame:
    p = (folder or share_dir()) / HISTORY
    if not p.exists():
        return pd.DataFrame(columns=["taken", "area", "files", "bytes"])
    h = pd.read_csv(p)
    h["taken"] = pd.to_datetime(h["taken"], errors="coerce")
    return h.drop_duplicates(["taken", "area"], keep="last")


# ----------------------------------------------------------------------------------------------
# Background scan (one per app process)
# ----------------------------------------------------------------------------------------------
class ShareScan:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.status = "idle"      # idle | running | done | error | cancelled
        self.root = ""
        self.started = self.finished = None
        self.files = 0
        self.bytes = 0
        self.folder = ""
        self.error = ""
        self.unreadable = 0
        self.saved: Path | None = None

    @property
    def running(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def start(self, root: str, folder: Path | None = None) -> bool:
        with self.lock:
            if self.running:
                return False
            self.stop.clear()
            self.status, self.root, self.error = "running", root, ""
            self.started, self.finished, self.files, self.bytes, self.folder = pd.Timestamp.now(), None, 0, 0, ""
            self.thread = threading.Thread(target=self._run, args=(root, folder), name="share-scan", daemon=True)
            self.thread.start()
            return True

    def cancel(self) -> None:
        self.stop.set()

    def _progress(self, n, b, folder):
        self.files, self.bytes, self.folder = n, b, folder

    def _run(self, root: str, folder: Path | None) -> None:
        try:
            if not os.path.isdir(root):
                raise OSError(f"Can't reach {root} from this PC.")
            df, self.unreadable = walk(root, self._progress, self.stop)
            self.files, self.bytes = len(df), int(df["size"].sum())
            self.saved = save_snapshot(df, root, folder=folder)
            self.status = "done"
        except Cancelled:
            self.status = "cancelled"
        except Exception as exc:  # noqa: BLE001
            self.status, self.error = "error", f"{type(exc).__name__}: {exc}"
        finally:
            self.finished = pd.Timestamp.now()


JOB = ShareScan()


def due(hours: float = 24, folder: Path | None = None) -> bool:
    """True when the newest snapshot is older than `hours` (or there is none)."""
    s = snapshots(folder)
    if not s:
        return True
    m = re.search(r"listing_(\d{8}_\d{6})", s[0].name)
    if not m:
        return True
    return pd.Timestamp.now() - pd.to_datetime(m.group(1), format="%Y%m%d_%H%M%S") > pd.Timedelta(hours=hours)


# ----------------------------------------------------------------------------------------------
# Making sense of a listing
# ----------------------------------------------------------------------------------------------
_ARCH_TYPE = re.compile(r"^[^_]+_(?P<t>.+?)(?:_\d{8})?_\d{4}-\d{2}-\d{2}T[\d.]+Z?\.(?:log|txt)$", re.I)


def classify(df: pd.DataFrame) -> pd.DataFrame:
    """Adds area, sub (component or folder), app_id (for app files, search indexes and reload logs) and log_type."""
    out = df.copy()
    if out.empty:
        for c in ("area", "sub", "app_id", "log_type"):
            out[c] = pd.Series(dtype=str)
        return out
    parts = out["path"].str.split("\\")
    p0 = parts.str[0].str.lower()
    n = parts.str.len()
    p1 = parts.str[1].fillna("")
    p2 = parts.str[2].fillna("")
    area = pd.Series("Other", index=out.index)
    sub = parts.str[0].fillna("")
    app_id = pd.Series("", index=out.index)
    log_type = pd.Series("", index=out.index)

    apps = p0.eq("apps")
    search = apps & (n >= 3) & p1.str.lower().eq("search")
    app_file = apps & (n == 2)
    area[apps] = "Apps"
    sub[apps] = "Other app files"
    guid_name = out["name"].str.fullmatch(GUID_RE.pattern + r"(\.lock)?", case=False).fillna(False)
    sub[app_file & guid_name & out["ext"].ne(".lock")] = "App file"
    sub[app_file & out["ext"].eq(".lock")] = "Lock file"
    app_id[app_file & guid_name] = out.loc[app_file & guid_name, "name"].str[:36].str.lower()
    area[search] = "App search index"
    sub[search] = "Search index"
    app_id[search] = p2[search].str.lower()

    arch = p0.eq("archivedlogs")
    comp = parts.str[2].fillna("")
    script = arch & comp.str.lower().eq("script")
    area[arch] = "Archived logs"
    sub[arch] = comp[arch].where(comp[arch].ne(""), "(top)")
    lt = out.loc[arch & ~script, "name"].str.extract(_ARCH_TYPE)["t"]
    log_type[arch & ~script] = lt.fillna("")
    area[script] = "Reload script logs"
    sub[script] = "Script"
    app_id[script] = out.loc[script, "name"].str.extract("(" + GUID_RE.pattern + ")")[0].fillna("").str.lower()

    static = p0.eq("staticcontent")
    area[static] = "Static content"
    sub[static] = p1[static]
    out["area"], out["sub"], out["app_id"], out["log_type"] = area, sub, app_id, log_type
    return out


def area_summary(c: pd.DataFrame) -> pd.DataFrame:
    if c.empty:
        return pd.DataFrame(columns=["area", "files", "GB", "newest", "oldest"])
    g = c.groupby("area").agg(files=("size", "size"), bytes=("size", "sum"), newest=("mtime", "max"),
                              oldest=("mtime", "min")).reset_index()
    g["GB"] = g["bytes"] / 1024 ** 3
    g["area"] = pd.Categorical(g["area"], AREAS, ordered=True)
    return g.sort_values("area").drop(columns="bytes").reset_index(drop=True)


def archive_by_month(c: pd.DataFrame, months: int = 18) -> pd.DataFrame:
    """GB of archived logs per month (by modified date) and component."""
    a = c[c["area"].isin(["Archived logs", "Reload script logs"])]
    if a.empty:
        return pd.DataFrame(columns=["month", "sub", "GB", "files"])
    a = a.assign(month=a["mtime"].dt.to_period("M").dt.to_timestamp())
    a = a[a["month"] >= a["month"].max() - pd.DateOffset(months=months - 1)]
    g = a.groupby(["month", "sub"]).agg(GB=("size", "sum"), files=("size", "size")).reset_index()
    g["GB"] = g["GB"] / 1024 ** 3
    return g


def log_types(c: pd.DataFrame, now: pd.Timestamp | None = None) -> pd.DataFrame:
    a = c[c["area"].eq("Archived logs")]
    if a.empty:
        return pd.DataFrame()
    now = now or c["mtime"].max()
    yr = a["mtime"] < now - pd.Timedelta(days=365)
    g = a.assign(old=a["size"].where(yr, 0), recent=a["size"].where(a["mtime"] >= now - pd.Timedelta(days=30), 0)) \
        .groupby(["sub", "log_type"]).agg(files=("size", "size"), GB=("size", "sum"), old_GB=("old", "sum"),
                                          last30_GB=("recent", "sum"), oldest=("mtime", "min"), newest=("mtime", "max"))
    for col in ("GB", "old_GB", "last30_GB"):
        g[col] = g[col] / 1024 ** 3
    return g.sort_values("GB", ascending=False).reset_index().rename(columns={"sub": "component"})


def app_files(c: pd.DataFrame, now: pd.Timestamp | None = None) -> pd.DataFrame:
    """One row per app found on the share: app file size and dates, search-index size, reload-log count."""
    if c.empty or not c["sub"].eq("App file").any():
        return pd.DataFrame({"app_id": pd.Series(dtype=str), "file_MB": pd.Series(dtype=float),
                             "modified": pd.Series(dtype="datetime64[ns]"), "created": pd.Series(dtype="datetime64[ns]"),
                             "age_days": pd.Series(dtype=float), "search_MB": pd.Series(dtype=float),
                             "lock": pd.Series(dtype=bool), "script_logs": pd.Series(dtype=int)})
    now = now or c["mtime"].max()
    f = c[c["sub"].eq("App file")].groupby("app_id").agg(file_MB=("size", "sum"), modified=("mtime", "max"),
                                                       created=("ctime", "min"))
    f["file_MB"] = f["file_MB"] / 1024 ** 2
    s = c[c["area"].eq("App search index")].groupby("app_id")["size"].sum() / 1024 ** 2
    lk = set(c.loc[c["sub"].eq("Lock file"), "app_id"])
    sl = c[c["area"].eq("Reload script logs")].groupby("app_id").size()
    out = f.join(s.rename("search_MB"), how="outer").join(sl.rename("script_logs"), how="left")
    out["search_MB"] = out["search_MB"].fillna(0)
    out["script_logs"] = out["script_logs"].fillna(0).astype(int)
    out["lock"] = out.index.isin(lk)
    out["age_days"] = (now - out["modified"]).dt.days
    out = out.reset_index().rename(columns={"index": "app_id"})
    return out[out["app_id"].ne("")]


def churn(c: pd.DataFrame, hours: int = 24) -> dict:
    """App files rewritten (reloaded and saved) in the `hours` before the newest file on the share."""
    a = c[c["sub"].eq("App file")]
    if a.empty:
        return {"apps": 0, "GB": 0.0, "since": None}
    since = c["mtime"].max() - pd.Timedelta(hours=hours)
    r = a[a["mtime"] >= since]
    return {"apps": len(r), "GB": r["size"].sum() / 1024 ** 3, "since": since}


def compare(cur: pd.DataFrame, prev: pd.DataFrame) -> dict:
    """What changed between two classified listings: apps added or removed, GB by area."""
    if prev is None or prev.empty:
        return {}
    a = set(cur.loc[cur["sub"].eq("App file"), "app_id"])
    b = set(prev.loc[prev["sub"].eq("App file"), "app_id"])
    gb = (cur.groupby("area")["size"].sum() - prev.groupby("area")["size"].sum()).fillna(0) / 1024 ** 3
    return {"new_apps": sorted(a - b), "gone_apps": sorted(b - a), "gb_change": gb.to_dict()}

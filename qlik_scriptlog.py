"""Reads one Qlik reload log (the ArchivedLogs Script folder): status, error text, start and finish.

Only the first 4 KB and the last 8 KB of a log are read, so it is quick on large logs. Read-only. Credentials in
connection strings are hidden in anything returned.
"""
from __future__ import annotations

import datetime as _dt
import os
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

SENSE_TS = re.compile(r"^(\d{8}T\d{6}(?:[.,]\d+)?(?:[+-]\d{4}|Z)?)[ \t]?(.*)$")
QV_TS = re.compile(r"^(\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4}[ T]\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s?[AaPp][Mm])?):?[ \t]?(.*)$")
LINENO = re.compile(r"^(\d{4,5})(?: {1,2}|$)(.*)$")
ROWS_RE = re.compile(r"(\d[\d,.\s ']*)\s+(?:lines|rows)\s+fetched", re.I)


@dataclass
class QlikReload:
    path: str
    started: str = ""
    finished: str = ""
    duration_s: Optional[float] = None
    status: str = "unknown"   # ok | warn | failed | running | incomplete | unknown
    error: str = ""
    trigger: str = ""         # "task" | "user" | ""


def _decode(raw: bytes) -> str:
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", errors="replace")
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if len(raw) > 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
        return raw.decode("utf-16-le", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def _read_text(path: str, limit: Optional[int] = None) -> str:
    with open(path, "rb") as fh:
        raw = fh.read(limit) if limit else fh.read()
    if limit and len(raw) == limit:
        # don't cut a UTF-8 character or a UTF-16 pair in half
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff") and len(raw) % 2:
            raw = raw[:-1]
    return _decode(raw)


def _tail(path: str, n: int = 6000) -> str:
    with open(path, "rb") as fh:
        head = fh.read(4)
        size = fh.seek(0, 2)
        start = max(0, size - n)
        utf16 = head[:2] in (b"\xff\xfe", b"\xfe\xff") or (len(head) == 4 and head[1:2] == b"\x00")
        if utf16 and start % 2:
            start += 1
        fh.seek(start)
        raw = fh.read()
    if utf16:
        return raw.decode("utf-16-be" if head[:2] == b"\xfe\xff" else "utf-16-le", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _split_ts(line: str) -> Tuple[str, str]:
    """Split one log line into (timestamp as 'YYYY-MM-DD HH:MM:SS' or raw, rest)."""
    m = SENSE_TS.match(line)
    if m:
        return _ts_to_iso(m.group(1)), m.group(2)
    m = QV_TS.match(line)
    if m:
        return _qv_ts_to_iso(m.group(1)), m.group(2)
    return "", line


def _ts_to_iso(ts: str) -> str:
    m = re.match(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})", ts)
    if m:
        return "%s-%s-%s %s:%s:%s" % m.groups()
    return ts[:19]


def _qv_ts_to_iso(ts: str) -> str:
    ts = ts.strip()
    for fmt in ("%d/%m/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%d.%m.%Y %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %I:%M:%S %p"):
        try:
            return _dt.datetime.strptime(re.sub(r"[.,]\d+$", "", ts), fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return ts


def _seconds(a: str, b: str) -> Optional[float]:
    try:
        fa = _dt.datetime.strptime(a[:19], "%Y-%m-%d %H:%M:%S")
        fb = _dt.datetime.strptime(b[:19], "%Y-%m-%d %H:%M:%S")
        return max(0.0, (fb - fa).total_seconds())
    except ValueError:
        return None


def hide_credentials(text: str) -> str:
    text = re.sub(r"\((?:\s*X?(?:UserId|Password)\s+is\b[^)]*)\)", "(credentials hidden)", text, flags=re.I)
    return re.sub(r"(?i)\b(pwd|password|user id|uid)\s*=\s*[^;\]\"']*", lambda m: m.group(1) + "=***", text)


def parse_log_text(text: str):
    """Returns (script lines, chunks, header info). A chunk is (timestamp, [(lineno, text)], [messages after it])."""
    script: List[Tuple[int, str]] = []
    chunks: List[Tuple[str, List[Tuple[int, str]], List[str]]] = []
    info: Dict[str, str] = {"_first": "", "_last": ""}
    cur: List[Tuple[int, str]] = []
    cur_ts = ""
    for raw in text.splitlines():
        if not raw.strip():
            continue
        ts, rest = _split_ts(raw.rstrip("\r"))
        if ts:
            info["_first"] = info["_first"] or ts
            info["_last"] = ts
        lm = LINENO.match(rest) if rest[:1].isdigit() else None
        if lm and not ROWS_RE.search(rest) and not re.match(r"^\d+\s+fields?\s+found", rest, re.I):
            no, txt = int(lm.group(1)), lm.group(2)
            script.append((no, txt))
            if not cur:
                cur_ts = ts
            cur.append((no, txt))
            continue
        msg = rest.strip()
        if cur:
            chunks.append((cur_ts, cur, []))
            cur = []
        if chunks:
            chunks[-1][2].append(msg)
        else:
            parts = re.split(r"\s{2,}|\t", msg, maxsplit=1)
            if len(parts) == 2:
                info[parts[0].strip()] = parts[1].strip()
            info.setdefault("_head", "")
            info["_head"] += msg + "\n"
    if cur:
        chunks.append((cur_ts, cur, []))
    return script, chunks, info


def _status_from(messages: List[str], recent: bool) -> Tuple[str, str]:
    finished = any(m.startswith("Execution finished") or "Execution finished" in m for m in messages)
    failed = any(re.search(r"Execution Failed|Execution aborted|Script execution aborted|Reload failed|"
                           r"General Script Error|Script Error\b", m, re.I) for m in messages)
    err = ""
    for i, m in enumerate(messages):
        if re.search(r"following error occurred", m, re.I) and i + 1 < len(messages):
            err = messages[i + 1]
            break
    if not err:
        for m in messages:
            if re.search(r"fields?\s+found|lines fetched", m, re.I):
                continue
            if re.match(r"^(Error|ErrorSource|ErrorMsg|Connector reply error|Cannot open file|Table '.*' not found|"
                        r"Field '.*' not found)", m, re.I) or re.search(r"\berror\b", m, re.I):
                err = m
                break
    err = hide_credentials(err)[:300]
    if failed:
        return "failed", err
    if finished:
        return ("warn" if err else "ok"), err
    return ("running" if recent else "incomplete"), err


def _trigger(info: Dict[str, str]) -> str:
    v = (info.get("Reload Executed By") or "").lower()
    if not v:
        return ""
    return "task" if ("sa_scheduler" in v or "internal" in v) else "user"


def _mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def reload_summary(path: str) -> QlikReload:
    """Status of an older log from its first and last few KB only."""
    try:
        head = _read_text(path, 4000)
        tail = _tail(path, 8000)
    except OSError:
        return QlikReload(path)
    _, _, ih = parse_log_text(head)
    msgs = []
    last = ""
    for ln in tail.splitlines():
        ts, rest = _split_ts(ln.rstrip("\r"))
        if ts:
            last = ts
        if rest and not LINENO.match(rest):
            msgs.append(rest.strip())
    recent = (time.time() - _mtime(path)) < 3 * 3600
    status, err = _status_from(msgs, recent)
    started = ih.get("_first", "")
    fin = last if status not in ("running", "incomplete") else ""
    return QlikReload(path, started, fin, _seconds(started, last) if fin else None, status, err, _trigger(ih))

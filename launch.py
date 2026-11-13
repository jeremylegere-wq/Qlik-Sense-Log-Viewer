"""Starts the Qlik Server Event Manager so it can run all day next to other Streamlit apps.

* It uses its own port (8601 unless QLIK_EM_PORT says otherwise), not Streamlit's shared default 8501, and moves to
  the next free port if that one is taken. On Windows two programs can end up sharing a port without an error, so
  "free" is checked by trying to connect, not just by trying to listen.
* If this app is already running, it opens a browser tab on it instead of starting a second copy.
* It listens on this PC only (127.0.0.1), so nobody else on the network can open it.
* If requirements.txt has changed since the last start (a new version of the app), it updates the packages first.

Run by "Start Qlik Log Analyzer.bat"; by hand:  .venv\\Scripts\\python.exe launch.py
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

HERE = Path(__file__).resolve().parent
PREFERRED = int(os.environ.get("QLIK_EM_PORT", "8601") or 8601)
STATE = Path(os.environ.get("QLIK_EVENT_DATA", "") or (Path.home() / ".qlik_log_analyzer")) / "running.json"


def listening(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.4):
            return True
    except OSError:
        return False


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":   # os.kill(pid, 0) would send Ctrl+C on Windows, so ask Windows directly
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)          # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        code = ctypes.c_ulong()
        ok = k32.GetExitCodeProcess(h, ctypes.byref(code))
        k32.CloseHandle(h)
        return bool(ok) and code.value == 259            # STILL_ACTIVE
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def free_port(start: int, tries: int = 50) -> int:
    for p in range(start, start + tries):
        if listening(p):
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", p))
            return p
        except OSError:
            continue
    raise SystemExit(f"No free port between {start} and {start + tries - 1}. Close an app and try again.")


def already_running() -> int | None:
    try:
        info = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if Path(info.get("folder", "")).resolve() != HERE:
        return None
    port, pid = int(info.get("port", 0)), int(info.get("pid", 0))
    return port if pid_alive(pid) and listening(port) else None


def update_packages() -> None:
    """Install what requirements.txt asks for when it has changed since the last successful update (a new version).
    pip's own output goes to a log file; a failure is retried at most once a day, and the app starts anyway."""
    req = HERE / "requirements.txt"
    mark = Path(sys.prefix) / "requirements.sha1"
    want = hashlib.sha1(req.read_bytes()).hexdigest() if req.exists() else ""
    have = mark.read_text().strip() if mark.exists() else ""
    if not want or want == have:
        return
    log = STATE.parent / "package_update.log"
    tried = STATE.parent / "package_update_failed.json"
    try:
        last = json.loads(tried.read_text(encoding="utf-8"))
        if last.get("want") == want and time.time() - float(last.get("at", 0)) < 86400:
            print("Packages weren't updated last time (see package_update.log); trying again tomorrow. Starting with what's installed.")
            return
    except (OSError, ValueError):
        pass
    py = f"{sys.version_info.major}.{sys.version_info.minor}"
    print(f"This version needs updated packages. Updating (a minute or two, Python {py})...")
    STATE.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "--disable-pip-version-check", "-r", str(req)],
                       capture_output=True, text=True)
    log.write_text(f"{time.ctime()}  Python {sys.version}\n\n{r.stdout}\n{r.stderr}", encoding="utf-8")
    if r.returncode == 0:
        mark.write_text(want)
        try:
            tried.unlink()
        except OSError:
            pass
        print("Packages updated.")
        return
    tried.write_text(json.dumps({"want": want, "at": time.time()}), encoding="utf-8")
    if "Requires-Python" in r.stderr and "No matching distribution" in r.stderr:
        why = f"a package this version wants doesn't support Python {py}"
    elif "Could not fetch" in r.stderr or "ConnectionError" in r.stderr or "Max retries" in r.stderr:
        why = "this PC couldn't reach pypi.org"
    else:
        why = "pip reported an error"
    print(f"Couldn't update the packages: {why}. Details: {log}")
    print("Starting with what's installed.")


def quiet_first_run() -> None:
    """Stop Streamlit asking for an email address the first time it runs (it would wait for an answer)."""
    cred = Path.home() / ".streamlit" / "credentials.toml"
    if not cred.exists():
        cred.parent.mkdir(parents=True, exist_ok=True)
        cred.write_text('[general]\nemail = ""\n', encoding="utf-8")


def main() -> int:
    quiet_first_run()
    port = already_running()
    if port:
        url = f"http://localhost:{port}"
        print(f"The Event Manager is already running at {url}. Opening it.")
        webbrowser.open(url)
        time.sleep(2)
        return 0
    update_packages()
    port = free_port(PREFERRED)
    url = f"http://localhost:{port}"
    print(f"Starting at {url}  (other Streamlit apps can keep running on their own ports)")
    STATE.parent.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "streamlit", "run", str(HERE / "app.py"), "--server.port", str(port),
           "--server.address", "localhost", "--server.headless", "false", "--browser.gatherUsageStats", "false",
           "--browser.serverAddress", "localhost"]
    proc = subprocess.Popen(cmd, cwd=str(HERE))
    STATE.write_text(json.dumps({"port": port, "pid": proc.pid, "folder": str(HERE)}), encoding="utf-8")
    try:
        return proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        return 0
    finally:
        try:
            if json.loads(STATE.read_text(encoding="utf-8")).get("pid") == proc.pid:
                STATE.unlink()
        except (OSError, ValueError):
            pass


if __name__ == "__main__":
    sys.exit(main())

import base64
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

import psutil
import requests
from flask import Flask, jsonify, request

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_config() -> Dict[str, Any]:
    with CONFIG_PATH.open("r", encoding="utf-8-sig") as f:
        cfg = json.load(f)

    cfg.setdefault("nodeId", "node-1")
    cfg.setdefault("name", "Node")
    cfg.setdefault("host", "0.0.0.0")
    cfg.setdefault("port", 8080)
    cfg.setdefault("panelUrl", "http://127.0.0.1:3000")
    cfg.setdefault("sharedSecret", "nodewings-shared-secret")
    cfg.setdefault("heartbeatSeconds", 5)
    cfg.setdefault("serversDir", "./servers")
    cfg.setdefault("autoRestartDelaySeconds", 2)
    cfg.setdefault("processManagerBinary", "./process_manager")
    cfg.setdefault("rapidCrashWindowSeconds", 20)
    cfg.setdefault("maxCrashRestarts", 5)

    return cfg


CONFIG = load_config()
SERVERS_ROOT = (BASE_DIR / CONFIG["serversDir"]).resolve()
SERVERS_ROOT.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

state_lock = threading.RLock()
server_states: Dict[str, Dict[str, Any]] = {}
panel_post_lock = threading.Lock()
panel_post_state: Dict[str, Dict[str, Any]] = {}


class WingsError(Exception):
    pass


def verify_secret() -> None:
    secret = request.headers.get("x-node-secret")
    if secret != CONFIG["sharedSecret"]:
        raise WingsError("Unauthorized")


def panel_headers() -> Dict[str, str]:
    return {
        "x-node-id": CONFIG["nodeId"],
        "x-node-secret": CONFIG["sharedSecret"],
        "Content-Type": "application/json",
    }


def post_panel(path: str, payload: Dict[str, Any], timeout: int = 4) -> None:
    url = CONFIG["panelUrl"].rstrip("/") + path
    try:
        response = requests.post(url, headers=panel_headers(), json=payload, timeout=timeout)
        response.raise_for_status()

        with panel_post_lock:
            state = panel_post_state.setdefault(path, {"failed": False, "failures": 0, "last_log": 0.0})
            if state["failed"]:
                print(f"[wings] panel link restored for {path} after {state['failures']} failures")
            state["failed"] = False
            state["failures"] = 0
            state["last_log"] = 0.0
    except Exception as exc:
        now = time.time()
        with panel_post_lock:
            state = panel_post_state.setdefault(path, {"failed": False, "failures": 0, "last_log": 0.0})
            state["failed"] = True
            state["failures"] = int(state["failures"]) + 1
            should_log = state["failures"] == 1 or (now - float(state["last_log"])) >= 15
            if should_log:
                state["last_log"] = now
                extra = "" if state["failures"] == 1 else f" (x{state['failures']})"
                print(f"[wings] panel post failed {path}{extra}: {exc}")


def emit_event(uuid: str, kind: str, payload: Dict[str, Any]) -> None:
    post_panel(
        "/api/internal/events",
        {
            "uuid": uuid,
            "type": kind,
            "payload": payload,
            "ts": now_iso(),
        },
        timeout=3,
    )


def emit_status(uuid: str, status: str, last_exit: Optional[Dict[str, Any]] = None) -> None:
    body: Dict[str, Any] = {"status": status}
    if last_exit is not None:
        body["lastExit"] = last_exit
    emit_event(uuid, "status", body)


def ensure_server_dir(uuid: str) -> Path:
    path = (SERVERS_ROOT / uuid).resolve()
    if not str(path).startswith(str(SERVERS_ROOT)):
        raise WingsError("Invalid server UUID")
    path.mkdir(parents=True, exist_ok=True)
    return path


def resolve_safe_path(uuid: str, relative_path: str) -> Path:
    root = ensure_server_dir(uuid)
    normalized = relative_path or "."
    target = (root / normalized).resolve()

    if not str(target).startswith(str(root)):
        raise WingsError("Path traversal is not allowed")

    return target


def running_proc(state: Dict[str, Any]) -> Optional[subprocess.Popen]:
    proc = state.get("proc")
    if proc and proc.poll() is None:
        return proc
    return None


def detect_python_binary() -> str:
    if sys.executable:
        return sys.executable

    for candidate in ["python3", "python"]:
        if shutil.which(candidate):
            return candidate
    return "python3"


def build_command(server: Dict[str, Any]) -> list:
    custom = server.get("startCommand")
    if custom:
        return shlex.split(custom)

    runtime = server.get("runtime", "node")
    entry = server.get("entryFile") or ("index.js" if runtime == "node" else "app.py")

    if runtime == "python":
        return [detect_python_binary(), entry]

    return ["node", entry]


def validate_start_inputs(server: Dict[str, Any], server_dir: Path) -> None:
    custom = server.get("startCommand")
    if custom:
        # Custom command may not map to a single entry file.
        return

    runtime = server.get("runtime", "node")
    entry = server.get("entryFile") or ("index.js" if runtime == "node" else "app.py")
    entry_path = (server_dir / entry).resolve()

    if not str(entry_path).startswith(str(server_dir)):
        raise WingsError("Entry file path is invalid")

    if not entry_path.exists() or not entry_path.is_file():
        raise WingsError(
            f"Entry file not found: {entry}. Upload it first in Files page or set startCommand."
        )


def build_launch_command(server: Dict[str, Any]) -> list:
    base_command = build_command(server)
    binary_cfg = CONFIG.get("processManagerBinary")
    if not binary_cfg:
        return base_command

    binary_path = Path(binary_cfg)
    if not binary_path.is_absolute():
        binary_path = (BASE_DIR / binary_path).resolve()

    if not binary_path.exists():
        return base_command

    wrapped = [str(binary_path), "spawn"]
    ram_limit = float(server.get("ramLimitMb") or 0)
    cpu_limit = float(server.get("cpuLimitPercent") or 0)
    if ram_limit > 0:
        wrapped += ["--ram-mb", str(ram_limit)]
    if cpu_limit > 0:
        wrapped += ["--cpu-pct", str(cpu_limit)]
    wrapped += ["--"] + base_command
    return wrapped


def watch_process(uuid: str, proc: subprocess.Popen) -> None:
    for line in iter(proc.stdout.readline, ""):
        if line == "":
            break
        emit_event(uuid, "log", {"line": line.rstrip("\n")})

    code = proc.wait()

    should_restart = False
    restart_server = None
    with state_lock:
        state = server_states.get(uuid)
        if not state:
            return

        if state.get("proc") is not proc:
            return

        was_manual = state.get("manual_stop", False)
        server_cfg = state.get("server", {})
        started_at = state.get("started_at")
        uptime = (time.time() - started_at) if started_at else None

        state["proc"] = None
        state["pid"] = None
        state["status"] = "stopped" if was_manual else "crashed"
        state["last_exit"] = {
            "code": code,
            "at": now_iso(),
        }
        state["started_at"] = None

        emit_status(uuid, state["status"], state["last_exit"])

        if (not was_manual) and server_cfg.get("autoRestart", True):
            rapid_window = max(1, int(CONFIG.get("rapidCrashWindowSeconds", 20)))
            max_restarts = max(1, int(CONFIG.get("maxCrashRestarts", 5)))

            if uptime is not None and uptime <= rapid_window:
                state["crash_streak"] = int(state.get("crash_streak", 0)) + 1
            else:
                state["crash_streak"] = 1

            if state["crash_streak"] > max_restarts:
                state["status"] = "stopped"
                state["last_exit"]["reason"] = "restart_paused"
                emit_event(
                    uuid,
                    "log",
                    {
                        "line": (
                            f"[wings] auto-restart paused after {state['crash_streak']} "
                            f"rapid crashes. Fix files/config and start manually."
                        )
                    },
                )
                emit_status(uuid, "stopped", state["last_exit"])
            else:
                should_restart = True
                restart_server = dict(server_cfg)
        else:
            state["crash_streak"] = 0

    if should_restart and restart_server:
        delay = max(1, int(CONFIG.get("autoRestartDelaySeconds", 2)))
        emit_event(uuid, "log", {"line": f"[wings] process crashed, restarting in {delay}s"})
        time.sleep(delay)
        try:
            start_server(restart_server)
        except Exception as exc:
            emit_event(uuid, "log", {"line": f"[wings] auto-restart failed: {exc}"})


def create_server(server: Dict[str, Any]) -> Dict[str, Any]:
    uuid = server.get("uuid")
    if not uuid:
        raise WingsError("Server UUID is required")

    path = ensure_server_dir(uuid)

    meta_path = path / "server-meta.json"
    with meta_path.open("w", encoding="utf-8") as f:
        json.dump(server, f, indent=2)

    with state_lock:
        if uuid not in server_states:
            server_states[uuid] = {
                "uuid": uuid,
                "server": dict(server),
                "proc": None,
                "pid": None,
                "status": "stopped",
                "manual_stop": True,
                "last_exit": None,
                "started_at": None,
                "cpu_limit_hits": 0,
                "crash_streak": 0,
            }
        else:
            server_states[uuid]["server"] = dict(server)

    return {"ok": True, "path": str(path)}


def start_server(server: Dict[str, Any]) -> Dict[str, Any]:
    uuid = server.get("uuid")
    if not uuid:
        raise WingsError("Server UUID is required")

    server_dir = ensure_server_dir(uuid)
    try:
        validate_start_inputs(server, server_dir)
    except WingsError as exc:
        last_exit = {
            "code": None,
            "at": now_iso(),
            "reason": "start_validation_failed",
        }
        with state_lock:
            state = server_states.setdefault(
                uuid,
                {
                    "uuid": uuid,
                    "server": dict(server),
                    "proc": None,
                    "pid": None,
                    "status": "stopped",
                    "manual_stop": True,
                    "last_exit": last_exit,
                    "started_at": None,
                    "cpu_limit_hits": 0,
                    "crash_streak": 0,
                },
            )
            state["server"] = dict(server)
            state["status"] = "stopped"
            state["manual_stop"] = True
            state["last_exit"] = last_exit
            state["started_at"] = None
            state["crash_streak"] = 0

        emit_event(uuid, "log", {"line": f"[wings] start blocked: {exc}"})
        emit_status(uuid, "stopped", last_exit)
        raise

    command = build_launch_command(server)

    with state_lock:
        state = server_states.setdefault(
            uuid,
            {
                "uuid": uuid,
                "server": dict(server),
                "proc": None,
                "pid": None,
                "status": "stopped",
                "manual_stop": False,
                "last_exit": None,
                "started_at": None,
                "cpu_limit_hits": 0,
                "crash_streak": 0,
            },
        )

        existing = running_proc(state)
        if existing:
            return {"ok": True, "message": "Already running", "pid": existing.pid}

        state["server"] = dict(server)
        state["manual_stop"] = False

        try:
            proc = subprocess.Popen(
                command,
                cwd=str(server_dir),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            state["status"] = "stopped"
            state["manual_stop"] = True
            state["started_at"] = None
            state["crash_streak"] = 0
            raise WingsError(f"Failed to start process: {exc}") from exc

        state["proc"] = proc
        state["pid"] = proc.pid
        state["status"] = "running"
        state["started_at"] = time.time()
        state["cpu_limit_hits"] = 0
        state["crash_streak"] = 0

    emit_status(uuid, "running")
    emit_event(uuid, "log", {"line": f"[wings] started pid={proc.pid} command={' '.join(command)}"})

    thread = threading.Thread(target=watch_process, args=(uuid, proc), daemon=True)
    thread.start()

    return {"ok": True, "pid": proc.pid, "command": command}


def stop_server(uuid: str, kill: bool = False) -> Dict[str, Any]:
    with state_lock:
        state = server_states.get(uuid)
        if not state:
            raise WingsError("Server not found")

        proc = running_proc(state)
        if not proc:
            state["status"] = "stopped"
            state["manual_stop"] = True
            state["crash_streak"] = 0
            emit_status(uuid, "stopped")
            return {"ok": True, "message": "Already stopped"}

        state["manual_stop"] = True

    try:
        if kill:
            proc.kill()
        else:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
    except Exception as exc:
        raise WingsError(str(exc)) from exc

    return {"ok": True}


def restart_server(server: Dict[str, Any]) -> Dict[str, Any]:
    uuid = server.get("uuid")
    if not uuid:
        raise WingsError("Server UUID is required")

    stop_server(uuid)
    return start_server(server)


def exec_server(uuid: str, command: str) -> Dict[str, Any]:
    with state_lock:
        state = server_states.get(uuid)
        if not state:
            raise WingsError("Server not found")

        proc = running_proc(state)
        if not proc or not proc.stdin:
            raise WingsError("Server is not running")

        proc.stdin.write(command + "\n")
        proc.stdin.flush()

    return {"ok": True}


def list_files(uuid: str, relative_path: str) -> Dict[str, Any]:
    path = resolve_safe_path(uuid, relative_path)
    if not path.exists():
        raise WingsError("Path does not exist")
    if not path.is_dir():
        raise WingsError("Path is not a directory")

    root = ensure_server_dir(uuid)
    entries = []
    for item in sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
        entries.append(
            {
                "name": item.name,
                "path": item.relative_to(root).as_posix() if item != root else ".",
                "isDirectory": item.is_dir(),
                "size": item.stat().st_size if item.is_file() else 0,
                "modifiedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(item.stat().st_mtime)),
            }
        )

    return {"ok": True, "entries": entries}


def mkdir_path(uuid: str, relative_path: str) -> Dict[str, Any]:
    target = resolve_safe_path(uuid, relative_path)
    target.mkdir(parents=True, exist_ok=True)
    return {"ok": True}


def upload_file(uuid: str, relative_path: str, content_base64: str) -> Dict[str, Any]:
    target = resolve_safe_path(uuid, relative_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    try:
        payload = base64.b64decode(content_base64)
    except Exception as exc:
        raise WingsError(f"Invalid base64 payload: {exc}") from exc

    with target.open("wb") as f:
        f.write(payload)

    return {"ok": True, "bytes": len(payload)}


def delete_path(uuid: str, relative_path: str) -> Dict[str, Any]:
    target = resolve_safe_path(uuid, relative_path)
    root = ensure_server_dir(uuid)

    if target == root:
        raise WingsError("Refusing to delete server root")

    if not target.exists():
        return {"ok": True, "message": "Path already missing"}

    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()

    return {"ok": True}


def download_file(uuid: str, relative_path: str) -> Dict[str, Any]:
    target = resolve_safe_path(uuid, relative_path)
    if not target.exists() or not target.is_file():
        raise WingsError("File not found")

    data = target.read_bytes()
    return {
        "ok": True,
        "contentBase64": base64.b64encode(data).decode("ascii"),
        "bytes": len(data),
    }


def collect_server_stats() -> list:
    stats = []
    with state_lock:
        items = list(server_states.items())

    for uuid, state in items:
        proc = running_proc(state)
        status = state.get("status", "stopped")
        pid = state.get("pid")
        cpu_percent = 0.0
        ram_mb = 0.0

        if proc:
            try:
                ps_proc = psutil.Process(proc.pid)
                cpu_percent = float(ps_proc.cpu_percent(interval=None))
                ram_mb = float(ps_proc.memory_info().rss / (1024 * 1024))
                status = "running"
                pid = proc.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                status = "stopped"
                pid = None

            server_cfg = state.get("server", {})
            ram_limit = float(server_cfg.get("ramLimitMb") or 0)
            cpu_limit = float(server_cfg.get("cpuLimitPercent") or 0)
            cpu_limit_hits = int(state.get("cpu_limit_hits", 0))

            if ram_limit > 0 and ram_mb > ram_limit:
                emit_event(uuid, "log", {"line": f"[wings] RAM limit exceeded ({ram_mb:.2f}MB > {ram_limit:.2f}MB). Killing process."})
                try:
                    stop_server(uuid, kill=True)
                except Exception as exc:
                    emit_event(uuid, "log", {"line": f"[wings] failed to stop server after RAM breach: {exc}"})

            if cpu_limit > 0:
                if cpu_percent > cpu_limit:
                    cpu_limit_hits += 1
                else:
                    cpu_limit_hits = 0
            else:
                cpu_limit_hits = 0

            with state_lock:
                if uuid in server_states:
                    server_states[uuid]["cpu_limit_hits"] = cpu_limit_hits

            if cpu_limit > 0 and cpu_limit_hits >= 3:
                emit_event(
                    uuid,
                    "log",
                    {
                        "line": (
                            f"[wings] CPU limit exceeded for 3 heartbeats "
                            f"({cpu_percent:.2f}% > {cpu_limit:.2f}%). Killing process."
                        )
                    },
                )
                try:
                    stop_server(uuid, kill=True)
                except Exception as exc:
                    emit_event(uuid, "log", {"line": f"[wings] failed to stop server after CPU breach: {exc}"})

        with state_lock:
            if uuid in server_states:
                server_states[uuid]["status"] = status
                server_states[uuid]["pid"] = pid
                if not proc:
                    server_states[uuid]["cpu_limit_hits"] = 0

        stats.append(
            {
                "uuid": uuid,
                "status": status,
                "pid": pid,
                "cpuPercent": round(cpu_percent, 2),
                "ramMb": round(ram_mb, 2),
            }
        )

        emit_event(
            uuid,
            "resource",
            {
                "status": status,
                "pid": pid,
                "cpuPercent": round(cpu_percent, 2),
                "ramMb": round(ram_mb, 2),
            },
        )

    return stats


def heartbeat_loop() -> None:
    previous_net = psutil.net_io_counters()
    previous_time = time.time()

    while True:
        interval = max(1, int(CONFIG.get("heartbeatSeconds", 5)))
        time.sleep(interval)

        try:
            vm = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            net = psutil.net_io_counters()
            now = time.time()
            elapsed = max(0.1, now - previous_time)

            rx_mbps = ((net.bytes_recv - previous_net.bytes_recv) / elapsed) / (1024 * 1024)
            tx_mbps = ((net.bytes_sent - previous_net.bytes_sent) / elapsed) / (1024 * 1024)

            previous_net = net
            previous_time = now

            resources = {
                "cpuPercent": round(psutil.cpu_percent(interval=None), 2),
                "ramUsedMb": round(vm.used / (1024 * 1024), 2),
                "ramTotalMb": round(vm.total / (1024 * 1024), 2),
                "ramUsedPercent": round(vm.percent, 2),
                "diskUsedGb": round(disk.used / (1024 * 1024 * 1024), 2),
                "diskTotalGb": round(disk.total / (1024 * 1024 * 1024), 2),
                "diskUsedPercent": round(disk.percent, 2),
                "networkRxMbps": round(rx_mbps, 4),
                "networkTxMbps": round(tx_mbps, 4),
            }

            servers = collect_server_stats()

            post_panel(
                "/api/internal/heartbeat",
                {
                    "nodeId": CONFIG["nodeId"],
                    "name": CONFIG["name"],
                    "ip": socket.gethostbyname(socket.gethostname()),
                    "resources": resources,
                    "servers": servers,
                    "ts": now_iso(),
                },
                timeout=3,
            )
        except Exception as exc:
            print(f"[wings] heartbeat error: {exc}")


@app.errorhandler(WingsError)
def handle_wings_error(error: WingsError):
    return jsonify({"error": str(error)}), 400


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "nodeId": CONFIG["nodeId"],
            "name": CONFIG["name"],
            "ts": now_iso(),
        }
    )


@app.post("/command")
def command():
    verify_secret()
    body = request.get_json(silent=True) or {}

    action = body.get("action")
    server = body.get("server") or {}
    uuid = server.get("uuid") or body.get("uuid")

    if action == "create_server":
        return jsonify(create_server(server))

    if action == "start_server":
        return jsonify(start_server(server))

    if action == "stop_server":
        if not uuid:
            raise WingsError("Server UUID is required")
        return jsonify(stop_server(uuid, kill=False))

    if action == "restart_server":
        return jsonify(restart_server(server))

    if action == "kill_server":
        if not uuid:
            raise WingsError("Server UUID is required")
        return jsonify(stop_server(uuid, kill=True))

    if action == "exec_server":
        if not uuid:
            raise WingsError("Server UUID is required")
        command_text = body.get("command")
        if not command_text:
            raise WingsError("command is required")
        return jsonify(exec_server(uuid, command_text))

    raise WingsError(f"Unsupported action: {action}")


@app.post("/files")
def files():
    verify_secret()
    body = request.get_json(silent=True) or {}

    action = body.get("action")
    server = body.get("server") or {}
    uuid = server.get("uuid")
    if not uuid:
        raise WingsError("Server UUID is required")

    relative_path = body.get("path") or "."

    if action == "list":
        return jsonify(list_files(uuid, relative_path))

    if action == "mkdir":
        return jsonify(mkdir_path(uuid, relative_path))

    if action == "upload":
        content_base64 = body.get("contentBase64")
        if not content_base64:
            raise WingsError("contentBase64 is required")
        return jsonify(upload_file(uuid, relative_path, content_base64))

    if action == "delete":
        return jsonify(delete_path(uuid, relative_path))

    if action == "download":
        return jsonify(download_file(uuid, relative_path))

    raise WingsError(f"Unsupported files action: {action}")


def main() -> None:
    print(f"[wings] Node: {CONFIG['nodeId']} ({CONFIG['name']})")
    print(f"[wings] Panel URL: {CONFIG['panelUrl']}")
    print(f"[wings] Servers dir: {SERVERS_ROOT}")

    t = threading.Thread(target=heartbeat_loop, daemon=True)
    t.start()

    app.run(host=CONFIG["host"], port=int(CONFIG["port"]), debug=False)


if __name__ == "__main__":
    main()

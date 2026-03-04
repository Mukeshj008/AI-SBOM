import argparse
import json
import sqlite3
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path


def set_active_db_link(link_file, db_path):
    link_path = Path(link_file)
    if not link_path.is_absolute():
        link_path = Path.cwd() / link_path
    with open(link_path, "w", encoding="utf-8") as handle:
        handle.write(str(Path(db_path).resolve()))

def read_active_db_link(link_file):
    link_path = Path(link_file)
    if not link_path.is_absolute():
        link_path = Path.cwd() / link_path
    if not link_path.exists():
        return None, link_path
    try:
        target = link_path.read_text(encoding="utf-8").strip()
    except Exception:
        return None, link_path
    if not target:
        return None, link_path
    return Path(target).resolve(), link_path


def is_port_open(host, port, timeout=0.25):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def write_ui_status(status_file, host, port, db_path, pid):
    status_path = Path(status_file)
    if not status_path.is_absolute():
        status_path = Path.cwd() / status_path
    payload = {
        "host": host,
        "port": int(port),
        "url": f"http://{host}:{port}",
        "db_path": str(Path(db_path).resolve()),
        "pid": int(pid),
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    }
    with open(status_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Convenience launcher for AI SBOM UI.")
    parser.add_argument("--port", type=int, default=9007, help="UI port (default: 9007)")
    parser.add_argument("--host", default="127.0.0.1", help="UI host")
    parser.add_argument("--db-path", default="ai_sbom.db", help="Default DB path")
    parser.add_argument("--db-link-file", default="ai_sbom_active_db.txt", help="Active DB link file")
    parser.add_argument("--ui-status-file", default="ai_sbom_ui_status.json", help="UI status metadata file")
    parser.add_argument("--new-db", action="store_true", help="Create new DB in current directory and auto-link UI")
    parser.add_argument("--attach-db", default="", help="Attach existing DB path and auto-link UI")
    args = parser.parse_args()

    linked_db, link_path = read_active_db_link(args.db_link_file)
    selected_db = Path(args.db_path)
    if args.attach_db:
        selected_db = Path(args.attach_db)
        if not selected_db.exists():
            print("Error: attach DB path not found.")
            print(f"Path: {selected_db}")
            print("Create new DB with:")
            print("python3 run-ui.py --new-db --port 9007")
            raise SystemExit(1)
        set_active_db_link(args.db_link_file, selected_db)
    elif args.new_db:
        selected_db = Path(f"ai_sbom_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.db")
        # Create empty sqlite file.
        conn = sqlite3.connect(str(selected_db))
        conn.close()
        set_active_db_link(args.db_link_file, selected_db)
    elif linked_db:
        if not linked_db.exists():
            print("Error: DB path in ai_sbom_active_db.txt not found.")
            print(f"Check path in: {link_path}")
            print("Or create new DB with:")
            print("python3 run-ui.py --new-db --port 9007")
            raise SystemExit(1)
        selected_db = linked_db
    else:
        if not selected_db.exists():
            print("Error: No active DB link found and default DB does not exist.")
            print(f"Expected link file: {link_path}")
            print("Create new DB with:")
            print("python3 run-ui.py --new-db --port 9007")
            raise SystemExit(1)
        set_active_db_link(args.db_link_file, selected_db)

    ui_script = Path(__file__).resolve().with_name("ai-sbom-ui.py")
    cmd = [
        "python3",
        str(ui_script),
        "--db-path",
        str(selected_db),
        "--db-link-file",
        args.db_link_file,
        "--host",
        args.host,
        "--port",
        str(args.port),
    ]
    log_file = Path.cwd() / f"ai_sbom_ui_{args.port}.log"
    with open(log_file, "a", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            cmd,
            stdout=log_handle,
            stderr=log_handle,
            start_new_session=True,
        )

    deadline = time.time() + 5
    while time.time() < deadline:
        if process.poll() is not None:
            break
        if is_port_open(args.host, args.port):
            write_ui_status(args.ui_status_file, args.host, args.port, selected_db, process.pid)
            print("UI started successfully.")
            print(f"URL: http://{args.host}:{args.port}")
            print(f"DB: {selected_db.resolve()}")
            print(f"Log: {log_file}")
            return
        time.sleep(0.15)

    if process.poll() is not None:
        print("Error: UI failed to start.")
        print(f"Check log: {log_file}")
        raise SystemExit(1)

    print("Warning: UI started in background but health check timed out.")
    print(f"Try opening: http://{args.host}:{args.port}")
    print(f"Log: {log_file}")


if __name__ == "__main__":
    main()

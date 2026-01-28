import json
from datetime import datetime, timezone

from src.log_parser import parse_auth_log


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_jsonl(path: str, obj: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")


def main() -> None:
    auth_log_path = "tests/samples/auth.log"  # CI-friendly
    events = parse_auth_log(auth_log_path)

    for e in events:
        alert = {
            "source": "log",
            "alert_type": "ssh_failed_login",
            "severity": "medium",
            "ts_event": e["ts_event"],
            "ts_detected": iso_now(),
            "host": e["host"],
            "indicator": e["ip"],
            "message": f"Failed SSH login user={e['user']} ip={e['ip']}",
            "extra": {"user": e["user"], "port": e["port"]},
        }
        write_jsonl("output/alerts.jsonl", alert)

    print("OK: wrote output/alerts.jsonl")


if __name__ == "__main__":
    main()

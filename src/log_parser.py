import re
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional


FAILED_SSH_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for(?: invalid user)?\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _to_iso8601_utc(mon: str, day: str, hhmmss: str, year: Optional[int] = None) -> str:
    now = datetime.now(timezone.utc)
    y = year or now.year
    dt = datetime(
        year=y,
        month=MONTHS[mon],
        day=int(day),
        hour=int(hhmmss[0:2]),
        minute=int(hhmmss[3:5]),
        second=int(hhmmss[6:8]),
        tzinfo=timezone.utc,
    )
    return dt.isoformat()


def parse_failed_ssh_lines(lines: Iterator[str]) -> List[Dict[str, str]]:
    events: List[Dict[str, str]] = []
    for line in lines:
        m = FAILED_SSH_RE.search(line.strip())
        if not m:
            continue
        ts_event = _to_iso8601_utc(m.group("mon"), m.group("day"), m.group("time"))
        events.append(
            {
                "ts_event": ts_event,
                "host": m.group("host"),
                "user": m.group("user"),
                "ip": m.group("ip"),
                "port": m.group("port"),
                "raw": line.strip(),
            }
        )
    return events


def parse_auth_log(path: str) -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return parse_failed_ssh_lines(f)

import gzip
import re
from collections import Counter
from pathlib import Path
from typing import Dict, Any, Tuple

# Matches standard syslog timestamp and captures the hour
SYSLOG_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+(?P<hour>\d{2}):\d{2}:\d{2}")

# Captures usernames and IPs from standard OpenSSH failure messages
FAIL_RE = re.compile(
    r"(?:Failed password for (?:invalid user )?(?P<u1>\S+)|Invalid user (?P<u2>\S+)).*?from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def get_reader(path: Path):
    """Return the correct file object for plain text or gzipped logs."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return path.open("r", encoding="utf-8", errors="ignore")


def extract_metrics(log_iterable) -> Tuple[Dict[str, int], Dict[str, Counter]]:
    """Scan log lines and aggregate base statistics and metrics."""
    stats = {"lines": 0, "malformed": 0, "failed": 0}
    counters = {"ip": Counter(), "user": Counter(), "hour": Counter()}

    for line in log_iterable:
        stats["lines"] += 1
        syslog_match = SYSLOG_RE.match(line)
        
        if not syslog_match:
            stats["malformed"] += 1
            continue

        fail_match = FAIL_RE.search(line)
        if fail_match:
            stats["failed"] += 1
            counters["hour"][syslog_match.group("hour")] += 1
            counters["ip"][fail_match.group("ip")] += 1
            
            user = fail_match.group("u1") or fail_match.group("u2")
            if user:
                counters["user"][user] += 1

    return stats, counters


def process_log(file_path: Path) -> Dict[str, Any]:
    """Coordinate reading and parsing the log file."""
    with get_reader(file_path) as f:
        stats, counters = extract_metrics(f)

    busiest_hour = counters["hour"].most_common(1)
    busiest = f"{busiest_hour[0][0]}:00" if busiest_hour else "N/A"

    return {
        "scanned": stats["lines"],
        "failed": stats["failed"],
        "malformed": stats["malformed"],
        "distinct_ips": len(counters["ip"]),
        "busiest_hour": busiest,
        "ip_counts": dict(counters["ip"]),
        "user_counts": counters["user"].most_common(5),
    }
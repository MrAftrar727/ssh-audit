import argparse
import sys
from pathlib import Path

from parser import process_log
from report import build_summary, generate_json, generate_text


def positive_int(value: str) -> int:
    """Argparse type to enforce positive integers."""
    try:
        ivalue = int(value)
        if ivalue <= 0:
            raise ValueError
        return ivalue
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} must be a positive integer")


def parse_args() -> argparse.Namespace:
    """Configure and return command-line arguments."""
    p = argparse.ArgumentParser(description="Audit SSH auth logs for suspicious activity.")
    p.add_argument("logfile", nargs="?", default="/var/log/auth.log", help="Path to log file")
    p.add_argument("-n", "--top", type=positive_int, default=10, help="Top N entries to show")
    p.add_argument("--threshold", type=positive_int, default=10, help="Attempts before flag")
    p.add_argument("--json", action="store_true", help="Output results in JSON format")
    p.add_argument("--output", type=Path, help="Write to a file instead of stdout")
    return p.parse_args()


def check_file_access(path: Path) -> None:
    """Validate file existence and permissions, exiting on failure."""
    if not path.exists():
        sys.stderr.write(f"Error: File not found - {path}\n")
        sys.exit(1)
    if path.is_dir():
        sys.stderr.write(f"Error: Path is a directory - {path}\n")
        sys.exit(1)
    try:
        path.open("r").close()
    except PermissionError:
        sys.stderr.write(f"Error: Permission denied - {path}\n")
        sys.exit(1)


def main() -> int:
    """Orchestrate argument parsing, processing, and output generation."""
    args = parse_args()
    log_path = Path(args.logfile)

    check_file_access(log_path)
    raw_data = process_log(log_path)
    summary = build_summary(raw_data, args.top, args.threshold)

    output = generate_json(summary) if args.json else generate_text(summary)

    if args.output:
        try:
            args.output.write_text(output)
        except OSError as e:
            sys.stderr.write(f"Error writing to output file: {e}\n")
            return 1
    else:
        print(output)

    return 1 if summary["suspicious_ips"] else 0


if __name__ == "__main__":
    sys.exit(main())
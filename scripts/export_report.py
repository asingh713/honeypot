#!/usr/bin/env python3
"""Export honeypot event data to JSON or CSV."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from honeypot.core.database import Database
import honeypot.core.config as _cfg


def main() -> None:
    parser = argparse.ArgumentParser(description="Export honeypot events to JSON or CSV.")
    parser.add_argument("--format",  choices=["json", "csv"], default="json")
    parser.add_argument("--service", choices=["ssh", "http", "telnet"], default=None)
    parser.add_argument("--since",   default=None, help="ISO date, e.g. 2026-04-01")
    parser.add_argument("--ip",      default=None, help="Filter by source IP")
    parser.add_argument("--limit",   type=int, default=10000)
    parser.add_argument("--output",  default="-", help="Output file path (default: stdout)")
    parser.add_argument("--top-ips", type=int, default=0, metavar="N",
                        help="Instead of events, print the top N attacker IPs")
    args = parser.parse_args()

    cfg = _cfg.load()
    db  = Database(cfg.database.path)

    if args.top_ips:
        stats = db.get_stats()
        data  = stats["top_ips"][:args.top_ips]
    else:
        data = db.get_events(
            service=args.service,
            src_ip=args.ip,
            since=args.since,
            page=1,
            per_page=args.limit,
        )

    out = open(args.output, "w", newline="") if args.output != "-" else sys.stdout

    try:
        if args.format == "json":
            json.dump(data, out, indent=2, default=str)
            out.write("\n")
        else:
            if not data:
                return
            writer = csv.DictWriter(out, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
    finally:
        if args.output != "-":
            out.close()


if __name__ == "__main__":
    main()

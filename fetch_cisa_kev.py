#!/usr/bin/env python3
"""Fetch CISA KEV data and save it as a JSON file."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def fetch_json(url: str, timeout: int) -> dict:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "cisa-kev-fetcher/1.0",
        },
    )
    with urlopen(request, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        payload = response.read().decode(charset)
        return json.loads(payload)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download CISA KEV feed and save it to a JSON file."
    )
    parser.add_argument(
        "-u",
        "--url",
        default=DEFAULT_KEV_URL,
        help=f"KEV feed URL (default: {DEFAULT_KEV_URL})",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="cisa_kev.json",
        help="Output JSON file path (default: cisa_kev.json)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        help="HTTP timeout in seconds (default: 30)",
    )
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        data = fetch_json(args.url, args.timeout)
    except HTTPError as exc:
        print(f"HTTP error while fetching KEV data: {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except URLError as exc:
        print(f"Network error while fetching KEV data: {exc.reason}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON received from endpoint: {exc}", file=sys.stderr)
        return 1

    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
    print(f"Saved CISA KEV feed to {output_path.resolve()} at {now}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

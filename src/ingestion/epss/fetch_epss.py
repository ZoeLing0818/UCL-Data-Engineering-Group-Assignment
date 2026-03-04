#!/usr/bin/env python3
"""Fetch EPSS data from the official FIRST API and save full snapshots."""

from __future__ import annotations

import argparse
import csv
import json
import ssl
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_DIR = REPO_ROOT / "data" / "raw" / "epss"
DEFAULT_EPSS_URL = "https://api.first.org/data/v1/epss"
DEFAULT_LIMIT = 1000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download EPSS data from the official FIRST API."
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_EPSS_URL,
        help=f"EPSS API base URL (default: {DEFAULT_EPSS_URL})",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Output directory for EPSS snapshots (default: <repo>/data/raw/epss).",
    )
    parser.add_argument(
        "--date",
        default="",
        help="Optional historical date in YYYY-MM-DD format.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help=f"API page size (default: {DEFAULT_LIMIT}).",
    )
    parser.add_argument(
        "--ca-bundle",
        default="",
        help="Path to CA bundle PEM file for TLS verification.",
    )
    parser.add_argument(
        "--insecure-skip-tls-verify",
        action="store_true",
        help="Disable TLS verification (debug only).",
    )
    return parser.parse_args()


def build_ssl_context(args: argparse.Namespace) -> ssl.SSLContext:
    if args.insecure_skip_tls_verify:
        return ssl._create_unverified_context()
    if args.ca_bundle:
        return ssl.create_default_context(cafile=args.ca_bundle)
    try:
        import certifi  # type: ignore

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def fetch_page(
    base_url: str,
    offset: int,
    limit: int,
    date_value: str,
    ssl_context: ssl.SSLContext,
) -> dict[str, Any]:
    query: dict[str, Any] = {"offset": offset, "limit": limit}
    if date_value:
        query["date"] = date_value
    url = f"{base_url}?{urlencode(query)}"
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "first-epss-fetcher/1.0",
        },
    )
    with urlopen(request, timeout=120, context=ssl_context) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_all(
    base_url: str,
    limit: int,
    date_value: str,
    ssl_context: ssl.SSLContext,
) -> dict[str, Any]:
    first = fetch_page(base_url, 0, limit, date_value, ssl_context)
    total = int(first.get("total", 0))
    rows = list(first.get("data", []))
    offset = int(first.get("offset", 0)) + int(first.get("limit", limit))

    while offset < total:
        page = fetch_page(base_url, offset, limit, date_value, ssl_context)
        rows.extend(page.get("data", []))
        offset += int(page.get("limit", limit))

    output = dict(first)
    output["data"] = rows
    output["total"] = len(rows)
    output["offset"] = 0
    output["limit"] = limit
    return output


def write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ssl_context = build_ssl_context(args)
    run_tag = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    try:
        payload = fetch_all(args.base_url, args.limit, args.date, ssl_context)
    except HTTPError as exc:
        print(f"HTTP error while fetching EPSS data: {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except URLError as exc:
        print(f"Network error while fetching EPSS data: {exc.reason}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON received from EPSS endpoint: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error while fetching EPSS data: {exc}", file=sys.stderr)
        return 1

    rows = payload.get("data", [])
    json_latest = output_dir / "epss_scores.json"
    csv_latest = output_dir / "epss_scores.csv"
    json_snapshot = output_dir / f"epss_scores_{run_tag}.json"
    csv_snapshot = output_dir / f"epss_scores_{run_tag}.csv"

    write_json(json_latest, payload)
    write_json(json_snapshot, payload)
    write_csv(csv_latest, rows)
    write_csv(csv_snapshot, rows)

    print(f"Fetched EPSS rows: {len(rows)}")
    print(f"Latest JSON: {json_latest}")
    print(f"Latest CSV: {csv_latest}")
    print(f"Snapshot JSON: {json_snapshot}")
    print(f"Snapshot CSV: {csv_snapshot}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
